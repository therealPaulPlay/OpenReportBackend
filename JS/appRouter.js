const express = require('express');
const appRouter = express.Router();
const { getDB } = require('./connectDB.js');
const { authenticateTokenWithId } = require('./authUtils.js');
const { executeOnUserDatabase, getUserDatabaseDetails } = require('./userDatabase.js');
const { standardLimiter, appCreationLimiter } = require('./rateLimiting.js');
const cron = require('node-cron');
const crypto = require('crypto');

// Endpoint to get apps by user id
appRouter.get('/apps/:id', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const userId = req.params.id;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        const query = `
            SELECT 
                ua.id AS app_id,
                ua.app_name,
                ua.warnlist_threshold,
                ua.blacklist_threshold,
                ua.monthly_report_count,
                ua.api_key,
                CASE 
                    WHEN ua.creator_id = ? THEN true
                    ELSE false
                END AS owner
            FROM users_apps ua
            LEFT JOIN apps_moderators am ON ua.id = am.app_id
            WHERE ua.creator_id = ? OR am.user_id = ?
            GROUP BY ua.id
        `;

        const apps = await new Promise((resolve, reject) => {
            db.query(query, [userId, userId, userId], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        res.json(apps);
    } catch (error) {
        console.error('Error retrieving apps:', error);
        res.status(500).json({ error: 'An error occurred while retrieving the apps.' });
    }
});

// Endpoint to create a new app
appRouter.post('/create', appCreationLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appName, domains } = req.body;

    if (!id || !appName || !domains || !Array.isArray(domains) || domains.length === 0) {
        return res.status(400).json({ error: 'Id, app name, and domains are required.' });
    }

    const validAppNameRegex = /^[a-z0-9_-]+$/;

    if (appName.includes(" ")) {
        return res.status(400).json({ error: 'The app name cannot include whitespaces.' });
    }

    if (!validAppNameRegex.test(appName)) {
        return res.status(400).json({ error: 'The app name can only contain lowercase letters, numbers, underscores, and hyphens.' });
    }

    if (domains.length > 30) {
        return res.status(400).json({ error: 'A maximum of 30 domains is allowed.' });
    }

    try {
        // Check if app name already exists for the user
        const checkAppQuery = 'SELECT id FROM users_apps WHERE creator_id = ? AND app_name = ?';
        const existingApp = await new Promise((resolve, reject) => {
            db.query(checkAppQuery, [id, appName], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (existingApp) {
            return res.status(409).json({ error: 'App with the same name already exists.' });
        }

        const apiKey = crypto.randomBytes(16).toString('hex'); // Generate 32-character key

        // Insert new app into users_apps table
        const insertAppQuery = `
            INSERT INTO users_apps (creator_id, app_name, api_key)
            VALUES (?, ?, ?)
        `;
        const appId = await new Promise((resolve, reject) => {
            db.query(insertAppQuery, [id, appName, apiKey], (err, results) => {
                if (err) return reject(err);
                resolve(results.insertId);
            });
        });

        // Insert domains into users_apps_domains table
        const insertDomainQuery = 'INSERT INTO users_apps_domains (app_id, domain) VALUES (?, ?)';
        for (const domain of domains) {
            await new Promise((resolve, reject) => {
                db.query(insertDomainQuery, [appId, domain], (err) => {
                    if (err) return reject(err);
                    resolve();
                });
            });
        }

        // Get user's database connection details
        const dbDetailsQuery = `
            SELECT db_host, db_user_name, db_password, db_database, db_port
            FROM users_databases WHERE user_id = ?
        `;
        const dbDetails = await new Promise((resolve, reject) => {
            db.query(dbDetailsQuery, [id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!dbDetails) {
            return res.status(404).json({ error: 'Database connection details not found for user.' });
        }

        // Create required tables in user's database !TODO add index on type, timestamp (DESC) and referenceId in all 3 tables
        const tableQueries = [
            `CREATE TABLE IF NOT EXISTS ${appName}_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                referenceId VARCHAR(255) NOT NULL,
                type VARCHAR(255) NOT NULL,
                reason VARCHAR(255),
                notes TEXT,
                link VARCHAR(255),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                reporterIp VARCHAR(45) NOT NULL
            )`,
            `CREATE TABLE IF NOT EXISTS ${appName}_warnlist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                referenceId VARCHAR(255) NOT NULL,
                type VARCHAR(255) NOT NULL,
                reason VARCHAR(255),
                link VARCHAR(255),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE KEY unique_type_reference (type, referenceId)
            )`,
            `CREATE TABLE IF NOT EXISTS ${appName}_blacklist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                referenceId VARCHAR(255) NOT NULL,
                type VARCHAR(255) NOT NULL,
                reason VARCHAR(255),
                link VARCHAR(255),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE KEY unique_type_reference (type, referenceId)
            )`,
        ];

        for (const query of tableQueries) {
            await executeOnUserDatabase(dbDetails, query);
        }

        // Now, add indexes after tables are created. Fulltext indexes improve search speed.
        const indexQueries = [
            `CREATE INDEX idx_reports_type ON ${appName}_reports(type);`,
            `CREATE INDEX idx_reports_timestamp ON ${appName}_reports(timestamp DESC);`,
            `CREATE INDEX idx_reports_referenceId ON ${appName}_reports(referenceId);`,
            `CREATE FULLTEXT INDEX idx_reports_fulltext ON ${appName}_reports(referenceId, type, reason, notes, link, reporterIp);`,

            `CREATE INDEX idx_warnlist_type ON ${appName}_warnlist(type);`,
            `CREATE INDEX idx_warnlist_timestamp ON ${appName}_warnlist(timestamp DESC);`,
            `CREATE INDEX idx_warnlist_referenceId ON ${appName}_warnlist(referenceId);`,
            `CREATE FULLTEXT INDEX idx_warnlist_fulltext ON ${appName}_warnlist(referenceId, type, reason, notes, link, reporterIp);`,

            `CREATE INDEX idx_blacklist_type ON ${appName}_blacklist(type);`,
            `CREATE INDEX idx_blacklist_timestamp ON ${appName}_blacklist(timestamp DESC);`,
            `CREATE INDEX idx_blacklist_referenceId ON ${appName}_blacklist(referenceId);`,
            `CREATE FULLTEXT INDEX idx_blacklist_fulltext ON ${appName}_blacklist(referenceId, type, reason, notes, link, reporterIp);`
        ];

        for (const query of indexQueries) {
            await executeOnUserDatabase(dbDetails, query);
        }

        res.status(201).json({
            message: 'App created successfully.',
            apiKey,
        });
    } catch (error) {
        console.error('Error creating app:', error);
        res.status(500).json({ error: 'An error occurred while creating the app: ' + error.message });
    }
});

// Endpoint to update thresholds
appRouter.patch('/update-thresholds', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appId, warnlistThreshold, blacklistThreshold } = req.body;

    if (!id || !appId || warnlistThreshold == null || blacklistThreshold == null) {
        return res.status(400).json({ error: 'Id, appId, and thresholds are required.' });
    }

    try {
        const updateQuery = `
            UPDATE users_apps 
            SET warnlist_threshold = ?, blacklist_threshold = ?
            WHERE creator_id = ? AND id = ?
        `;
        const result = await new Promise((resolve, reject) => {
            db.query(updateQuery, [warnlistThreshold, blacklistThreshold, id, appId], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'App not found.' });
        }

        res.json({ message: 'Thresholds updated successfully.' });
    } catch (error) {
        console.error('Error updating thresholds:', error);
        res.status(500).json({ error: 'An error occurred while updating thresholds.' });
    }
});

// Endpoint to update app domains
appRouter.put('/update-domains', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appId, domains } = req.body;

    if (!id || !appId || !domains || !Array.isArray(domains) || domains.length === 0) {
        return res.status(400).json({ error: 'User id, app id, and domains are required.' });
    }

    if (domains.length > 30) {
        return res.status(400).json({ error: 'A maximum of 30 domains is allowed.' });
    }

    try {
        // Verify that the app exists and belongs to the user
        const checkAppQuery = 'SELECT id FROM users_apps WHERE id = ? AND creator_id = ?';
        const existingApp = await new Promise((resolve, reject) => {
            db.query(checkAppQuery, [appId, id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!existingApp) {
            return res.status(404).json({ error: 'App not found or does not belong to user.' });
        }

        // Delete all existing domains for this app
        const deleteDomainQuery = 'DELETE FROM users_apps_domains WHERE app_id = ?';
        await new Promise((resolve, reject) => {
            db.query(deleteDomainQuery, [appId], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        // Insert new domains
        const insertDomainQuery = 'INSERT INTO users_apps_domains (app_id, domain) VALUES (?, ?)';
        for (const domain of domains) {
            await new Promise((resolve, reject) => {
                db.query(insertDomainQuery, [appId, domain], (err) => {
                    if (err) return reject(err);
                    resolve();
                });
            });
        }

        res.status(200).json({
            message: 'Domains updated successfully.',
            updatedDomains: domains
        });
    } catch (error) {
        console.error('Error updating app domains:', error);
        res.status(500).json({ error: 'An error occurred while updating the domains: ' + error.message });
    }
});

// Endpoint to delete an app
appRouter.delete('/delete', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appId } = req.body;

    if (!id || !appId) {
        return res.status(400).json({ error: 'Id and app name are required.' });
    }

    try {
        // Fetch app ID
        const appQuery = 'SELECT app_name FROM users_apps WHERE creator_id = ? AND id = ?';
        const app = await new Promise((resolve, reject) => {
            db.query(appQuery, [id, appId], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!app) {
            return res.status(404).json({ error: 'App not found.' });
        }

        const appName = app.app_name;

        // Fetch user's database connection details
        const dbDetails = await getUserDatabaseDetails(db, id);

        // Delete related tables in user's database
        const tablesToDelete = [`${appName}_reports`, `${appName}_warnlist`, `${appName}_blacklist`];
        for (const table of tablesToDelete) {
            try {
                await executeOnUserDatabase(
                    dbDetails,
                    `DROP TABLE IF EXISTS \`${table}\``
                );
            } catch (error) {
                console.warn(`Could not delete table ${table}:`, error.message);
            }
        }

        // Delete the app from users_apps table
        const deleteAppQuery = 'DELETE FROM users_apps WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(deleteAppQuery, [appId], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        res.json({ message: 'App and related tables deleted successfully.' });
    } catch (error) {
        console.error('Error deleting app:', error);
        res.status(500).json({ error: 'An error occurred while deleting the app.' });
    }
});

// Reset the monthly_report_count to 0 at the start of each month
cron.schedule('0 0 1 * *', async () => {
    console.log('Running monthly report count reset...');
    const db = getDB();

    try {
        const resetQuery = 'UPDATE users_apps SET monthly_report_count = 0';

        await new Promise((resolve, reject) => {
            db.query(resetQuery, (err, result) => {
                if (err) return reject(err);
                resolve(result);
            });
        });

        console.log('Successfully reset monthly report counts');
    } catch (error) {
        console.error('Error resetting monthly report counts:', error);
    }
});

module.exports = appRouter;