const express = require('express');
const appRouter = express.Router();
const { getDB } = require('./connectDB.js');
const { authenticateTokenWithId } = require('./authUtils.js');
const { executeOnUserDatabase } = require('./userDatabase.js');
const { standardLimiter, appCreationLimiter } = require('./rateLimiting.js');
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

    if (domains.length > 100) {
        return res.status(400).json({ error: 'A maximum of 100 domains is allowed.' });
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

        // Create required tables in user's database !TODO add index on type and referenceId in all 3 tables
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
                UNIQUE KEY unique_type_reference (type, referenceId)
            )`,
            `CREATE TABLE IF NOT EXISTS ${appName}_blacklist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                referenceId VARCHAR(255) NOT NULL,
                type VARCHAR(255) NOT NULL,
                reason VARCHAR(255),
                link VARCHAR(255),
                UNIQUE KEY unique_type_reference (type, referenceId)
            )`,
        ];

        for (const query of tableQueries) {
            await executeOnUserDatabase(dbDetails, query);
        }

        res.status(201).json({
            message: 'App created successfully.',
            apiKey,
        });
    } catch (error) {
        console.error('Error creating app:', error);
        res.status(500).json({ error: 'An error occurred while creating the app: ' + error });
    }
});

// Endpoint to update thresholds
appRouter.patch('/update-thresholds', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appName, warnlistThreshold, blacklistThreshold } = req.body;

    if (!id || !appName || warnlistThreshold == null || blacklistThreshold == null) {
        return res.status(400).json({ error: 'Id, app name, and thresholds are required.' });
    }

    try {
        const updateQuery = `
            UPDATE users_apps 
            SET warnlist_threshold = ?, blacklist_threshold = ?
            WHERE creator_id = ? AND app_name = ?
        `;
        const result = await new Promise((resolve, reject) => {
            db.query(updateQuery, [warnlistThreshold, blacklistThreshold, id, appName], (err, results) => {
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

// Endpoint to delete an app
appRouter.delete('/delete', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appName } = req.body;

    if (!id || !appName) {
        return res.status(400).json({ error: 'Id and app name are required.' });
    }

    try {
        // Fetch app ID
        const appQuery = 'SELECT id FROM users_apps WHERE creator_id = ? AND app_name = ?';
        const app = await new Promise((resolve, reject) => {
            db.query(appQuery, [id, appName], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!app) {
            return res.status(404).json({ error: 'App not found.' });
        }

        const appId = app.id;

        // Fetch user's database connection details
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

module.exports = appRouter;