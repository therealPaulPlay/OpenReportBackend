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

// Endpoint to get app secret key by id
appRouter.put('/secret-key', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const { id, appId } = req.body;
    if (!id || !appId) return res.status(400).json({ error: "Id and appId are required." });

    const db = getDB();

    try {
        const query = `
            SELECT secret_key FROM users_apps
            WHERE id = ? AND creator_id = ?;`;

        const result = await new Promise((resolve, reject) => {
            db.query(query, [appId, id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!result) {
            return res.status(404).json({ error: 'Only app owners can reveal the secret key.' });
        }

        res.json({ secret: result?.secret_key });
    } catch (error) {
        console.error('Error retrieving app secret key:', error);
        res.status(500).json({ error: 'An error occurred while retrieving the app secret key.' });
    }
});

// Endpoint to rotate app secret key
appRouter.put('/rotate-secret', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const { id, appId } = req.body;
    if (!id || !appId) return res.status(400).json({ error: "Id and appId are required." });

    const db = getDB();

    try {
        const verifyQuery = `
            SELECT id FROM users_apps 
            WHERE id = ? AND creator_id = ?;
        `;

        const verifyResult = await new Promise((resolve, reject) => {
            db.query(verifyQuery, [appId, id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!verifyResult) {
            return res.status(404).json({ error: 'Only app owners can rotate the secret key.' });
        }

        // Generate new secret key
        const newSecretKey = crypto.randomBytes(16).toString('hex');
        const updateQuery = `
            UPDATE users_apps 
            SET secret_key = ? 
            WHERE id = ? AND creator_id = ?;
        `;

        await new Promise((resolve, reject) => {
            db.query(updateQuery, [newSecretKey, appId, id], (err, result) => {
                if (err) return reject(err);
                resolve(result);
            });
        });

        res.json({
            message: 'Secret key rotated successfully.',
            secret: newSecretKey
        });

    } catch (error) {
        console.error('Error rotating app secret key:', error);
        res.status(500).json({ error: 'An error occurred while rotating the app secret key.' });
    }
});

// Endpoint to create a new app
appRouter.post('/create', appCreationLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appName, domains } = req.body;

    if (!id || !appName || !domains || !Array.isArray(domains) || domains.length === 0) {
        return res.status(400).json({ error: 'Id, app name, and domains are required.' });
    }

    const validAppNameRegex = /^[a-z0-9_]+$/;

    if (appName.includes(" ")) {
        return res.status(400).json({ error: 'The app name cannot include whitespaces.' });
    }

    if (!validAppNameRegex.test(appName)) {
        return res.status(400).json({ error: 'The app name can only contain lowercase letters, numbers and underscores.' });
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

        const apiKey = crypto.randomBytes(16).toString('hex'); // Generate 32-character api key (for reports etc.)
        const secretKey = crypto.randomBytes(16).toString('hex'); // Generate 32-character api key (for api requests etc.)

        // Insert new app into users_apps table
        const insertAppQuery = `
            INSERT INTO users_apps (creator_id, app_name, api_key, secret_key)
            VALUES (?, ?, ?, ?)
        `;
        const appId = await new Promise((resolve, reject) => {
            db.query(insertAppQuery, [id, appName, apiKey, secretKey], (err, results) => {
                if (err) return reject(err);
                resolve(results.insertId);
            });
        });

        // Insert domains into users_apps_domains table
        const insertDomainQuery = 'INSERT INTO users_apps_domains (app_id, domain) VALUES (?, ?)';
        for (let domain of domains) {
            domain = domain.replace("http://", "").replace("https://", "");
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

        // Create required tables in user's database
        const tableQueries = [
            `CREATE TABLE IF NOT EXISTS ${appName}_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                reference_id VARCHAR(255) NOT NULL,
                type VARCHAR(255) NOT NULL,
                reason VARCHAR(255),
                notes TEXT,
                link VARCHAR(255),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                reporter_ip VARCHAR(45) NOT NULL
            )`,
            `CREATE TABLE IF NOT EXISTS ${appName}_warnlist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                reference_id VARCHAR(255) NOT NULL,
                type VARCHAR(255) NOT NULL,
                reason VARCHAR(255),
                link VARCHAR(255),
                created_by VARCHAR(255) NOT NULL DEFAULT 'system',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                expires_at DATETIME DEFAULT NULL,
                UNIQUE KEY unique_type_reference (type, reference_id)
            )`,
            `CREATE TABLE IF NOT EXISTS ${appName}_blacklist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                reference_id VARCHAR(255) NOT NULL,
                type VARCHAR(255) NOT NULL,
                reason VARCHAR(255),
                link VARCHAR(255),
                created_by VARCHAR(255) NOT NULL DEFAULT 'system',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                expires_at DATETIME DEFAULT NULL,
                UNIQUE KEY unique_type_reference (type, reference_id)
            )`,
        ];

        for (const query of tableQueries) {
            await executeOnUserDatabase(dbDetails, query);
        }

        // Now, add indexes after tables are created. Fulltext indexes improve search speed.
        const indexQueries = [
            `CREATE INDEX idx_reports_type ON ${appName}_reports(type);`,
            `CREATE INDEX idx_reports_timestamp ON ${appName}_reports(timestamp DESC);`,
            `CREATE INDEX idx_reports_reference_id ON ${appName}_reports(reference_id);`,
            `CREATE FULLTEXT INDEX idx_reports_fulltext ON ${appName}_reports(reference_id, type, reason, notes, link, reporter_ip);`,

            `CREATE INDEX idx_warnlist_type ON ${appName}_warnlist(type);`,
            `CREATE INDEX idx_warnlist_timestamp ON ${appName}_warnlist(timestamp DESC);`,
            `CREATE INDEX idx_warnlist_reference_id ON ${appName}_warnlist(reference_id);`,
            `CREATE INDEX idx_warnlist_expires_at ON ${appName}_warnlist(expires_at);`,
            `CREATE FULLTEXT INDEX idx_warnlist_fulltext ON ${appName}_warnlist(reference_id, type, reason, link);`,

            `CREATE INDEX idx_blacklist_type ON ${appName}_blacklist(type);`,
            `CREATE INDEX idx_blacklist_timestamp ON ${appName}_blacklist(timestamp DESC);`,
            `CREATE INDEX idx_blacklist_reference_id ON ${appName}_blacklist(reference_id);`,
            `CREATE INDEX idx_blacklist_expires_at ON ${appName}_blacklist(expires_at);`,
            `CREATE FULLTEXT INDEX idx_blacklist_fulltext ON ${appName}_blacklist(reference_id, type, reason, link);`
        ];

        for (const query of indexQueries) {
            await executeOnUserDatabase(dbDetails, query);
        }

        // Create a scheduler to delete expired entries from warnlist and blacklist
        const schedulerQueries = [
            `CREATE EVENT IF NOT EXISTS ${appName}_warnlist_cleanup
            ON SCHEDULE EVERY 1 DAY
            DO
                DELETE FROM ${appName}_warnlist WHERE expires_at IS NOT NULL AND expires_at < NOW();`,

            `CREATE EVENT IF NOT EXISTS ${appName}_blacklist_cleanup
            ON SCHEDULE EVERY 1 DAY
            DO
                DELETE FROM ${appName}_blacklist WHERE expires_at IS NOT NULL AND expires_at < NOW();`
        ];

        for (const query of schedulerQueries) {
            await executeOnUserDatabase(dbDetails, query, undefined, false);
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

// Update default warn + blacklist entry expiry
appRouter.put('/update-expiry', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appId, days } = req.body;

    if (!id || !appId) {
        return res.status(400).json({ error: 'Id and appId are required.' });
    }

    if (days !== null && (typeof days !== 'number' || days < 1 || days > 365)) {
        return res.status(400).json({ error: 'Days must be a number between 1 and 365, or null to reset.' });
    }

    try {
        // Fetch app name
        const appQuery = 'SELECT app_name FROM users_apps WHERE creator_id = ? AND id = ?';
        const app = await new Promise((resolve, reject) => {
            db.query(appQuery, [id, appId], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!app) {
            return res.status(404).json({ error: 'App not found or missing permission.' });
        }

        // Fetch user's database connection details
        const dbDetails = await getUserDatabaseDetails(db, id);

        let modifyQueries;

        if (days !== null) {
            modifyQueries = [
                `ALTER TABLE \`${app.app_name}_warnlist\` ALTER expires_at SET DEFAULT (DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ${days} DAY))`,
                `ALTER TABLE \`${app.app_name}_blacklist\` ALTER expires_at SET DEFAULT (DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ${days} DAY))`
            ];
        } else {
            modifyQueries = [
                `ALTER TABLE \`${app.app_name}_warnlist\` MODIFY expires_at DATETIME NULL`,
                `ALTER TABLE \`${app.app_name}_blacklist\` MODIFY expires_at DATETIME NULL`
            ];
        }

        for (const query of modifyQueries) {
            await executeOnUserDatabase(dbDetails, query);
        }

        res.json({
            message: `Default expiry successfully updated to ${days !== null ? `${days} days` : 'never'} for warnlist and blacklist.`
        });
    } catch (error) {
        console.error('Error updating expiry:', error);
        res.status(500).json({ error: 'An error occurred while updating the expiry: ' + error.message });
    }
});

// Endpoint to enable reports auto-cleanup for app
appRouter.post('/enable-auto-cleanup', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appId, days } = req.body;

    if (!id || !appId || !days || !Number.isInteger(days) || days < 1) {
        return res.status(400).json({ error: 'Valid user id, app id, and days (positive integer) are required.' });
    }

    try {
        // Fetch app details
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

        // Get user's database connection details
        const dbDetails = await getUserDatabaseDetails(db, id);

        // Create event for auto-cleanup
        const eventName = `${appName}_reports_cleanup`;
        const createEventQuery = `
            CREATE EVENT IF NOT EXISTS \`${eventName}\`
            ON SCHEDULE EVERY 1 DAY
            DO
                DELETE FROM \`${appName}_reports\`
                WHERE timestamp < DATE_SUB(NOW(), INTERVAL ? DAY)
        `;

        await executeOnUserDatabase(dbDetails, createEventQuery, [days], false);

        res.json({ message: 'Auto-cleanup enabled successfully.' });

    } catch (error) {
        console.error('Error enabling auto-cleanup:', error);
        res.status(500).json({ error: 'An error occurred while enabling auto-cleanup.' });
    }
});

// Endpoint to disable reports auto-cleanup for app
appRouter.delete('/disable-auto-cleanup', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appId } = req.body;

    if (!id || !appId) return res.status(400).json({ error: 'User id and app id are required.' });

    try {
        // Fetch app details
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

        // Get user's database connection details
        const dbDetails = await getUserDatabaseDetails(db, id);

        // Drop the event
        const dropEventQuery = `DROP EVENT IF EXISTS \`${appName}_reports_cleanup\``;
        await executeOnUserDatabase(dbDetails, dropEventQuery);

        res.json({ message: 'Auto-cleanup disabled successfully.' });

    } catch (error) {
        console.error('Error disabling auto-cleanup:', error);
        res.status(500).json({ error: 'An error occurred while disabling auto-cleanup.' });
    }
});

// Endpoint to get auto-cleanup configuration
appRouter.get('/get-auto-cleanup', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, appId } = req.query;
    if (!id || !appId) return res.status(400).json({ error: 'User id and app id are required.' });

    try {
        // Fetch app details
        const appQuery = 'SELECT app_name FROM users_apps WHERE creator_id = ? AND id = ?';
        const app = await new Promise((resolve, reject) => {
            db.query(appQuery, [id, appId], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!app) return res.status(404).json({ error: 'App not found.' });

        const appName = app.app_name;

        // Get user's database connection details
        const dbDetails = await getUserDatabaseDetails(db, id);

        // Get event details
        const getEventQuery = `
            SELECT EVENT_DEFINITION
            FROM information_schema.EVENTS 
            WHERE EVENT_SCHEMA = ? 
            AND EVENT_NAME = ?
        `;
        const eventDetails = await executeOnUserDatabase(
            dbDetails,
            getEventQuery,
            [dbDetails.db_database, `${appName}_reports_cleanup`]
        );

        if (!eventDetails || eventDetails.length === 0) {
            return res.json({ days: null });
        }

        // Extract days value from EVENT_DEFINITION
        const eventDefinition = eventDetails[0].EVENT_DEFINITION;
        const daysMatch = eventDefinition.match(/INTERVAL (\d+) DAY/);
        const days = daysMatch ? parseInt(daysMatch[1]) : null;

        res.json({ days });

    } catch (error) {
        console.error('Error getting auto-cleanup configuration:', error);
        res.status(500).json({ error: 'An error occurred while getting auto-cleanup configuration.' });
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

        // Remove MySQL events related to the app
        const eventsToDelete = [`${appName}_warnlist_cleanup`, `${appName}_blacklist_cleanup`];
        for (const event of eventsToDelete) {
            try {
                await executeOnUserDatabase(
                    dbDetails,
                    `DROP EVENT IF EXISTS \`${event}\``
                );
            } catch (error) {
                console.warn(`Could not delete event ${event}:`, error.message);
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

        res.json({ message: 'App, related tables and events deleted successfully.' });
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