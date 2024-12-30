const express = require('express');
const appRouter = express.Router();
const { getDB } = require('./connectDB.js');
const { authenticateTokenWithId } = require('./authUtils.js');
const { executeOnUserDatabase } = require('./userDatabase.js');
const { standardLimiter } = require('./rateLimiting.js');

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
appRouter.post('/create', standardLimiter, authenticateTokenWithId, async (req, res) => {
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

        // Insert new app
        const insertAppQuery = `
            INSERT INTO users_apps (creator_id, app_name)
            VALUES (?, ?)
        `;
        const appId = await new Promise((resolve, reject) => {
            db.query(insertAppQuery, [id, appName], (err, results) => {
                if (err) return reject(err);
                resolve(results.insertId);
            });
        });

        // Insert domains
        const insertDomainQuery = 'INSERT INTO users_apps_domains (app_id, domain) VALUES (?, ?)';
        for (const domain of domains) {
            await new Promise((resolve, reject) => {
                db.query(insertDomainQuery, [appId, domain], (err) => {
                    if (err) return reject(err);
                    resolve();
                });
            });
        }

        res.status(201).json({ message: 'App created successfully.' });
    } catch (error) {
        console.error('Error creating app:', error);
        res.status(500).json({ error: 'An error occurred while creating the app.' });
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

        // Delete the app
        const deleteAppQuery = 'DELETE FROM users_apps WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(deleteAppQuery, [appId], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        // Delete related tables in user's database
        const tablesToDelete = [`${appName}_reports`, `${appName}_warnlist`, `${appName}_blacklist`];
        for (const table of tablesToDelete) {
            try {
                await executeOnUserDatabase(
                    { user_id: id },
                    `DROP TABLE IF EXISTS \`${table}\``
                );
            } catch (error) {
                console.warn(`Could not delete table ${table}:`, error.message);
            }
        }

        res.json({ message: 'App deleted successfully.' });
    } catch (error) {
        console.error('Error deleting app:', error);
        res.status(500).json({ error: 'An error occurred while deleting the app.' });
    }
});

module.exports = appRouter;