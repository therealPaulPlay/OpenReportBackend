import express from 'express';
import { getDB } from './connectDB.js';
import { authenticateTokenWithId } from './authUtils.js';
import { standardLimiter } from './rateLimiting.js';

const moderatorRouter = express.Router();

// Get moderators of a specific app
moderatorRouter.put('/moderators', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id: userId, appId } = req.body; // Include the appName in the request body

    if (!appId) {
        return res.status(400).json({ error: 'App Id is required.' });
    }

    try {
        // Verify the app belongs to the authenticated user
        const appQuery = 'SELECT id FROM users_apps WHERE id = ? AND creator_id = ?';
        const app = await new Promise((resolve, reject) => {
            db.query(appQuery, [appId, userId], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!app) {
            return res.status(404).json({ error: 'App not found or you are not the owner.' });
        }

        // Get the emails of moderators for the specified app
        const moderatorsQuery = `
            SELECT u.email 
            FROM apps_moderators am
            JOIN users u ON am.user_id = u.id
            WHERE am.app_id = ?
        `;
        const moderators = await new Promise((resolve, reject) => {
            db.query(moderatorsQuery, [appId], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        res.json({ moderators: moderators.map(moderator => moderator.email) });
    } catch (error) {
        console.error('Error retrieving moderators:', error);
        res.status(500).json({ error: 'An error occurred while retrieving moderators.' });
    }
});


// Add a moderator to an app
moderatorRouter.post('/add', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id: userId, appId, email } = req.body; // Include these 2 properties in the request body

    if (!appId || !email) {
        return res.status(400).json({ error: 'App Id and email are required.' });
    }

    try {
        // Get the app ID and creator's moderator limit
        const appQuery = `
            SELECT 
                ua.id AS app_id, 
                ua.moderator_count,
                u.moderator_limit
            FROM users_apps ua
            JOIN users u ON ua.creator_id = u.id
            WHERE ua.id = ? AND ua.creator_id = ?
        `;
        const app = await new Promise((resolve, reject) => {
            db.query(appQuery, [appId, userId], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!app) {
            return res.status(404).json({ error: 'App not found or you are not the owner.' });
        }

        if (app.moderator_count >= app.moderator_limit) {
            return res.status(400).json({ error: 'Moderator limit reached for this app.' });
        }

        // Get the user ID of the email provided
        const userQuery = 'SELECT id FROM users WHERE email = ?';
        const user = await new Promise((resolve, reject) => {
            db.query(userQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!user) {
            return res.status(404).json({ error: 'User with the provided email not found.' });
        }

        // Check if the user is already a moderator for the app
        const checkModeratorQuery = 'SELECT id FROM apps_moderators WHERE app_id = ? AND user_id = ?';
        const existingModerator = await new Promise((resolve, reject) => {
            db.query(checkModeratorQuery, [appId, user.id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (existingModerator) {
            return res.status(400).json({ error: 'User is already a moderator for this app.' });
        }

        // Add the user as a moderator
        const insertModeratorQuery = 'INSERT INTO apps_moderators (app_id, user_id) VALUES (?, ?)';
        await new Promise((resolve, reject) => {
            db.query(insertModeratorQuery, [appId, user.id], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        // Increment the moderator count for the app
        const updateModeratorCountQuery = 'UPDATE users_apps SET moderator_count = moderator_count + 1 WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(updateModeratorCountQuery, [appId], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        res.json({ message: 'Moderator added successfully.' });
    } catch (error) {
        console.error('Error adding moderator:', error);
        res.status(500).json({ error: 'An error occurred while adding the moderator.' });
    }
});

// Remove a moderator from an app
moderatorRouter.delete('/remove', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id: userId, appId, email } = req.body; // Include these 2 properties in the request body

    if (!appId || !email) {
        return res.status(400).json({ error: 'App Id and email are required.' });
    }

    try {
        // Get the app ID
        const appQuery = 'SELECT app_name FROM users_apps WHERE id = ? AND creator_id = ?';
        const app = await new Promise((resolve, reject) => {
            db.query(appQuery, [appId, userId], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });
        if (!app) return res.status(404).json({ error: 'App not found or you are not the owner.' });

        // Get the user ID of the email provided
        const userQuery = 'SELECT id FROM users WHERE email = ?';
        const user = await new Promise((resolve, reject) => {
            db.query(userQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });
        if (!user) return res.status(404).json({ error: 'User with the provided email not found.' });

        // Remove the user as a moderator
        const deleteModeratorQuery = 'DELETE FROM apps_moderators WHERE app_id = ? AND user_id = ?';
        const result = await new Promise((resolve, reject) => {
            db.query(deleteModeratorQuery, [appId, user.id], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });
        if (result.affectedRows === 0) return res.status(400).json({ error: 'User is not a moderator for this app.' });

        // Decrement the moderator count for the app
        const updateModeratorCountQuery = 'UPDATE users_apps SET moderator_count = moderator_count - 1 WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(updateModeratorCountQuery, [appId], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        res.json({ message: 'Moderator removed successfully.' });
    } catch (error) {
        console.error('Error removing moderator:', error);
        res.status(500).json({ error: 'An error occurred while removing the moderator.' });
    }
});

export default moderatorRouter;