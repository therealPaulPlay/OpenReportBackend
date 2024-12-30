const express = require('express');
const { getDB } = require('./db.js');
const { executeOnUserDatabase } = require('./userDatabase.js');
const reportRouter = express.Router();
const { authenticateTokenWithId } = require('./authUtils.js');
const { standardLimiter } = require('./rateLimiting.js');

// Function to verify ownership or moderation and return app info
async function verifyOwnershipOrModeration(db, userId, appId) {
    const query = `
        SELECT ua.id AS app_id, ua.creator_id
        FROM users_apps AS ua
        LEFT JOIN apps_moderators AS am ON ua.id = am.app_id
        WHERE (ua.creator_id = ? OR am.moderator_id = ?) AND ua.id = ?;
    `;
    return new Promise((resolve, reject) => {
        db.query(query, [userId, userId, appId], (err, results) => {
            if (err) return reject(err);
            resolve(results[0] || null);
        });
    });
}

// Function to retrieve user database connection details
async function getUserDatabaseDetails(db, userId) {
    const query = `
        SELECT db_host, db_user_name, db_password, db_database, db_port
        FROM users_databases
        WHERE user_id = ?;
    `;
    return new Promise((resolve, reject) => {
        db.query(query, [userId], (err, results) => {
            if (err) return reject(err);
            resolve(results[0] || null);
        });
    });
}

// Function to verify app by API key and fetch its details
async function verifyAppByKey(db, key) {
    const query = `
        SELECT ua.id AS app_id, ua.creator_id, ua.warnlist_threshold, ua.blacklist_threshold, 
               u.report_limit, ua.monthly_report_count, ua.name AS app_name
        FROM users_apps AS ua
        INNER JOIN users AS u ON ua.creator_id = u.id
        WHERE ua.api_key = ?;
    `;
    return new Promise((resolve, reject) => {
        db.query(query, [key], (err, results) => {
            if (err) return reject(err);
            resolve(results[0] || null);
        });
    });
}

reportRouter.post('/submit', standardLimiter, async (req, res) => {
    const { key, referenceId, type, reason, notes, link } = req.body;
    const reporterIp = req.clientIp;

    if (!key || !referenceId || !type) {
        return res.status(400).json({ error: 'Key, referenceId, and type are required.' });
    }

    try {
        const db = getDB();

        // Verify app and fetch details
        const app = await verifyAppByKey(db, key);
        if (!app) {
            return res.status(404).json({ error: 'App not found.' });
        }

        if (app.monthly_report_count >= app.report_limit) {
            return res.status(429).json({ error: 'Monthly report limit exceeded for this app.' });
        }

        const { app_name: appName, creator_id: creatorId, warnlist_threshold, blacklist_threshold } = app;

        // Fetch user database connection details
        const dbDetails = await getUserDatabaseDetails(db, creatorId);
        if (!dbDetails) {
            return res.status(500).json({ error: 'User database not configured.' });
        }

        // Prevent duplicate reports by IP for the same type and referenceId
        const duplicateCheckQuery = `
            SELECT COUNT(*) AS count
            FROM \`${appName}_reports\`
            WHERE type = ? AND referenceId = ? AND reporterIp = ?;
        `;
        const duplicateCheck = await executeOnUserDatabase(
            dbDetails,
            duplicateCheckQuery,
            [type, referenceId, reporterIp]
        );

        if (duplicateCheck.count > 0) {
            return res.status(409).json({ error: 'Duplicate report detected.' });
        }

        // Insert the new report
        const insertReportQuery = `
            INSERT INTO \`${appName}_reports\`
            (referenceId, type, reason, notes, link, reporterIp, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, NOW());
        `;
        await executeOnUserDatabase(
            dbDetails,
            insertReportQuery,
            [referenceId, type, reason || null, notes || null, link || null, reporterIp]
        );

        // Update the monthly report count
        const updateReportCountQuery = `
            UPDATE users_apps SET monthly_report_count = monthly_report_count + 1 WHERE id = ?;
        `;
        await new Promise((resolve, reject) => {
            db.query(updateReportCountQuery, [app.id], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        // Check if warnlist or blacklist thresholds are exceeded
        const countQuery = `
            SELECT COUNT(*) AS count
            FROM \`${appName}_reports\`
            WHERE type = ? AND referenceId = ?;
        `;
        const countResult = await executeOnUserDatabase(
            dbDetails,
            countQuery,
            [type, referenceId]
        );

        if (countResult.count >= warnlist_threshold) {
            const warnlistCheckQuery = `
                SELECT COUNT(*) AS count
                FROM \`${appName}_warnlist\`
                WHERE referenceId = ? AND type = ?;
            `;
            const warnlistCheck = await executeOnUserDatabase(dbDetails, warnlistCheckQuery, [referenceId, type]);

            if (warnlistCheck.count === 0) {
                const warnlistInsertQuery = `
                    INSERT INTO \`${appName}_warnlist\` (referenceId, type, reason, link)
                    VALUES (?, ?, ?, ?);
                `;
                await executeOnUserDatabase(
                    dbDetails,
                    warnlistInsertQuery,
                    [referenceId, type, reason || null, link || null]
                );
            } else {
                return res.status(409).json({ error: 'Entry already exists in the warnlist.' });
            }
        }

        if (countResult.count >= blacklist_threshold) {
            const blacklistCheckQuery = `
                SELECT COUNT(*) AS count
                FROM \`${appName}_blacklist\`
                WHERE referenceId = ? AND type = ?;
            `;
            const blacklistCheck = await executeOnUserDatabase(dbDetails, blacklistCheckQuery, [referenceId, type]);

            if (blacklistCheck.count === 0) {
                const blacklistInsertQuery = `
                    INSERT INTO \`${appName}_blacklist\` (referenceId, type, reason, link)
                    VALUES (?, ?, ?, ?);
                `;
                await executeOnUserDatabase(
                    dbDetails,
                    blacklistInsertQuery,
                    [referenceId, type, reason || null, link || null]
                );
            } else {
                return res.status(409).json({ error: 'Entry already exists in the blacklist.' });
            }
        }

        res.status(201).json({ message: 'Report submitted successfully.' });
    } catch (error) {
        console.error('Error submitting report:', error);
        res.status(500).json({ error: 'An error occurred while submitting the report.' });
    }
});