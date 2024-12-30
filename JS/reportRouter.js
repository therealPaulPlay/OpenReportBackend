const express = require('express');
const { getDB } = require('./db.js');
const { executeOnUserDatabase } = require('./userDatabase.js');
const reportRouter = express.Router();
const { authenticateTokenWithId } = require('./authUtils.js');
const { standardLimiter } = require('./rateLimiting.js');

reportRouter.post('/submit', standardLimiter, async (req, res) => {
    const { key, referenceId, type, reason, notes, link } = req.body;
    const reporterIp = req.clientIp;

    if (!key || !referenceId || !type) {
        return res.status(400).json({ error: 'Key, referenceId, and type are required.' });
    }

    try {
        const db = getDB();

        // Fetch app details
        const appQuery = `
            SELECT ua.id AS app_id, ua.creator_id, ua.warnlist_threshold, ua.blacklist_threshold, 
                   u.report_limit, ua.monthly_report_count
            FROM users_apps AS ua
            INNER JOIN users AS u ON ua.creator_id = u.id
            WHERE ua.api_key = ?;
        `;
        const app = await new Promise((resolve, reject) => {
            db.query(appQuery, [key], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!app) {
            return res.status(404).json({ error: 'App not found.' });
        }

        if (app.monthly_report_count >= app.report_limit) {
            return res.status(429).json({ error: 'Monthly report limit exceeded for this app.' });
        }

        const { app_id, creator_id, warnlist_threshold, blacklist_threshold } = app;

        // Fetch user database connection details
        const dbDetailsQuery = `
            SELECT db_host, db_user_name, db_password, db_database, db_port
            FROM users_databases
            WHERE user_id = ?;
        `;
        const dbDetails = await new Promise((resolve, reject) => {
            db.query(dbDetailsQuery, [creator_id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!dbDetails) {
            return res.status(500).json({ error: 'User database not configured.' });
        }

        // Prevent duplicate reports by IP for the same type and referenceId
        const duplicateCheckQuery = `
            SELECT COUNT(*) AS count
            FROM \`${app_id}_reports\`
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
            INSERT INTO \`${app_id}_reports\`
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
            db.query(updateReportCountQuery, [app_id], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        // Check if warnlist or blacklist thresholds are exceeded
        const countQuery = `
            SELECT COUNT(*) AS count
            FROM \`${app_id}_reports\`
            WHERE type = ? AND referenceId = ?;
        `;
        const countResult = await executeOnUserDatabase(
            dbDetails,
            countQuery,
            [type, referenceId]
        );

        if (countResult.count >= warnlist_threshold) {
            const warnlistInsertQuery = `
                INSERT IGNORE INTO \`${app_id}_warnlist\` (referenceId, type, reason, link)
                VALUES (?, ?, ?, ?);
            `;
            await executeOnUserDatabase(
                dbDetails,
                warnlistInsertQuery,
                [referenceId, type, reason || null, link || null]
            );
        }

        if (countResult.count >= blacklist_threshold) {
            const blacklistInsertQuery = `
                INSERT IGNORE INTO \`${app_id}_blacklist\` (referenceId, type, reason, link)
                VALUES (?, ?, ?, ?);
            `;
            await executeOnUserDatabase(
                dbDetails,
                blacklistInsertQuery,
                [referenceId, type, reason || null, link || null]
            );
        }

        res.status(201).json({ message: 'Report submitted successfully.' });
    } catch (error) {
        console.error('Error submitting report:', error);
        res.status(500).json({ error: 'An error occurred while submitting the report.' });
    }
});