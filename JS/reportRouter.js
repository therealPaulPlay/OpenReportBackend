const express = require('express');
const { getDB } = require('./connectDB.js');
const { executeOnUserDatabase, getUserDatabaseDetails } = require('./userDatabase.js');
const reportRouter = express.Router();
const { authenticateTokenWithId } = require('./authUtils.js');
const { standardLimiter, manualEntryLimiter } = require('./rateLimiting.js');
const validateCaptcha = require('./captchaMiddleware.js');

// Function to verify ownership or moderation and return app info
async function verifyAppOwnership(db, appId, userId) {
    const query = `
        SELECT ua.id AS app_id, ua.creator_id, ua.app_name
        FROM users_apps AS ua
        LEFT JOIN apps_moderators AS am ON am.app_id = ua.id
        WHERE ua.id = ? AND (ua.creator_id = ? OR am.user_id = ?);
    `;
    return new Promise((resolve, reject) => {
        db.query(query, [appId, userId, userId], (err, results) => {
            if (err) return reject(err);
            resolve(results[0] || null);
        });
    });
}

// Function to verify app by API key and fetch its details
async function verifyAppByKey(db, key) {
    const query = `
        SELECT ua.id AS app_id, ua.app_name, ua.creator_id, ua.warnlist_threshold, ua.blacklist_threshold, 
               u.report_limit, ua.monthly_report_count
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

// Submit a report
reportRouter.post('/submit', standardLimiter, validateCaptcha, async (req, res) => {
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

        const { app_id, app_name, creator_id, warnlist_threshold, blacklist_threshold, report_limit, monthly_report_count } = app;

        // Fetch user database connection details
        const dbDetails = await getUserDatabaseDetails(db, creator_id);

        // Prevent duplicate reports by IP for the same type and referenceId
        const duplicateCheckQuery = `
            SELECT COUNT(*) AS count
            FROM \`${app_name}_reports\`
            WHERE type = ? AND referenceId = ? AND reporterIp = ?;
        `;
        const duplicateCheck = await executeOnUserDatabase(
            dbDetails,
            duplicateCheckQuery,
            [type, referenceId, reporterIp]
        );

        if (duplicateCheck.count > 0) {
            return res.status(409).json({ error: 'Please only submit the same content once.' });
        }

        // Insert the new report
        const insertReportQuery = `
            INSERT INTO \`${app_name}_reports\`
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

        // Check if warnlist or blacklist thresholds are exceeded --------------------
        const countQuery = `
            SELECT COUNT(*) AS count
            FROM \`${app_name}_reports\`
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
                FROM \`${app_name}_warnlist\`
                WHERE referenceId = ? AND type = ?;
            `;
            const warnlistCheck = await executeOnUserDatabase(dbDetails, warnlistCheckQuery, [referenceId, type]);

            if (warnlistCheck.count === 0) {
                const warnlistInsertQuery = `
                    INSERT INTO \`${app_name}_warnlist\` (referenceId, type, reason, link, timestamp)
                    VALUES (?, ?, ?, ?, NOW());
                `;
                await executeOnUserDatabase(
                    dbDetails,
                    warnlistInsertQuery,
                    [referenceId, type, reason || null, link || null]
                );
            }
        }

        if (countResult.count >= blacklist_threshold) {
            const blacklistCheckQuery = `
                SELECT COUNT(*) AS count
                FROM \`${app_name}_blacklist\`
                WHERE referenceId = ? AND type = ?;
            `;
            const blacklistCheck = await executeOnUserDatabase(dbDetails, blacklistCheckQuery, [referenceId, type]);

            if (blacklistCheck.count === 0) {
                const blacklistInsertQuery = `
                    INSERT INTO \`${app_name}_blacklist\` (referenceId, type, reason, link, timestamp)
                    VALUES (?, ?, ?, ?, NOW());
                `;
                await executeOnUserDatabase(
                    dbDetails,
                    blacklistInsertQuery,
                    [referenceId, type, reason || null, link || null]
                );
            }
        }

        res.status(201).json({ message: 'Report submitted successfully.' });
    } catch (error) {
        console.error('Error submitting report:', error);
        res.status(500).json({ error: 'An error occurred while submitting the report: ' + error.message });
    }
});

// Endpoint 3.2: Delete an Entry
reportRouter.delete('/delete', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const { id, appId, table, entryId } = req.body; // `id` is the user ID

    if (!["blacklist", "warnlist", "reports"].includes(table) || entryId == null || appId == null) return res.status(400).json({ error: "Table, appId and entryId are required." });

    try {
        const db = getDB();

        // Verify app ownership and fetch app details
        const app = await verifyAppOwnership(db, appId, id);
        if (!app) return res.status(403).json({ error: 'Unauthorized access.' });

        const { app_id, creator_id, app_name } = app;

        // Get the app's database
        const dbDetails = await getUserDatabaseDetails(db, creator_id);

        // Delete the entry
        const deleteQuery = `DELETE FROM \`${app_name}_${table}\` WHERE id = ?;`;
        await executeOnUserDatabase(dbDetails, deleteQuery, [entryId]);

        res.status(200).json({ message: 'Entry deleted successfully.' });
    } catch (error) {
        console.error('Error deleting entry:', error);
        res.status(500).json({ error: 'An error occurred while deleting the entry: ' + error.message });
    }
});

// Endpoint 3.3: Add to Blacklist or Warnlist
reportRouter.post('/add-manually', manualEntryLimiter, authenticateTokenWithId, async (req, res) => {
    const { id, appId, table, referenceId, type, reason, link } = req.body;
    if (!["blacklist", "warnlist"].includes(table) || referenceId == null || appId == null) return res.status(400).json({ error: "Table, appId and referenceId are required." });

    try {
        const db = getDB();

        // Verify app ownership and fetch app details
        const app = await verifyAppOwnership(db, appId, id);
        if (!app) return res.status(403).json({ error: 'Unauthorized access.' });

        const { app_id, creator_id, app_name } = app;

        // Get the app's database
        const dbDetails = await getUserDatabaseDetails(db, creator_id);

        // Prevent duplicates
        const duplicateCheckQuery = `
            SELECT COUNT(*) AS count FROM \`${app_name}_${table}\` WHERE referenceId = ? AND type = ?;
        `;
        const duplicateCheck = await executeOnUserDatabase(dbDetails, duplicateCheckQuery, [referenceId, type]);

        if (duplicateCheck.count > 0) {
            return res.status(409).json({ error: `Entry already exists in the ${table}.` });
        }

        // Insert into blacklist
        const insertQuery = `
            INSERT INTO \`${app_name}_${table}\` (referenceId, type, reason, link)
            VALUES (?, ?, ?, ?);
        `;
        await executeOnUserDatabase(dbDetails, insertQuery, [referenceId, type, reason || null, link || null]);

        res.status(201).json({ message: `Entry added to ${table} successfully.` });
    } catch (error) {
        console.error('Error adding to blacklist:', error);
        res.status(500).json({ error: 'An error occurred while adding to the table: ' + error.message });
    }
});

// Endpoint 3.4: Clean a Table
reportRouter.delete('/clean', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const { id, appId, days, table } = req.body;

    if (!days || days < 1 || !['reports', 'warnlist', 'blacklist'].includes(table) || !appId) {
        return res.status(400).json({ error: 'Valid days (minimum 1), table ("reports", "warnlist", "blacklist"), and appId are required.' });
    }

    try {
        const db = getDB();

        // Verify app ownership and fetch app details
        const app = await verifyAppOwnership(db, appId, id);
        if (!app) return res.status(403).json({ error: 'Unauthorized access.' });

        const { app_id, creator_id, app_name } = app;

        // Get the app's database
        const dbDetails = await getUserDatabaseDetails(db, creator_id);

        // Clean the table
        const cleanQuery = `
        DELETE FROM \`${app_name}_${table}\` 
        WHERE timestamp < NOW() - INTERVAL ? DAY;
    `;
        await executeOnUserDatabase(dbDetails, cleanQuery, [days]);

        res.status(200).json({ message: 'Table cleaned successfully.' });
    } catch (error) {
        console.error('Error cleaning table:', error);
        res.status(500).json({ error: 'An error occurred while cleaning the table: ' + error.message });
    }
});

// Get entries
reportRouter.put('/get-table', authenticateTokenWithId, standardLimiter, async (req, res) => {
    const { id, appId, table, page = 1 } = req.body;

    if (!['reports', 'warnlist', 'blacklist'].includes(table) || !appId) {
        return res.status(400).json({ error: 'Valid table and appId are required.' });
    }

    try {
        const db = getDB();

        // Verify ownership or moderation
        const app = await verifyAppOwnership(db, appId, id);
        if (!app) {
            return res.status(403).json({ error: 'Unauthorized to perform this action on the app.' });
        }

        const dbDetails = await getUserDatabaseDetails(db, app.creator_id);

        const limit = 50;
        const offset = (Number(page) - 1) * limit;

        // Fetch paginated results
        const getQuery = `
            SELECT * FROM \`${app.app_name}_${table}\` 
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?;
        `;
        console.log(getQuery);
        console.log([limit, offset]);
        const results = await executeOnUserDatabase(dbDetails, getQuery, [limit, offset]);

        res.status(200).json({ data: results });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'An error occurred while fetching the data: '  + error.message });
    }
});

module.exports = reportRouter;