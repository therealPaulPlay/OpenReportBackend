const express = require('express');
const { getDB } = require('./connectDB.js');
const { executeOnUserDatabase, getUserDatabaseDetails } = require('./userDatabase.js');
const reportRouter = express.Router();
const { authenticateTokenWithId } = require('./authUtils.js');
const { standardLimiter, manualEntryLimiter, highLimiter } = require('./rateLimiting.js');
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
    const referrer = req.get('Referer'); // Yes, this HTTP header was misspelled

    if (!key || !referenceId || !type) return res.status(400).json({ error: 'Key, referenceId, and type are required.' });

    if (notes && notes.length > 1000) return res.status(400).json({ error: "Please keep your notes short and concise." });

    try {
        const db = getDB();

        // Verify app and fetch details
        const app = await verifyAppByKey(db, key);
        if (!app) return res.status(404).json({ error: 'App not found.' });
        if (app.monthly_report_count >= app.report_limit) return res.status(429).json({ error: 'Monthly report limit exceeded for this app.' });

        // Check domain restrictions
        if (referrer) {
            try {
                const domain = new URL(referrer).hostname;
                if (domain == process.env.SITE_DOMAIN.replace("https://", "").replace(/\/$/, "")) return;
                const domainCheckQuery = `
                    SELECT COUNT(*) as count 
                    FROM users_apps_domains 
                    WHERE app_id = ? AND domain = ?
                `;

                const [domainResult] = await new Promise((resolve, reject) => {
                    db.query(domainCheckQuery, [app.app_id, domain], (err, results) => {
                        if (err) return reject(err);
                        resolve(results);
                    });
                });

                if (domainResult.count === 0) {
                    return res.status(403).json({ error: 'Domain not authorized for this app.' });
                }
            } catch (urlError) {
                return res.status(400).json({ error: 'Invalid referrer URL: ' + urlError });
            }
        }

        // Fetch user database connection details
        const dbDetails = await getUserDatabaseDetails(db, app.creator_id);

        // Prevent duplicate reports by IP for the same type and referenceId
        const duplicateCheckQuery = `
            SELECT COUNT(*) AS count
            FROM \`${app.app_name}_reports\`
            WHERE type = ? AND reference_id = ? AND reporter_ip = ?
            LIMIT 1;
        `;

        const duplicateResult = await executeOnUserDatabase(
            dbDetails,
            duplicateCheckQuery,
            [type.trim(), referenceId.trim(), reporterIp.trim()]
        );

        if (duplicateResult[0].count > 0) {
            return res.status(409).json({ error: 'Please only report the same content once.' });
        }

        // Insert the new report
        const insertReportQuery = `
            INSERT INTO \`${app.app_name}_reports\`
            (reference_id, type, reason, notes, link, reporter_ip, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, NOW());
        `;
        await executeOnUserDatabase(
            dbDetails,
            insertReportQuery,
            [referenceId.trim(), type.trim(), reason || null, notes?.trim() || null, link || null, reporterIp.trim()]
        );

        // Update the monthly report count
        const updateReportCountQuery = `
            UPDATE users_apps SET monthly_report_count = monthly_report_count + 1 WHERE id = ?;
        `;
        await new Promise((resolve, reject) => {
            db.query(updateReportCountQuery, [app.app_id], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        // Check if warnlist or blacklist thresholds are exceeded
        const countQuery = `
            SELECT COUNT(*) AS count
            FROM \`${app.app_name}_reports\`
            WHERE type = ? AND reference_id = ?;
        `;
        const countResult = await executeOnUserDatabase(
            dbDetails,
            countQuery,
            [type.trim(), referenceId.trim()]
        );

        if (countResult[0].count >= app.warnlist_threshold) {
            const warnlistCheckQuery = `
                SELECT COUNT(*) AS count
                FROM \`${app.app_name}_warnlist\`
                WHERE reference_id = ? AND type = ?;
            `;
            const warnlistCheck = await executeOnUserDatabase(
                dbDetails,
                warnlistCheckQuery,
                [referenceId.trim(), type.trim()]
            );

            if (warnlistCheck[0].count === 0) {
                const warnlistInsertQuery = `
                    INSERT INTO \`${app.app_name}_warnlist\` (reference_id, type, reason, link, timestamp)
                    VALUES (?, ?, ?, ?, NOW());
                `;
                await executeOnUserDatabase(
                    dbDetails,
                    warnlistInsertQuery,
                    [referenceId.trim(), type.trim(), reason || null, link || null]
                );
            }
        }

        if (countResult[0].count >= app.blacklist_threshold) {
            const blacklistCheckQuery = `
                SELECT COUNT(*) AS count
                FROM \`${app.app_name}_blacklist\`
                WHERE reference_id = ? AND type = ?;
            `;
            const blacklistCheck = await executeOnUserDatabase(
                dbDetails,
                blacklistCheckQuery,
                [referenceId.trim(), type.trim()]
            );

            if (blacklistCheck[0].count === 0) {
                const blacklistInsertQuery = `
                    INSERT INTO \`${app.app_name}_blacklist\` (reference_id, type, reason, link, timestamp)
                    VALUES (?, ?, ?, ?, NOW());
                `;
                await executeOnUserDatabase(
                    dbDetails,
                    blacklistInsertQuery,
                    [referenceId.trim(), type.trim(), reason || null, link || null]
                );
            }
        }

        res.status(201).json({ message: 'Report submitted successfully.' });
    } catch (error) {
        console.error('Error submitting report:', error);
        res.status(500).json({ error: 'An error occurred while submitting the report: ' + error.message });
    }
});

// Delete an Entry
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

// Add to Blacklist or Warnlist
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
            SELECT COUNT(*) AS count FROM \`${app_name}_${table}\` WHERE reference_id = ? AND type = ?;
        `;
        const duplicateCheck = await executeOnUserDatabase(dbDetails, duplicateCheckQuery, [referenceId, type]);

        if (duplicateCheck[0].count > 0) {
            return res.status(409).json({ error: `Entry already exists in the ${table}.` });
        }

        const getUserEmailQuery = `SELECT email FROM users WHERE id = ?;`;
        const userEmail = await new Promise((resolve, reject) => {
            db.query(getUserEmailQuery, [id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0].email);
            });
        });

        if (!userEmail) return res.status(404).json({ error: "User's email address not found." });

        // Insert into blacklist
        const insertQuery = `
            INSERT INTO \`${app_name}_${table}\` (reference_id, type, reason, link, created_by)
            VALUES (?, ?, ?, ?, ?);
        `;
        await executeOnUserDatabase(dbDetails, insertQuery, [referenceId, type, reason || null, link || null, userEmail]);

        res.status(201).json({ message: `Entry added to ${table} successfully.` });
    } catch (error) {
        console.error('Error adding to blacklist:', error);
        res.status(500).json({ error: 'An error occurred while adding to the table: ' + error.message });
    }
});

// Edit Expiry for an Existing Entry
reportRouter.put('/edit-expiry', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const { id, entryId, appId, table, newExpiry } = req.body;

    if (!["blacklist", "warnlist"].includes(table) || !entryId || !appId) {
        return res.status(400).json({ error: "Table, appId and entryId are required." });
    }

    if (newExpiry !== null && (typeof newExpiry !== 'string' || isNaN(Date.parse(newExpiry)))) {
        return res.status(400).json({ error: "Invalid expiry date. Must be a valid ISO-8601 date or null to remove expiry." });
    }

    try {
        const db = getDB();

        // Verify app ownership and fetch app details
        const app = await verifyAppOwnership(db, appId, id);
        if (!app) return res.status(403).json({ error: 'Unauthorized access.' });

        const { app_name, creator_id } = app;

        // Get the app's database
        const dbDetails = await getUserDatabaseDetails(db, creator_id);

        // Check if the entry exists
        const entryCheckQuery = `
            SELECT COUNT(*) AS count FROM \`${app_name}_${table}\` WHERE id = ?;
        `;
        const entryCheck = await executeOnUserDatabase(dbDetails, entryCheckQuery, [entryId]);

        if (entryCheck[0].count === 0) {
            return res.status(404).json({ error: `Entry not found in the ${table}.` });
        }

        // Update the expires_at value
        const updateQuery = `
            UPDATE \`${app_name}_${table}\`
            SET expires_at = ?
            WHERE id = ?;
        `;
        await executeOnUserDatabase(dbDetails, updateQuery, [newExpiry || null, entryId]);

        res.status(200).json({ message: "Expiry date for entry updated successfully." });
    } catch (error) {
        console.error('Error editing expiry:', error);
        res.status(500).json({ error: 'An error occurred while editing expiry: ' + error.message });
    }
});

// Clean a Table
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

// Get entries with optional search
reportRouter.put('/get-table', authenticateTokenWithId, standardLimiter, async (req, res) => {
    const { id, appId, table, page = 1, search = '' } = req.body;

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

        // Build the query for searching
        let searchQuery = '';
        if (search) {
            const sanitizedSearch = search.replace(/'/g, "\\'"); // Escape single quotes for safety
            const extraReportTables = table == "reports" ? ", notes, reporter_ip" : ""; // Include more columns if its the reports table

            // Use MATCH AGAINST for full-text search
            searchQuery = `
                AND MATCH(reference_id, type, reason, link${extraReportTables})
                AGAINST ('${sanitizedSearch}' IN BOOLEAN MODE)
            `;
        }

        // Fetch paginated results with optional search
        const getQuery = `
            SELECT * FROM \`${app.app_name}_${table}\`
            WHERE 1 ${searchQuery}
            ORDER BY timestamp DESC, id DESC
            LIMIT ${offset}, ${limit};
        `;

        const results = await executeOnUserDatabase(dbDetails, getQuery);

        res.status(200).json({ data: results });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'An error occurred while fetching the data: ' + error.message });
    }
});

// PUBLIC API
// Get entry from warnlist or blacklist by reference ID
reportRouter.put('/get-entry', highLimiter, async (req, res) => {
    const { appId, table, type, secret, referenceId } = req.body;

    if (!['warnlist', 'blacklist'].includes(table) || !appId || !secret || !referenceId || !type) {
        return res.status(400).json({ error: 'Valid table, secret, referenceId, type and appId are required.' });
    }

    try {
        const db = getDB();

        const getAppQuery = `
        SELECT * FROM users_apps
        WHERE id = ? AND secret_key = ?;
        `;

        const app = await new Promise((resolve, reject) => {
            db.query(getAppQuery, [appId, secret], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        })

        if (!app) {
            return res.status(403).json({ error: 'App not found or unauthorized.' });
        }

        const dbDetails = await getUserDatabaseDetails(db, app.creator_id);

        // Fetch paginated results with optional search
        const getQuery = `
            SELECT * FROM \`${app.app_name}_${table}\`
            WHERE reference_id = ? AND type = ?
            LIMIT 1;
        `;

        const results = await executeOnUserDatabase(dbDetails, getQuery, [referenceId, type]);

        res.status(200).json({ entry: results[0] || null });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'An error occurred while fetching the data: ' + error.message });
    }
});

module.exports = reportRouter;