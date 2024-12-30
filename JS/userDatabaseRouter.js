const express = require('express');
const userDatabaseRouter = express.Router();
const { getDB } = require('./connectDB.js');
const { authenticateTokenWithId } = require('./authUtils.js'); // Assuming it handles JWT validation
const { testDatabaseConnection } = require('./userDatabase.js');
const { standardLimiter } = require('./rateLimiting.js');

userDatabaseRouter.post('/update', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const db = getDB();
    const { id, dbHost, dbPort, dbUserName, dbPassword, dbDatabase } = req.body; // Use id from body

    if (!id || !dbHost || !dbPort || !dbUserName || !dbPassword || !dbDatabase) {
        return res.status(400).json({ error: 'Id and all database fields are required.' });
    }

    try {
        // Test the connection details
        const testResult = await testDatabaseConnection({
            host: dbHost,
            user: dbUserName,
            password: dbPassword,
            database: dbDatabase,
            port: dbPort,
        });

        if (!testResult.success) {
            return res.status(400).json({ error: `Database connection failed: ${testResult.error}` });
        }

        // Check if the user already has a database record
        const userDbQuery = 'SELECT id FROM users_databases WHERE user_id = ?';
        const existingDb = await new Promise((resolve, reject) => {
            db.query(userDbQuery, [id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (existingDb) {
            // Update existing database details
            const updateQuery = `
                UPDATE users_databases 
                SET db_host = ?, db_port = ?, db_user_name = ?, db_password = ?, db_database = ?
                WHERE user_id = ?
            `;
            await new Promise((resolve, reject) => {
                db.query(updateQuery, [dbHost, dbPort, dbUserName, dbPassword, dbDatabase, id], (err, results) => {
                    if (err) return reject(err);
                    resolve(results);
                });
            });

            return res.json({ message: 'Database details updated successfully.' });
        } else {
            // Insert new database record
            const insertQuery = `
                INSERT INTO users_databases (user_id, db_host, db_port, db_user_name, db_password, db_database)
                VALUES (?, ?, ?, ?, ?, ?)
            `;
            await new Promise((resolve, reject) => {
                db.query(insertQuery, [id, dbHost, dbPort, dbUserName, dbPassword, dbDatabase], (err, results) => {
                    if (err) return reject(err);
                    resolve(results);
                });
            });

            return res.json({ message: 'Database details added successfully.' });
        }
    } catch (error) {
        console.error('Error updating database details:', error);
        res.status(500).json({ error: 'An error occurred while updating the database details.' });
    }
});

module.exports = userDatabaseRouter;