const mysql = require('mysql2/promise');

// Test database connection
async function testDatabaseConnection(details) {
    const { db_host: host, db_user_name: user, db_password: password, db_database: database, db_port: port } = details;

    try {
        const connection = await mysql.createConnection({ host, user, password, database, port });
        await connection.ping();
        await connection.end();
        return { success: true };
    } catch (error) {
        console.error('Database connection failed:', error);
        return { success: false, error: error.message };
    }
}

// Execute query on user database and ensure the connection is closed
async function executeOnUserDatabase(details, query, params = [], usePreparedStatements = true) {
    const { db_host: host, db_user_name: user, db_password: password, db_database: database, db_port: port } = details;

    try {
        const connection = await mysql.createConnection({ host, user, password, database, port });

        let results;

        if (usePreparedStatements) {
            [results] = await connection.execute(query, params); // Execute includes params on the MySQL server, checking for security and preventing SQL injection
        } else {
            [results] = await connection.query(query, params); // However, execute doesn't work for all SQL syntax yet
        }

        await connection.end();
        return results;
    } catch (error) {
        console.error('Error executing query on user database:', error);
        throw new Error(`Failed to execute query on the user's own database: ${error.message}`);
    }
}

// Function to fetch user database details
async function getUserDatabaseDetails(db, userId) {
    try {
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
    } catch (error) {
        console.error('Error obtaining database credentials:', error);
        throw new Error(`Failed to obtain database credentials: ${error.message}`);
    }
}

module.exports = {
    testDatabaseConnection,
    executeOnUserDatabase,
    getUserDatabaseDetails,
};