const mysql = require('mysql2/promise');

// Test database connection
async function testDatabaseConnection(details) {
    const { host, user, password, database, port } = details;

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
async function executeOnUserDatabase(details, query, params = []) {
    const { host, user, password, database, port } = details;

    try {
        const connection = await mysql.createConnection({ host, user, password, database, port });
        const [results] = await connection.execute(query, params);
        await connection.end();
        return results;
    } catch (error) {
        console.error('Error executing query on user database:', error);
        throw new Error(`Failed to execute query: ${error.message}`);
    }
}

module.exports = {
    testDatabaseConnection,
    executeOnUserDatabase,
};