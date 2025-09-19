import mysql from 'mysql2';

const RETRY_INTERVAL = 5000;
let pool;

function createDBPool() {
    return mysql.createPool({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        waitForConnections: true,
        connectionLimit: 10,    // Adjust based on your expected concurrency - the MySQL db can handle up to ~75, though other servers need conns too
        queueLimit: 0           // No limit on queued connection requests
    });
}

export function getDB() {
    // Return the pool instance instead of a single connection
    if (!pool) console.error("Database pool is not initialized. Did you forget to call connectDB?");
    return pool;
}

export function connectDB() {
    pool = createDBPool();

    // Test the connection when starting the pool
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error connecting to MySQL pool:', err);
            console.log(`Connection failed. Retrying in ${RETRY_INTERVAL / 1000} seconds...`);
            setTimeout(connectDB, RETRY_INTERVAL); // Retry pool creation
            return;
        }

        console.log('Connected to MySQL pool');
        connection.release(); // Release the test connection back to the pool
    });

    pool.on('error', (err) => {
        console.error('Database pool error:', err);
        console.log('Attempting to recreate the pool...');
        setTimeout(connectDB, RETRY_INTERVAL); // Attempt to recreate the pool on error
    });
}