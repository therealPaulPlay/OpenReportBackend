const express = require('express');
const bodyParser = require('body-parser');
const requestIp = require('request-ip');
const cors = require('cors');
const xss = require('xss-clean');
require('dotenv').config(); // Load environment variables

// Router Imports
const accountRouter = require("./JS/accountRouter.js");

// Function imports
const { connectDB } = require("./JS/connectDB.js");

const app = express();

// CORS configuration ------------------------------------------------------------
app.use(cors({
    origin: process.env.CORS_ORIGIN
}));

// Middleware
app.use(bodyParser.json());
app.use(requestIp.mw());
app.use(xss());

// Database Connection
connectDB();


// Routers
app.use("/account", accountRouter)

// Start the server ----------------------------------------------------------------------------------------------------------------------------------
app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});