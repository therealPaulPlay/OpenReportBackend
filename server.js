import express from 'express';
import requestIp from 'request-ip';
import cors from 'cors';
import 'dotenv/config'; // Load environment variables

// Router Imports
import accountRouter from "./JS/accountRouter.js";
import userDatabaseRouter from "./JS/userDatabaseRouter.js";
import appRouter from "./JS/appRouter.js";
import moderatorRouter from "./JS/moderatorRouter.js";
import reportRouter from "./JS/reportRouter.js";
import subscriptionRouter from "./JS/subscriptionRouter.js";

// Function imports
import { connectDB } from "./JS/connectDB.js";

const app = express();

// CORS configuration ------------------------------------------------------------
app.use(cors({
    origin: (origin, callback) => {
        const corsOrigins = process.env.CORS_ORIGIN.split(',').map(o =>
            /^\/.*\/$/.test(o) ? new RegExp(o.slice(1, -1)) : o
        );

        if (!origin || corsOrigins.some(pattern => typeof pattern === 'string' ? pattern === origin : pattern.test(origin))) {
            callback(null, true); // Allow requests without an origin (e.g., webhooks), otherwise check if it is matching
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
}));

// Middleware
app.use((req, res, next) => {
    if (req.originalUrl === '/subscription/webhook') {
        next(); // Skip json body parsing for Stripe Webhook
    } else {
        express.json()(req, res, next); // Parse request bodies as json
    }
});
app.use(requestIp.mw());

// Database Connection
connectDB();

// Routers
app.use("/account", accountRouter)
app.use("/user-database", userDatabaseRouter);
app.use("/app", appRouter);
app.use("/moderator", moderatorRouter);
app.use("/report", reportRouter);
app.use("/subscription", subscriptionRouter);

// Health check
app.get('/health', (req, res) => {
    res.status(200).json({ message: 'Server is healthy. I hope you are too!' });
});

// Start the server ----------------------------------------------------------------------------------------------------------------------------------
app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});