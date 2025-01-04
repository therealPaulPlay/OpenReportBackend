const express = require('express');
const subscriptionRouter = express.Router();

const stripeLib = require('stripe');
const { standardLimiter } = require("./rateLimiting.js");
const { authenticateTokenWithId } = require("./authUtils.js");
const { getDB } = require("./connectDB.js");
const { sendMail } = require('./sendEmails.js');

// Default limits
const DEFAULT_REPORT_LIMIT = 2500;
const DEFAULT_MODERATOR_LIMIT = 10;

let stripe;

try {
    stripe = stripeLib(process.env.STRIPE_SECRET_KEY);
} catch (error) {
    console.error("Stripe initialization failed:", error);
}

// Helper function to update user limits
async function updateUserLimits(userId, reportLimit, moderatorLimit, subscriptionTier) {
    const db = getDB();
    const updateQuery = 'UPDATE users SET report_limit = ?, moderator_limit = ?, subscription_tier = ? WHERE id = ?';
    return new Promise((resolve, reject) => {
        db.query(updateQuery, [reportLimit, moderatorLimit, subscriptionTier, userId], (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
}

// Helper function to get user by stripe customer ID
async function getUserByStripeCustomerId(stripeCustomerId) {
    const db = getDB();
    const query = 'SELECT * FROM users WHERE stripe_customer_id = ?';
    return new Promise((resolve, reject) => {
        db.query(query, [stripeCustomerId], (err, results) => {
            if (err) return reject(err);
            resolve(results[0]);
        });
    });
}

// Helper function to send confirmation email
async function sendSubscriptionEmail(email, purchaseId, amountTotal, productName) {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Thank you for subscribing to OpenReport!',
        text: `Hi,

thank you for subscribing to OpenReport!

Product: ${productName}
Purchase ID: ${purchaseId}
Amount: $${(amountTotal / 100).toFixed(2)}

If you have any questions regarding the purchase, please do not hesitate to reach out through the contact form on https://paulplay.studio.

Make sure to also provide the Purchase ID. (This email was sent automatically, please do not reply directly).`
    };

    await sendMail(mailOptions);
}

subscriptionRouter.post('/create-checkout-session', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const id = req.body.id;

    try {
        // Get user data to associate with Stripe customer
        const db = getDB();
        const user = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        const prices = await stripe.prices.list({
            lookup_keys: [req.body.lookup_key],
            expand: ['data.product'],
        });

        // Create or retrieve Stripe customer
        let customer;
        if (user.stripe_customer_id) {
            customer = await stripe.customers.retrieve(user.stripe_customer_id);
        } else {
            customer = await stripe.customers.create({
                email: user.email,
                metadata: { user_id: id },
            });

            await new Promise((resolve, reject) => {
                db.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?',
                    [customer.id, id],
                    (err, results) => {
                        if (err) return reject(err);
                        resolve(results);
                    });
            });
        }

        // Check existing subscriptions and currency
        const subscriptions = await stripe.subscriptions.list({
            customer: customer.id,
            status: 'active',
        });

        if (subscriptions.data.length > 0) {
            return res.status(409).json({ error: "Please cancel your existing subscription first." });
        }

        // Create a new checkout session with automatic tax
        const session = await stripe.checkout.sessions.create({
            customer: customer.id,
            billing_address_collection: 'auto', // Allow auto-collection of billing address
            automatic_tax: {
                enabled: true, // Enable automatic tax
            },
            payment_method_types: ['card', 'paypal'], // Include PayPal as a payment method
            line_items: [
                {
                    price: prices.data[0].id,
                    quantity: 1,
                },
            ],
            mode: 'subscription',
            success_url: `${process.env.SITE_DOMAIN}?success=true`,
            cancel_url: `${process.env.SITE_DOMAIN}?cancel=true`,
            customer_update: {
                address: 'auto',
            },
        });

        res.json({ url: session.url });
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session.' });
    }
});

subscriptionRouter.post('/create-portal-session', standardLimiter, authenticateTokenWithId, async (req, res) => {
    try {
        const db = getDB();

        const user = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM users WHERE id = ?', [req.body.id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!user.stripe_customer_id) {
            return res.status(400).json({ error: 'No active subscription found.' });
        }

        const portalSession = await stripe.billingPortal.sessions.create({
            customer: user.stripe_customer_id,
            return_url: process.env.SITE_DOMAIN,
        });

        res.json({ url: portalSession.url });
    } catch (error) {
        console.error('Error creating portal session:', error);
        res.status(500).json({ error: 'Failed to create portal session.' });
    }
});

subscriptionRouter.post(
    '/webhook',
    express.raw({ type: 'application/json' }),
    async (req, res) => {
        let event;

        try {
            if (process.env.STRIPE_WEBHOOK_SECRET) {
                const signature = req.headers['stripe-signature'];
                event = stripe.webhooks.constructEvent(
                    req.body,
                    signature,
                    process.env.STRIPE_WEBHOOK_SECRET
                );
            } else {
                event = req.body;
            }

            switch (event.type) {
                case 'checkout.session.completed': {
                    const session = event.data.object;
                    const subscription = await stripe.subscriptions.retrieve(session.subscription);
                    const product = await stripe.products.retrieve(subscription.items.data[0].price.product);

                    // Get user from customer ID
                    const user = await getUserByStripeCustomerId(session.customer);

                    // Update user limits based on product metadata
                    if (product.metadata.report_limit && product.metadata.moderator_limit) {
                        await updateUserLimits(
                            user.id,
                            parseInt(product.metadata.report_limit),
                            parseInt(product.metadata.moderator_limit),
                            parseInt(product.metadata.subscription_tier)
                        );
                    }

                    // Send confirmation email
                    await sendSubscriptionEmail(
                        user.email,
                        session.id,
                        session.amount_total,
                        product.name
                    );
                    break;
                }

                case 'customer.subscription.created':
                case 'customer.subscription.deleted':
                case 'customer.subscription.updated': {
                    const subscription = event.data.object;
                    const user = await getUserByStripeCustomerId(subscription.customer);

                    if (subscription.status === 'active') {
                        // Get the product details and update limits
                        const product = await stripe.products.retrieve(subscription.items.data[0].price.product);
                        await updateUserLimits(
                            user.id,
                            parseInt(product.metadata.report_limit),
                            parseInt(product.metadata.moderator_limit),
                            parseInt(product.metadata.subscription_tier)
                        );
                    } else if (subscription.status === 'canceled' || subscription.status === 'unpaid') {
                        // Reset to default limits
                        await updateUserLimits(
                            user.id,
                            DEFAULT_REPORT_LIMIT,
                            DEFAULT_MODERATOR_LIMIT,
                            0
                        );
                    }
                    break;
                }
            }

            res.json({ received: true });
        } catch (error) {
            console.error('Webhook error:', error);
            res.status(400).json({ error: 'Webhook error' });
        }
    }
);

module.exports = subscriptionRouter;