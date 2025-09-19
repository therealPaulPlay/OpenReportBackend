import crypto from 'crypto';
import { getDB } from './connectDB.js';

async function sendWebhook(appId, type, data) {
    const db = getDB();

    try {
        const query = 'SELECT webhook_url, webhook_secret FROM users_apps WHERE id = ?';
        const [results] = await db.promise().query(query, [appId]);
        const result = results[0];

        if (!result || !result.webhook_url) {
            return;
        }

        const payload = {
            type,
            data
        };

        const signature = crypto
            .createHmac('sha256', result.webhook_secret)
            .update(JSON.stringify(payload))
            .digest('hex');

        const response = await fetch(result.webhook_url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Webhook-Signature': `sha256=${signature}`
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            console.warn(`Webhook delivery failed for app ${appId}: ${response.status} ${response.statusText}`);
        }
    } catch (error) {
        console.warn(`Webhook delivery error for app ${appId}:`, error.message);
    }
}

export { sendWebhook };