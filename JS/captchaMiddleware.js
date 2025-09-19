import { randomUUID } from 'crypto';

// Validate captcha with Cloudflare Turnstile
const validateCaptcha = async (req, res, next) => {
    const turnstileToken = req.headers['cf-turnstile-response'];
    if (!turnstileToken) return res.status(400).json({ error: "Turnstile token missing." });

    try {
        const verificationUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        const validationResponse = await fetch(verificationUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                secret: process.env.CAPTCHA_SECRET_KEY,
                response: turnstileToken,
                remoteip: req.clientIp || req.ip,
                idempotency_key: randomUUID()
            })
        });
        if (!validationResponse.ok) throw new Error(`HTTP error: ${validationResponse.status}`);

        const data = await validationResponse.json();
        const { success, error_codes } = data;

        if (!success) return res.status(403).json({ error: 'Captcha validation failed.', error_codes });

        // Continue with other functions
        next();
    } catch (err) {
        console.error("Error during Turnstile Captcha validation: ", err);
        return res.status(500).json({ error: 'Error validating Captcha (Turnstile) token.' });
    }
};

export default validateCaptcha;