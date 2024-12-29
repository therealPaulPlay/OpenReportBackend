const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 60 * 1000,
    keyGenerator: (req) => req.clientIp, // Use correct ip and not the one of the proxy. This uses request-ip pkg
    max: 5,
    message: 'Too many login attempts from this IP, please try again later.'
});

const registerLimiter = rateLimit({
    windowMs: 30 * 60 * 1000,
    keyGenerator: (req) => req.clientIp,
    max: 5,
    message: { error: 'Too many accounts created from this IP, please try again after 24 hours.' }
});

const standardLimiter = rateLimit({
    windowMs: 1000,
    keyGenerator: (req) => req.clientIp,
    max: 10,
    message: { error: 'You are sending too many requests.' }
});

module.exports = { loginLimiter, registerLimiter, standardLimiter };