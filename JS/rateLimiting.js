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
    message: { error: 'Too many accounts created from this IP, please try again after 30 minutes.' }
});

const standardLimiter = rateLimit({
    windowMs: 1000,
    keyGenerator: (req) => req.clientIp,
    max: 10,
    message: { error: 'You are sending too many requests.' }
});

const submitLimiter = rateLimit({
    windowMs: 16 * 60 * 60 * 1000,
    keyGenerator: (req) => req.clientIp,
    max: 10,
    message: { error: 'You have submitted too many reports for today.' }
});

const highLimiter = rateLimit({
    windowMs: 1000,
    keyGenerator: (req) => req.clientIp,
    max: 50,
    message: { error: 'You are sending too many requests.' }
});

const appCreationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    keyGenerator: (req) => req.clientIp,
    max: 10,
    message: { error: 'You can create max. 10 apps per hour.' }
});

const manualEntryLimiter = rateLimit({
    windowMs: 24 * 60 * 60 * 1000,
    keyGenerator: (req) => req.clientIp,
    max: 1000,
    message: { error: 'You can modify max. 1000 entries individually per day to prevent misuse.' }
});


module.exports = { loginLimiter, registerLimiter, standardLimiter, appCreationLimiter, manualEntryLimiter, highLimiter, submitLimiter };