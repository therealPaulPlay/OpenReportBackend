const nodemailer = require('nodemailer');

// Configure your email service
let transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
    },
});

async function sendMail(options) {
    await transporter.sendMail(options);
}

module.exports = { sendMail };