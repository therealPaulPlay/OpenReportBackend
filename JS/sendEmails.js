const nodemailer = require('nodemailer');

// Configure your email service - !CHANGE these details to match your email provider
let transporter = nodemailer.createTransport({
    host: "smtp.example.com",
    port: 465,
    auth: {
        user: "email-address",
        pass: "password", // Ideally store in a .env file
    },
});

async function sendMail(options) {
    await transporter.sendMail(options);
}

module.exports = { sendMail };