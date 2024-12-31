const express = require('express');
const accountRouter = express.Router();

const jwt = require('jsonwebtoken');
const { standardLimiter, registerLimiter, loginLimiter } = require("./rateLimiting.js");
const { getEncodedPassword, isPasswordValid, createNewJwtToken, authenticateTokenWithId } = require("./authUtils.js");
const { getDB } = require("./connectDB.js");
const { sendMail } = require('./sendEmails.js');

// Get user details
accountRouter.get('/user/:id', standardLimiter, authenticateTokenWithId, async (req, res) => {
    const id = req.params?.id;
    if (id == null) return res.status(400).json({ error: "Id is required." });

    const db = getDB();


    try {
        const getUserQuery = 'SELECT * FROM users WHERE id = ?';
        const details = await new Promise((resolve, reject) => {
            db.query(getUserQuery, [id], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        if (!details || details.length === 0) return res.status(404).json({ error: "User not found." });
        res.json({ user: details[0] });

    } catch (error) {
        console.error("Error getting user:", error);
        res.status(500).json({ error: "An error occured getting the user: " + error.message });
    }
});

// Register Endpoint
accountRouter.post('/register', registerLimiter, async (req, res) => {
    const db = getDB();

    let { userName, email, password } = req.body; // Include these 3 properties in the request body

    if (!userName || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required.' });
    }

    userName = userName.trim(); // Remove whitespaces from username
    email = email.trim().toLowerCase(); // Remove whitespaces from email and lowercase

    if (userName.length < 4) {
        return res.status(400).json({ error: "Username is too short." });
    }

    try {
        // Check if email already exists
        const emailExistsQuery = 'SELECT id FROM users WHERE email = ?';
        const existingEmailUser = await new Promise((resolve, reject) => {
            db.query(emailExistsQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (existingEmailUser) {
            return res.status(409).json({ error: 'Email is already in use.' });
        }

        // Generate hashed password
        const hashedPassword = await getEncodedPassword(password);

        // Get current timestamp
        const now = new Date();

        // Insert new user into the database
        const insertUserQuery = 'INSERT INTO users (user_name, email, password, created_at) VALUES (?, ?, ?, ?)';
        const newUser = await new Promise((resolve, reject) => {
            db.query(insertUserQuery, [userName, email, hashedPassword, now], (err, results) => {
                if (err) return reject(err);
                resolve(results.insertId);
            });
        });

        res.status(201).json({ message: 'Registration successful.' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'An error occurred during registration.' });
    }
});

// Login Endpoint
accountRouter.post('/login', loginLimiter, async (req, res) => {
    const db = getDB();
    const { email, password } = req.body; // Include these 2 properties in the request body

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        // Find user by email
        const userQuery = 'SELECT id, user_name, password FROM users WHERE email = ?';
        const user = await new Promise((resolve, reject) => {
            db.query(userQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        // Check password
        const isValidPassword = await isPasswordValid(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        // Generate JWT token
        const accessToken = createNewJwtToken({ email, id: user.id });

        res.json({
            message: 'Login successful',
            bearerToken: accessToken, // Here, the bearer token is being returned. Save it in the frontend to authorize future requests.
            id: user.id,
            userName: user.user_name
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'An error occurred during login.' });
    }
});

// Delete Account endpoint
accountRouter.delete('/delete', standardLimiter, async (req, res) => {
    const db = getDB();
    const { id, password } = req.body; // include these 2 properties in the request body

    if (!id || !password) {
        return res.status(400).json({ error: 'Id and password are required.' });
    }

    try {
        // Find user by email to retrieve password hash
        const userQuery = 'SELECT password FROM users WHERE id = ?';
        const user = await new Promise((resolve, reject) => {
            db.query(userQuery, [id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials. User not found.' });
        }

        // Check password
        const isValidPassword = await isPasswordValid(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        // Delete user account
        const deleteUserQuery = 'DELETE FROM users WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(deleteUserQuery, [id], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        res.json({ message: 'Account deleted successfully.' });
    } catch (error) {
        console.error('Error during account deletion:', error);
        res.status(500).json({ error: 'An error occurred during account deletion.' });
    }
});

// Password resets via email -----------------------------------------------------------------------------

// request password reset email endpoint
accountRouter.post('/reset-password-request', standardLimiter, async (req, res) => {
    const db = getDB();
    const { email } = req.body; // include this property in the request body

    if (!email) {
        return res.status(400).json({ error: 'Email is required.' });
    }

    try {
        // Find user by email
        const userQuery = 'SELECT id FROM users WHERE email = ?';
        const user = await new Promise((resolve, reject) => {
            db.query(userQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!user) {
            return res.status(404).json({ error: 'No account with that email found.' });
        }

        // Create a password reset token
        const resetToken = jwt.sign({ email: email, id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Send email with the reset token
        const resetUrl = `https://openreport.dev/login?token=${resetToken}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset',
            text: `Please click this link to reset your password: ${resetUrl}` // You can adjust the text as you wish
        };

        await sendMail(mailOptions);

        res.json({ message: 'Password reset email sent.' });
    } catch (error) {
        console.error('Error during password reset request:', error);
        res.status(500).json({ error: 'An error occurred during password reset request.' });
    }
});

// Reset password endpoint
accountRouter.post('/reset-password', standardLimiter, async (req, res) => {
    const db = getDB();
    const { token, newPassword } = req.body; // include these 2 properties in the request body

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token and new password are required.' });
    }

    try {
        // Verify the reset token + get user Id from the token so that the correct account's password can be changed
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Hash the new password
        const hashedPassword = await getEncodedPassword(newPassword);

        // Update the user's password in the database
        const updatePasswordQuery = 'UPDATE users SET password = ? WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(updatePasswordQuery, [hashedPassword, decoded.id], (err, results) => { // This takes the id from the authentication token to ensure only this account can be resetted
                if (err) return reject(err);
                resolve(results);
            });
        });

        res.json({ message: 'Password reset successfully.' });
    } catch (error) {
        console.error('Error during password reset:', error);
        res.status(500).json({ error: 'An error occurred during password reset.' });
    }
});

module.exports = accountRouter;