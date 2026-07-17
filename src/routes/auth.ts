import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { protect } from '../middleware/authMiddleware';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { OAuth2Client } from 'google-auth-library';
import User from '../models/User';

const router = express.Router();

// --- THE REGISTER ROUTE ---
router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

            // 1. Check if user already exists
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ message: "User already exists" });
        }

            // 2. Hash the password (Security First!)
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

            // 3. Create and Save the User
        const newUser = new User({
            username,
            email,
            password: hashedPassword
        });

        await newUser.save();
        res.status(201).json({ message: "User registered successfully!" });

    } catch (error) {
         res.status(500).json({ message: "Server error during registration" });
    }
});

// 1. FORGOT PASSWORD - Sends the email
router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user: any = await User.findOne({ email });

        if (!user) return res.status(404).json({ message: "User not found" });

        // Create a random token
        const token = crypto.randomBytes(20).toString('hex');

        // Set token and expiry (1 hour)
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; 
        await user.save();

        // Configure Email Transport
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
        });

        const resetUrl = `https://fintrack-pro-xw6w.vercel.app/reset/${token}`;

        await transporter.sendMail({
            to: user.email,
            subject: 'FinTrack Pro Password Reset',
            text: `You requested a password reset. Click here: ${resetUrl}`
        });

        res.json({ message: "Reset link sent to your email!" });
    } catch (err) {
        res.status(500).json({ message: "Error sending email" });
    }
});

// 2. RESET PASSWORD - Updates the DB with new password
router.post('/reset-password/:token', async (req, res) => {
    try {
        const user: any = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).json({ message: "Invalid or expired token" });

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(req.body.password, salt);
        
        // Clear reset fields
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        
        await user.save();
        res.json({ message: "Password updated successfully!" });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});


// --- 2. THE LOGIN ROUTE ---
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user: any = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }

        // Create Token
        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET as string,
            { expiresIn: '1h' }
        );

        res.json({
            token,
            user: { id: user._id, username: user.username, email: user.email }
        });

    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

// --- THE VIP PROFILE ROUTE ---
router.get('/profile', protect, async (req: any, res) => {
    try {
         // Since we are 'protected', we have access to the user ID
         const user = await User.findById(req.user.id).select('-password'); //Don't send the password!
         res.json(user);
    } catch (error) {
        res.status(500).json({ message: "Server" });
    }
});

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

router.post('/google', async (req, res) => {
    const { token } = req.body;
    try {
        // 1. Verify the token with Google
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        if (!payload) return res.status(400).json({ message: "Invalid Google Token" });

        const { email, name, sub } = payload; // 'sub' is Google's unique user ID

        // 2. Find user or create if they don't exist
        let user = await User.findOne({ email });

        if (!user) {
            user = new User({
                username: name,
                email: email,
                password: sub, // We use the Google ID as a dummy password
            });
            await user.save();
        }

        // 3. Create our own JWT so they can stay logged in
        const ourToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET as string, { expiresIn: '1h' });

        res.json({ token: ourToken, user });
    } catch (error) {
        res.status(500).json({ message: "Google Auth failed on server" });
    }
});



export default router;