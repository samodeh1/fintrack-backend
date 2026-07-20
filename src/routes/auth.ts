import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { protect } from '../middleware/authMiddleware';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import User from '../models/User';
import axios from 'axios';

const router = express.Router();

// --- 1. REGISTER ROUTE ---
router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const lowerEmail = email.toLowerCase(); // Ensure email is saved in lowercase

        const userExists = await User.findOne({ email: lowerEmail });
        if (userExists) {
            return res.status(400).json({ message: "User already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            username,
            email: lowerEmail,
            password: hashedPassword
        });

        await newUser.save();
        res.status(201).json({ message: "User registered successfully!" });

    } catch (error) {
         res.status(500).json({ message: "Server error during registration" });
    }
});

// --- 2. LOGIN ROUTE ---
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const lowerEmail = email.toLowerCase();

        const user: any = await User.findOne({ email: lowerEmail });
        if (!user) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }

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

// --- 3. CUSTOM GOOGLE LOGIN (For the new Styled Button) ---
router.post('/google', async (req, res) => {
    const { token } = req.body; // This is the access_token from the frontend
    try {
        // Fetch user info directly from Google
        const googleRes = await axios.get(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${token}`);
        const payload = googleRes.data;

        if (!payload) return res.status(400).json({ message: "Invalid Google Token" });

        const { email, name, sub } = payload;
        const lowerEmail = email.toLowerCase();

        let user = await User.findOne({ email: lowerEmail });

        if (!user) {
            user = new User({
                username: name,
                email: lowerEmail,
                password: sub, // Dummy password using Google ID
            });
            await user.save();
        }

        const ourToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET as string, { expiresIn: '1h' });

        res.json({ token: ourToken, user });
    } catch (error) {
        console.error("Google Auth Error:", error);
        res.status(500).json({ message: "Google authentication failed" });
    }
});

// --- 4. FORGOT PASSWORD ---
router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user: any = await User.findOne({ email: email.toLowerCase() });

        if (!user) return res.status(404).json({ message: "Email not found" });

        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; 
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
        });

        const resetUrl = `https://smart-ledger-xw6w.vercel.app/reset/${token}`;

        await transporter.sendMail({
            to: user.email,
            subject: 'FinanceFlow | Password Reset Request', 
            text: `You requested a password reset from FinanceFlow. Click here to reset: ${resetUrl}`
        });

        res.json({ message: "Reset link sent to your email!" });
    } catch (err) {
        res.status(500).json({ message: "Error sending email" });
    }
});

// --- 5. RESET PASSWORD ---
router.post('/reset-password/:token', async (req, res) => {
    try {
        const user: any = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).json({ message: "Invalid or expired token" });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(req.body.password, salt);
        
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        
        await user.save();
        res.json({ message: "Password updated successfully!" });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// --- 6. PROTECTED PROFILE ROUTE ---
router.get('/profile', protect, async (req: any, res) => {
    try {
         const user = await User.findById(req.user.id).select('-password');
         res.json(user);
    } catch (error) {
        res.status(500).json({ message: "Server Error" });
    }
});

export default router;