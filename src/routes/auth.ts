import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { protect } from '../middleware/authMiddleware';
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

export default router;