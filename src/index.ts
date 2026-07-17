import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/auth';
import transactionRoutes from './routes/transactions';

dotenv.config();

const app = express();

// Middleware
app.use(express.json()); // Allows the server to read JSON data
app.use(cors()); // Allows your React app to talk to this server

app.use('/api/auth', authRoutes);

app.use('/api/transactions', transactionRoutes);

// Connect to Database
mongoose.connect(process.env.MONGO_URI as string)
    .then(() => console.log("Database connected successfully!"))
    .catch((err) => console.log("Database connection error:", err));

    // Test Rout
    app.get('/', (req, res) => {
        res.send("The SecureNode Vault API is running!");
    });

    const PORT = process.env.PORT || 5000;
    app.listen(PORT, "0.0.0.0", () => {
        console.log(`Server is running on port ${PORT}`);
    });