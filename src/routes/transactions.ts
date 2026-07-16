import express from 'express';
import { protect } from '../middleware/authMiddleware';
import Transaction from '../models/Transaction';

const router = express.Router();

// Get all transactions for the logged-in user
router.get('/', protect, async (req: any, res) => {
    try {
        const items = await Transaction.find({ user: req.user.id });
        res.json(items);
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// Add a new transaction
router.post('/', protect, async (req: any, res) => {
    try {
        const newTransaction = new Transaction({
            ...req.body,
            user: req.user.id
        });
        const savedItem = await newTransaction.save();
        res.json(savedItem);
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// Delete a transaction
router.delete('/:id', protect, async (req: any, res) => {
    try {
        const transaction = await Transaction.findById(req.params.id);
        if (!transaction) return res.status(404).json({ message: "Not found" });

         // Ensure user owns the transaction
         if (transaction.user.toString() !== req.user.id) {
            return res.status(401).json({ message: "Not authorized" });
         }

         await transaction.deleteOne();
         res.json({ message: "Transaction removed" });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

export default router;