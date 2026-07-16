import mongoose from "mongoose";


// 1. Define the Blueprint for a user
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

// 2. Export the model so we can use it to save data
export default mongoose.model('User', UserSchema);

