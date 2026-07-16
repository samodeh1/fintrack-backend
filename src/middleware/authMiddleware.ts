import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken';

// This function acts as the "Security Guard"
export const protect = (req: any, res: Response, next: NextFunction) => {
    // 1. Get the token from the request header
    const token = req.header('x-auth-token');

    // 2. If no token, deny access
    if (!token) {
        return res.status(401).json({ message: "No token, authorization denied." });
    }

    try {
         // 3. Verify the token using your secret key
         const decoded = jwt.verify(token, process.env.JWT_SECRET as string);

          // 4. Attach the user ID to the request object so the next function can use it

          req.user = decoded;

          // 5. Move to the next step (the actual logic)
          next();
    } catch (error) {
        res.status(401).json({ message: "Token is not valid." });
    }
};