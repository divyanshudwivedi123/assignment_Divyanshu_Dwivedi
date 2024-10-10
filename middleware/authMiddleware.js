const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');
const User = require('../models/User');

const authMiddleware = async (req, res, next) => {
    // Check for token in cookies
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).send('Access denied. Login Again !');
    }

    try {
        // Verify the JWT token
        const verified = jwt.verify(token, process.env.JWT_SECRET);

        // Check the user type
        if (verified.type === 'admin') {
            // If the token belongs to an admin
            req.admin = await Admin.findById(verified.id);
            if (!req.admin) return res.status(404).send('Admin not found.');
        } else if (verified.type === 'user') {
            // If the token belongs to a user
            req.user = await User.findById(verified.id);
            if (!req.user) return res.status(404).send('User not found.');
        } else {
            return res.status(400).send('Invalid token type.');
        }
        next();
    } catch (err) {
        console.error('Error verifying token:', err);
        res.status(400).send('Invalid token.');
    }
};

module.exports = authMiddleware;
