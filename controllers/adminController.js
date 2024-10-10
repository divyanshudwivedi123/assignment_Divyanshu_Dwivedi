const Admin = require('../models/Admin');
const Assignment = require('../models/Assignment');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.registerAdmin = async (req, res) => {
    const { username, password, secret } = req.body;

    // Check if the username is provided
    if (!username) {
        return res.status(400).json({ message: 'Please provide a username' });
    }

    // Check if the password is provided
    if (!password) {
        return res.status(400).json({ message: 'Please provide a password' });
    }

    // Check if the secret is provided
    if (!secret) {
        return res.status(400).json({ message: 'Please provide the secret string' });
    }

    // check username and password length
    if (username.length < 6) {
        return res.status(400).json({ message: 'Username must be at least 6 characters long' });
    }
    if (password.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    // Check if thw secret matches
    if (secret != process.env.ADMIN_SECRET) {
        return res.status(403).json({ message: 'Invalid secret string' });
    }

    try {
        // Check if the username is already taken
        const existingAdmin = await Admin.findOne({ username });
        if (existingAdmin) {
            return res.status(409).json({ message: 'Admin already exists !' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new admin
        const newAdmin = new Admin({ username, password: hashedPassword });
        await newAdmin.save();

        res.status(201).json({ message: 'Admin registered successfully' });
    } catch (error) {
        console.error("Error registering admin:", error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

exports.loginAdmin = async (req, res) => {
    const { username, password } = req.body;

    // Check if username is provided
    if (!username) {
        return res.status(400).json({ message: 'Please provide a username' });
    }

    // Check if password is provided
    if (!password) {
        return res.status(400).json({ message: 'Please provide a password' });
    }

    // Check the length of username and password
    if (username.length < 6) {
        return res.status(400).json({ message: 'Username must be at least 6 characters long' });
    }

    if (password.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    try {
        // Find the admin by username
        const admin = await Admin.findOne({ username });
        
        // Check if admin exists and password matches
        if (!admin) {
            return res.status(404).json({ message: 'Admin not found' });
        }
        
        // Compare the password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate a JWT token for the admin
        const token = jwt.sign({ id: admin._id, type: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Send the token as a cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: false
        });

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error("Error logging in admin:", error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

exports.getAssignments = async (req, res) => {
    // Check if the requester is an admin
    if (!req.admin) {
        return res.status(403).json({ message: 'Access denied. This endpoint is only for admins.' });
    }

    try {
        // Fetch assignments for the specific admin using adminId
        const assignments = await Assignment.find({ adminId: req.admin._id });

        // Check if assignments were found
        if (!assignments.length) {
            return res.status(404).json({ message: 'No assignments found for this admin.' });
        }

        // Return the assignments if found
        res.status(200).json(assignments);
    } catch (error) {
        console.error('Error fetching assignments:', error);
        res.status(500).json({ message: 'Failed to fetch assignments. Please try again later.' });
    }
};

exports.acceptAssignment = async (req, res) => {
    const { id } = req.params;

    // Check if the requester is an admin
    if (!req.admin) {
        return res.status(403).json({ message: 'Access denied. This endpoint is only for admins.' });
    }

    try {
        // Find the assignment by ID
        const assignment = await Assignment.findById(id);
        
        // Check if the assignment exists
        if (!assignment) {
            return res.status(404).json({ message: 'Assignment not found.' });
        }

        // Update the assignment status to 'accepted'
        await Assignment.findByIdAndUpdate(id, { status: 'Accepted' });

        // Respond with a success message
        res.status(200).json({ message: 'Assignment accepted' });
    } catch (error) {
        console.error('Error accepting assignment:', error);
        res.status(500).json({ message: 'Failed to accept assignment. Please try again later.' });
    }
};

exports.rejectAssignment = async (req, res) => {
    const { id } = req.params;

    // Check if the requester is an admin
    if (!req.admin) {
        return res.status(403).json({ message: 'Access denied. This endpoint is only for admins.' });
    }

    try {
        // Find the assignment by ID
        const assignment = await Assignment.findById(id);
        
        // Check if the assignment exists
        if (!assignment) {
            return res.status(404).json({ message: 'Assignment not found.' });
        }

        // Update the assignment status to 'accepted'
        await Assignment.findByIdAndUpdate(id, { status: 'Rejected' });

        // Respond with a success message
        res.status(200).json({ message: 'Assignment Rejected' });
    } catch (error) {
        console.error('Error accepting assignment:', error);
        res.status(500).json({ message: 'Failed to reject assignment. Please try again later.' });
    }
};
