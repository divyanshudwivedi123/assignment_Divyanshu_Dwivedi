const User = require('../models/User');
const Admin = require('../models/Admin');
const types = require('../config/types');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Assignment = require('../models/Assignment');

exports.registerUser = async (req, res) => {
    
    const body = req.body;
    const validation = types.userCheck.safeParse(body);
    if(!validation.success){
        if(validation.error.errors[0].message === "Required"){
            return res.status(400).json({
                message: 'Enter all the fields !'
            })
        }
        return res.status(400).json({
            message: validation.error.errors[0].message
        })
    }
    const { username, password } = req.body;

    try {
        // Check if the username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username is already taken' });
        }

        // Hash the password and create the new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });

    } catch (err) {
        console.error("Error registering user:", err);
        res.status(500).json({ message: 'Internal server error' });
    }
};

exports.loginUser = async (req, res) => {

    const body = req.body;
    const validation = types.userCheck.safeParse(body);
    if(!validation.success){
        if(validation.error.errors[0].message === "Required"){
            return res.status(400).json({
                message: 'Enter all the fields !'
            })
        }
        return res.status(400).json({
            message: validation.error.errors[0].message
        })
    }

    const { username, password } = req.body;

    try {
        // Find the user in the database
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Compare the provided password with the hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate a JWT token for the user
        const token = jwt.sign({ id: user._id, type: 'user' }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Send the token as a cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: false
        });

        res.status(200).json({ message: 'Login successful'});

    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
};

exports.uploadAssignment = async (req, res) => {
    // Check if admin is requesting
    if (req.admin) {
        return res.status(403).json({ message: 'Admins are not allowed to upload assignments' });
    }

    const body = req.body;
    const validation = types.uploadAssignmentCheck.safeParse(body);
    if(!validation.success){
        if(validation.error.errors[0].message === "Required"){
            return res.status(400).json({
                message: 'Enter all the fields !'
            })
        }
        return res.status(400).json({
            message: validation.error.errors[0].message
        })
    }
    // If not an admin, proceed to handle the assignment upload
    const { task, admin } = req.body;  

    try {
        // Search for admin in database
        const foundAdmin = await Admin.findOne({ username: admin });

        // If the admin does not exist
        if (!foundAdmin) {
            return res.status(404).json({ message: 'This admin does not exist! Give a valid admin name!' });
        }

        const userId = req.user._id;  // userId from the authenticated user

        // Create a new assignment with userId, task, and the found admin's ID
        const newAssignment = new Assignment({
            userId,
            task,
            adminId: foundAdmin._id 
        });

        await newAssignment.save(); 
        return res.status(201).json({ message: 'Assignment uploaded successfully' });
    } catch (error) {
        console.error('Error uploading assignment:', error);
        return res.status(500).json({ message: 'Failed to upload assignment. Please try again later.' });
    }
};

exports.getAdmins = async (req, res) => {
    try {
        // Retrieve the usernames of all admins
        const admins = await Admin.find({}, 'username');

        // Check if no admins were found
        if (admins.length === 0) {
            return res.status(404).json({ message: 'No admins found' });
        }

        // Respond with the list of admin usernames
        res.status(200).json(admins);
    } catch (error) {
        console.error('Error fetching admins:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};



