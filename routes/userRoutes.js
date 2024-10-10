const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware');
router.post('/register', userController.registerUser);
router.post('/login', userController.loginUser);
router.post('/upload', authMiddleware, userController.uploadAssignment);
router.get('/admins', authMiddleware, userController.getAdmins);

module.exports = router;
