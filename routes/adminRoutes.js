const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const authMiddleware = require('../middleware/authMiddleware');

router.post('/register', adminController.registerAdmin);
router.post('/login', adminController.loginAdmin);
router.get('/assignments', authMiddleware, adminController.getAssignments);
router.post('/assignments/:id/accept', authMiddleware, adminController.acceptAssignment);
router.post('/assignments/:id/reject', authMiddleware, adminController.rejectAssignment);

module.exports = router;
