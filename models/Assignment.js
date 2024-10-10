const mongoose = require('mongoose');

const assignmentSchema = new mongoose.Schema({
    userId: { 
        type: String, 
        required: true 
    },
    task: { 
        type: String, 
        required: true 
    },
    adminId: { 
        type: String, 
        required: true 
    }, 
    status: { 
        type: String, 
        enum: ['pending', 'accepted', 'rejected'], 
        default: 'pending' },
    createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Assignment', assignmentSchema);
