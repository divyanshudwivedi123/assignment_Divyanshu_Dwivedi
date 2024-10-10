const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true, 
        minlength: 6  
    },
    password: { 
        type: String, 
        required: true, 
        minlength: 6  
    },
}, { timestamps: true });  

module.exports = mongoose.model('User', userSchema);
