const zod = require('zod');
const mongoose = require('mongoose');

exports.adminRegisterCheck = zod.object({
    username: zod.string().min(6, { message: 'Enter username of min 6 characters!' }),
    password: zod.string().min(6, { message: 'Enter password of at least 6 digits!' }),
    secret: zod.string().min(6, { message: 'Enter the correct secret!' }) // Enforces both the required field and the minimum length
});


exports.adminLoginCheck = zod.object({
    username: zod.string().min(6, { message: 'Enter username of min 6 characters !' }),
    password: zod.string().min(6, { message: 'Enter password of min 6 digits !' })
})

exports.userCheck = zod.object({
    username: zod.string().min(6, { message: 'Enter username of min 6 characters !' }),
    password: zod.string().min(6, { message: 'Enter password of min 6 digits !' })
})

exports.assignmentIdCheck = zod.string().refine((id) => mongoose.Types.ObjectId.isValid(id), 
{ message: 'Enter valid assignment ID !' });

exports.uploadAssignmentCheck = zod.object({
    task: zod.string().min(6, {message: 'Minimum task size can be 6 characters !' }),
    admin: zod.string().min(6, {message: 'Enter a valid admin name !' })
})