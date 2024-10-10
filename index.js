const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');
const cookieParser = require("cookie-parser");
dotenv.config();
const app = express();
app.use(express.json());
app.use(cookieParser());
connectDB();

app.use('/user', userRoutes);
app.use('/admin', adminRoutes);

const PORT = process.env.PORT;

app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
