const asyncHandler = require('express-async-handler');
const User = require('../models/user.model');
const bcrypt = require('bcryptjs');

const register = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email ||password) {
        res.status(400);
        throw new Error('Please fill in all required fields');
    }

    if (password.length < 6) {
        res.status(400);
        throw new Error('Password must be up to 6 characters');
    }

    // Check if user exists
    const userExists = await User.findOne({ email });

    if (!userExists) {
        res.status(400);
        throw new Error('Email already in use');
    }

    // Create new user
    const user = await User.create({ name, email, password });
});

module.exports = { register };