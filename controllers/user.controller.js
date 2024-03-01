const asyncHandler = require('express-async-handler');
const User = require('../models/user.model');
const bcrypt = require('bcryptjs');
const { generateToken, hashToken } = require('../utils/index.util');
const sendEmail = require('../utils/sendEmail.util');
let parser = require('ua-parser-js');
const jwt = require('jsonwebtoken');
const Token = require('../models/token.model');
const crypto = require('crypto');
const Cryptr = require('cryptr');

const cryptr = new Cryptr(process.env.CRYPTR_KEY);

const register = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
        res.status(400);
        throw new Error('Please fill in all required fields');
    }

    if (password.length < 6) {
        res.status(400);
        throw new Error('Password must be up to 6 characters');
    }

    // Check if user exists
    const userExists = await User.findOne({ email });

    if (userExists) {
        res.status(400);
        throw new Error('Email already in use');
    }

    // Get UserAgent
    const ua = parser(req.headers['user-agent']);
    const userAgent = [ua.ua];

    // Create new user
    const user = await User.create({ name, email, password, userAgent });

    // Generate token
    const token =  generateToken(user._id);

    // Send HTTP-Only cookie
    res.cookie('token', token, {
        path: '/',
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 24 * 60 * 60), // 1 day
        sameSite: 'none',
        secure: true
    });

    if (user) {
        const { _id, name, email, phone, bio, photo, role, isVerified } = user;

        res.status(201).json({ _id, name, email, phone, bio, photo, role, isVerified, token });
    } else {
        res.status(400);
        throw new Error('Invalid User data');
    }
});


// ----------- Verification Email --------------------
const sendVerificationEmail = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (!user) {
        res.status(404);
        throw new Error('User not found.'); 
    }

    if (user.isVerified) {
        res.status(400);
        throw new Error('User already verified');
    }

    // Delete Token if exists in DB
    let token = await Token.findOne({ userId: user._id });

    if (token) {
        await Token.deleteOne();
    }

    // Create verification Token And Save
    const verificationToken = crypto.randomBytes(32).toString('hex') + user._id;
    console.log('Verification Token', verificationToken);

    // Hash Token and save
    const hashedToken = hashToken(verificationToken);
    await new Token({
        userId: user._id,
        vToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // 60 minutes
    }).save();

    // Construction Verification URL
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

    // Send Email
    const subject = 'Verify Your Account - EMARH';
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = 'noreply@lhlp.fr';
    const template = 'verifyEmail';
    const name = user.name;
    const link = verificationUrl;

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
        res.status(200).json({ message: 'Verification Email sent !' });
    } catch(error) {
        res.status(500);
        throw new Error('Email  was not sent, try again.');
    }
});


// ----------- Login --------------------
const login = asyncHandler(async(req, res) => {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
        res.status(400);
        throw new Error('Please add email and password');
    }

    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error('User not found, please signup');
    }

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (!passwordIsCorrect) {
        res.status(400);
        throw new Error('Invalid email or password');
    }

    // Trigger 2FA (Two Factors Authentication) for unknow UserAgent
    // The User Agent (Insomnia, Postman, Chrome, Safari ...), 
    // tant qu'il n'est pas stocké en base il va renvoyer un code pour pouvoir rajouter un nouvel agent en base
    const ua = parser(req.headers['user-agent']);
    const thisUserAgent = ua.ua;
    console.log('thisUserAgent', thisUserAgent);
    const allowedAgent = user.userAgent.includes(thisUserAgent);

    if (!allowedAgent) {
        // Generate 6 digit code
        const loginCode = Math.floor(100000 + Math.random() * 900000);
        console.log('loginCode: ' + loginCode);

        // Encrypt login code before saving to DB
        const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

        // Delete Token if it exists in DB
        let userToken = await Token.findOne({ userId: user._id });

        if (userToken) {
            await userToken.deleteOne();
        }

        // Save Token To DB
        await new Token({
            userId: user._id,
            lToken: encryptedLoginCode,
            createdAt: Date.now(),
            expiresAt: Date.now() + 60 * (60 * 1000) // 1h
        }).save();

        res.status(400);
        throw new Error('Check your email for login code');
    }

    // Generate token
    const token = generateToken(user._id);

    if (user && passwordIsCorrect) {
        // Send HTTP-Only cookie
        res.cookie('token', token, {
            path: '/',
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 24 * 60 * 60), // 1 day
            sameSite: 'none',
            secure: true
        });

        const { _id, name, email, phone, bio, photo, role, isVerified } = user;

        res.status(200).json({ _id, name, email, phone, bio, photo, role, isVerified, token });
    } else {
        res.status(500);
        throw new Error('Something went wrong, please try again');
    }
});


// ----------- Logout --------------------
const logout = asyncHandler(async(req, res) => {
    res.cookie('token', '', {
        path: '/',
        httpOnly: true,
        expires: new Date(0),
        sameSite: 'none',
        secure: true
    });

    return res.status(200).json({ message: 'Logout Successful' })
});


// ----------- Get User Infos --------------------
const getUser = asyncHandler(async(req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { _id, name, email, phone, bio, photo, role, isVerified } = user;

        res.status(200).json({ _id, name, email, phone, bio, photo, role, isVerified });

    } else {
        res.status(404);
        throw new Error('User not found');
    }
});


// ----------- Update User --------------------
const update = asyncHandler(async(req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { name, email, phone, bio, photo, role, isVerified } = user

        user.name = req.body.name || name;
        user.email = req.body.email || email;
        user.phone = req.body.phone || phone;
        user.bio = req.body.bio || bio;
        user.photo = req.body.photo || photo;

        const updatedUser = await user.save();

        res.status(200).json({ 
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            phone: updatedUser.phone,
            bio: updatedUser.bio,
            photo: updatedUser.photo,
            role: updatedUser.role,
            isVerified: updatedUser.isVerified,
        });
    } else {
        res.status(404);
        throw new Error('User not found');
    }
});


// ----------- Delete User --------------------
const deleteUser = asyncHandler(async(req, res) => {
    const user = User.findById(req.params.id);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    await user.deleteOne();

    res.status(200).json({
        message: 'User deleted successfully'
    });
});


// ----------- Get All Users --------------------
const getAllUsers = asyncHandler(async(req, res) => {
    const users = await User.find().sort('-createdAt').select('-password');

    if (!users) {
        res.status(500);
        throw new Error('Something went wrong');
    }

    res.status(200).json(users);
});


// ----------- Get Login Status --------------------
const loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        res.json(false);
    }

    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if (verified) {
        return res.json(true);
    }
    return res.json(false);
});


// ----------- Change Role of User --------------------
const upgradeUser = asyncHandler(async(req, res) => {
    const { id, role } = req.body;

    const user = await User.findById(id);

    if (!user) {
        res.status(500);
        throw new Error('User not found');
    }

    user.role = role;
    await user.save();

    res.status(200).json({
        message: `User role updated successfully to ${role}`
    });
});


// ----------- Send Automated Email --------------------
const sendAutomatedEmail = asyncHandler(async(req, res) => {
    const { subject, send_to, reply_to, template, url } = req.body;

    if (!subject || !send_to || !reply_to || !template) {
        res.status(500);
        throw new Error('Missing email parameters');
    }

    // Get user
    const user = await User.findOne({ email: send_to });

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    const sent_from = process.env.EMAIL_USER;
    const name = user.name;
    const link = `${process.env.FRONTEND_URL}${url}`;

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
        res.status(200).json({ message: 'Email sent !' });
    } catch(error) {
        res.status(500);
        throw new Error('Email  was not sent, try again.');
    }
});


// ----------- Verify User --------------------
const verifyUser = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params;

    const hashedToken = hashToken(verificationToken);

    const userToken = await Token.findOne({
        vToken: hashedToken,
        expiresAt: {$gt: Date.now()}
    });

    if (!userToken) {
        res.status(404);
        throw new Error('Invalid or expired token');
    }

    // Find User
    const user = await User.findOne({ _id: userToken.userId });

    if (user.isVerified) {
        res.status(400);
        throw new Error('User is already verified');
    }

    // Now verify user
    user.isVerified = true;
    await user.save();

    res.status(200).json({
        message: 'Account Verification Successfully'
    });
});

const forgotPassword = asyncHandler(async(req, res) => {

    const { email } = req.body;

    const user = await User.findOne({ email });

    if(!user) {
        res.status(404);
        throw new Error('No user with this email');
    }

    // Delete Token if it exists in DB
    let token = await Token.findOne({ userId: user._id });

    if (token) {
        await token.deleteOne();
    }

    // Create Verification Token and Save
    const resetToken = crypto.randomBytes(32).toString('hex') + user._id;
    console.log('resetToken', resetToken);

    // Hash token and save
    const hashedToken = hashToken(resetToken);
    await new Token({
        userId: user._id,
        rToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000) // 1h
    }).save();

    // Construct Reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

    // Send Email
    const subject = 'Password Reset Request - EMARH';
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = 'noreply@emarh-auth.fr';
    const template = 'forgotPassword';
    const name = user.name;
    const link = resetUrl;

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
        res.status(200).json({ message: 'Password Reset Email sent !' });
    } catch(error) {
        res.status(500);
        throw new Error('Email  was not sent, try again.');
    }

});

    const resetPassword = asyncHandler(async(req, res) => {
        // res.send('Reset Password');
        const { resetToken } = req.params;
        const { password } = req.body;

        const hashedToken = hashToken(resetToken);

        const userToken = await Token.findOne({
            rToken: hashedToken,
            expiresAt: { $gt: Date.now() }
        });

        if (!userToken) {
            res.status(404);
            throw new Error("Invalid or Expired Token");
        }

        // Find User
        const user = await User.findOne({ _id: userToken.userId });

        // Now Reset Password
        user.password = password;
        await user.save();

        res.status(200).json({ message: "Password Reset Successful, please login" });
    });

    const changePassword = asyncHandler(async(req, res) => {
        const { oldPassword, password } = req.body;
        const user = await User.findById(req.user._id);

        if (!user) {
            res.status(404);
            throw new Error('User not found');
        }

        if (!oldPassword || !password) {
            res.status(400);
            throw new Error('Please enter old and new password.')
        }

        // Check if old password is correct
        const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

        // Save new Password
        if (user && passwordIsCorrect) {
            user.password = password;
            await user.save();

            res.status(200).json({
                message: 'Password change successful, please re-login !'
            });
        } else {
            res.status(400);
            throw new Error('Votre ancien mot de passe est incorrect');
        }
    });

    const sendLoginCode = asyncHandler(async(req, res) => {
        res.send('Send login code');
    });

module.exports = { 
    register, login, logout, getUser, update, deleteUser, getAllUsers, loginStatus, upgradeUser, sendAutomatedEmail, sendVerificationEmail, verifyUser, forgotPassword, 
    resetPassword, changePassword, sendLoginCode
};