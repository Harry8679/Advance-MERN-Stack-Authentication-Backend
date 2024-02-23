const express = require('express');
const { register, login, logout, getUser, update, deleteUser, getAllUsers, loginStatus, upgradeUser, sendAutomatedEmail, sendVerificationEmail, verifyUser, forgotPassword } = require('../controllers/user.controller');
const { protected, adminOnly, authorOnly } = require('../middlewares/auth.middleware');
const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/logout', logout);
router.get('/getUser', protected, getUser);
router.patch('/updateUser', protected, update);
router.delete('/:id', protected, adminOnly, deleteUser);
router.get('/getUsers', protected, authorOnly, getAllUsers);
router.get('/loginStatus', loginStatus);
router.post('/upgradeUser', protected, adminOnly, upgradeUser);
router.post('/verificationEmail', protected, sendVerificationEmail);
router.post('/sendAutomatedEmail', protected, sendAutomatedEmail);
router.patch('/verifyUser/:verificationToken', protected, verifyUser);
router.post('/forgotPassword/', forgotPassword);

module.exports = router;