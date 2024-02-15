const express = require('express');
const { register, login, logout, getUser, update } = require('../controllers/user.controller');
const { protected } = require('../middlewares/auth.middleware');
const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/logout', logout);
router.get('/getUser', protected, getUser);
router.put('/update', protected, update);

module.exports = router;