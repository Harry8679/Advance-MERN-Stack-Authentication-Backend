const express = require('express');
const { register, login, logout, getUser, update, deleteUser } = require('../controllers/user.controller');
const { protected, adminOnly } = require('../middlewares/auth.middleware');
const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/logout', logout);
router.get('/getUser', protected, getUser);
router.patch('/updateUser', protected, update);
router.delete('/:id', protected, adminOnly, deleteUser);

module.exports = router;