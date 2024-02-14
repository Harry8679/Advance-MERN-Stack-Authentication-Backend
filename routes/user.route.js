const express = require('express');
const { register } = require('../controllers/user.controller');
const router = express.Router();

router.post('/register', register);

module.exports = router;