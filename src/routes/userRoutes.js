const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

router.post('/signup', userController.signup);
router.get('/users/:user_id', userController.getUser);
router.patch('/users/:user_id', userController.updateUser);
router.post('/close', userController.deleteUser);

module.exports = router;
