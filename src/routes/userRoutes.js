const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

router.post('/signup', userController.signup);
router.get('/:user_id', userController.getUser);
router.patch('/:user_id', userController.updateUser);
router.post('/close', userController.deleteUser);

module.exports = router;
