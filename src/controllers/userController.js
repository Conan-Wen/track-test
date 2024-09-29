const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// in-memory データベース
let users = [];

exports.signup = (req, res) => {
    const user_id = req.body.user_id.trim();
    const password = req.body.password.trim();

    if (!user_id || !password) {
        return res.status(400).json({
            message: 'Account creation failed',
            cause: 'required user_id and password'
        });
    }

    if (user_id.length < 6 || user_id.length > 20) {
        return res.status(400).json({
            message: 'Account creation failed',
            cause: 'user_id length must be between 6 and 20 characters'
        });
    }

    if (password.length < 8 || password.length > 20) {
        return res.status(400).json({
            message: 'Account creation failed',
            cause: 'password length must be between 8 and 20 characters'
        });
    }

    if (users.find(user => user.user_id === user_id)) {
        return res.status(400).json({
            message: 'Account creation failed',
            cause: 'already same user_id is used'
        });
    }

    const hashedPassword = bcrypt.hashSync(password, 8);

    const newUser = { user_id, password: hashedPassword, nickname: user_id, comment: '' };
    users.push(newUser);

    res.status(200).json({
        message: 'Account successfully created',
        user: {
            user_id: newUser.user_id,
            nickname: newUser.nickname
        }
    });
};

exports.getUser = (req, res) => {
    const { user_id } = req.params;
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: 'Authentication Failed' });
    }

    const base64Credentials = authHeader.split(' ')[1];
    const [authUserId, password] = Buffer.from(base64Credentials, 'base64').toString('ascii').split(':');

    const user = users.find(u => u.user_id === user_id);

    if (!user) {
        return res.status(404).json({ message: 'No User found' });
    }

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ message: 'Authentication Failed' });
    }

    res.status(200).json({
        message: 'User details by user_id',
        user: {
            user_id: user.user_id,
            nickname: user.nickname || user.user_id,
            comment: user.comment || undefined
        }
    });
};

exports.updateUser = (req, res) => {
    const { user_id } = req.params;
    const { nickname, comment } = req.body;
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: 'Authentication Failed' });
    }

    const base64Credentials = authHeader.split(' ')[1];
    const [authUserId, password] = Buffer.from(base64Credentials, 'base64').toString('ascii').split(':');

    const user = users.find(u => u.user_id === user_id);

    if (!user) {
        return res.status(404).json({ message: 'No User found' });
    }

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ message: 'Authentication Failed' });
    }

    if (authUserId !== user_id) {
        return res.status(403).json({
            "message": "No Permission for Update"
        });
    }

    if (!nickname && !comment) {
        return res.status(400).json({
            message: 'User updation failed',
            cause: 'required nickname or comment'
        });
    }

    if (nickname) {
        user.nickname = nickname;
    }
    if (comment) {
        user.comment = comment;
    }

    if (req.body.password || req.body.user_id) {
        return res.status(400).json({
            "message": "User updation failed",
            "cause": "not updatable user_id and password"
        });
    }

    res.status(200).json({
        message: 'User successfully updated',
        user: {
            nickname: user.nickname,
            comment: user.comment
        }
    });
};

exports.deleteUser = (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: 'Authentication Failed' });
    }

    const base64Credentials = authHeader.split(' ')[1];
    const [authUserId, password] = Buffer.from(base64Credentials, 'base64').toString('ascii').split(':');

    const userIndex = users.findIndex(u => u.user_id === authUserId);

    if (userIndex === -1) {
        return res.status(404).json({ message: 'No User found' });
    }

    const validPassword = bcrypt.compareSync(password, users[userIndex].password);
    if (!validPassword) {
        return res.status(401).json({ message: 'Authentication Failed' });
    }

    users.splice(userIndex, 1);
    res.status(200).json({ message: 'Account and user successfully removed' });
};
