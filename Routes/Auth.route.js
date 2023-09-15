const express = require('express')
const router = express.Router()
const AuthController = require('../Controllers/Auth.Controller')
const AuthMethods = require('../middleware/authMiddleware')

router.post('/register', AuthController.register)

router.post('/login', AuthController.login)

router.post('/refresh-token', AuthController.refreshToken)

router.delete('/logout', AuthMethods.verifyAccessToken ,AuthController.logout)

module.exports = router
