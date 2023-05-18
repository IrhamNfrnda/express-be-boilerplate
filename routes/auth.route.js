
const router = require('express').Router()
const authController = require('../controllers/auth.controller')
const { registerValidation, loginValidation } = require('../middlewares/validation')
const verifyToken = require('../middlewares/token.middleware')

router.post('/register', registerValidation, authController.register)
router.post('/login', loginValidation, authController.login)
router.get('/logout', verifyToken, authController.logout)
router.get('/refresh_token', authController.refreshToken)

module.exports = router
