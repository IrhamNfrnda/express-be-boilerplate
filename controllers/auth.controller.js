const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const users = require('../models/users.model');
const { registerValidation, loginValidation } = require('../middlewares/validation');

// Function to generate access token
const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.TOKEN_SECRET, { expiresIn: '1d' });
}

// Function to generate refresh token
const generateRefreshToken = (user) => {
    return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
}

// Function to register user
const register = async (req, res) => {
    try {
        const {
            email, fullname, password
        } = req.body
  
        // Check email is already exist using middleware
        const { error } = registerValidation(req.body)
        if (error) {
            return res.status(400).json({
                status: false,
                message: error.details[0].message
            })
        }
  
        // Hash password
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password, salt)
  
        const createUser = await users.createUser({
            email,
            fullname,
            password: hashedPassword
        })
  
        return res.status(200).json({
            status: true,
            message: 'Success Register!',
            data: createUser
        })
    } catch (error) {
        return res.status(500).json({
            status: false,
            message: error.message
        })
        }
}

// Function to login user
const login = async (req, res) => {
    try {
        const { email, password } = req.body

        // Check email is already exist using middleware
        const { error } = loginValidation(req.body)
        if (error) {
            return res.status(400).json({
                status: false,
                message: error.details[0].message
            })
        }

        // Check email is already exist
        const user = await users.findUser({ email })
        if (!user) {
            return res.status(400).json({
                status: false,
                message: 'Email is not found'
            })
        }

        // Check password is correct
        const validPassword = await bcrypt.compare(password, user.password)
        if (!validPassword) {
            return res.status(400).json({
                status: false,
                message: 'Invalid password'
            })
        }

        // Create and assign a token
        const accessToken = generateAccessToken({ id: user._id })
        const refreshToken = generateRefreshToken({ id: user._id })

        // Save refresh token to database
        await users.updateRefreshToken({ email }, { refreshToken })

        return res.status(200).json({
            status: true,
            message: 'Success Login!',
            data: {
                accessToken,
                refreshToken
            }
        })
    } catch (error) {
        return res.status(500).json({
            status: false,
            message: error.message
        })
    }
}

// Function to logout user
const logout = async (req, res) => {
    try {
        const { email } = req.user

        // Delete refresh token from database
        await users.updateRefreshToken({ email }, { refreshToken: '' })

        return res.status(200).json({
            status: true,
            message: 'Success Logout!'
        })
    } catch (error) {
        return res.status(500).json({
            status: false,
            message: error.message
        })
    }
}

// Function to refresh token
const refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body

        // Check refresh token is exist
        if (!refreshToken) {
            return res.status(400).json({
                status: false,
                message: 'Refresh token is required'
            })
        }

        // Check refresh token is valid
        const user = await users.findUser({ refreshToken })
        if (!user) {
            return res.status(400).json({
                status: false,
                message: 'Refresh token is not found'
            })
        }

        // Verify refresh token
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({
                    status: false,
                    message: 'Invalid refresh token'
                })
            }

            // Create and assign a token
            const accessToken = generateAccessToken({ id: user._id })
            const refreshToken = generateRefreshToken({ id: user._id })

            // Save refresh token to database
            users.updateRefreshToken({ email: user.email }, { refreshToken })

            return res.status(200).json({
                status: true,
                message: 'Success Refresh Token!',
                data: {
                    accessToken,
                    refreshToken
                }
            })
        })
    } catch (error) {
        return res.status(500).json({
            status: false,
            message: error.message
        })
    }
}

module.exports = {
    register,
    login,
    logout,
    refreshToken
}
