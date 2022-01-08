const { Router } = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

// /api/auth/register
router.post(
    '/register', 
    [
        check('email', 'Incorrect e-mail').isEmail(),
        check('password', 'Minimum password length 6 characters')
            .isLength({ min: 6 })
    ],
    async(req, res) => {
    try {
        const errors = validationResult(req)

        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Incorrect data during registration'
            })
        }

        const {email, password} = req.body

        const candidate = await User.findOne({ email })

        if(candidate) {
           return res.status(400).json({ message: 'User already exist' })
        }

        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({ email, password: hashedPassword })

        await user.save()

        res.status(201).json({ message: 'User has been created' })

    } catch(e) {
        res.status(500).json({ message: 'Something goes wrong, try again please' })
    }
})

// /api/auth/login
router.post(
    '/login', 
    [
        check('email', 'Enter correct e-mail').normalizeEmail().isEmail(),
        check('password', 'Enter your password').exists()
    ],
    async(req, res) => {
    try {
        const errors = validationResult(req)
    
        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Incorrect data during entrance into the system'
            })
        }
    
        const {email, password} = req.body

        const user = await User.findOne({ email })

        if(!user) {
            return res.status(400).json({ message: 'User is not found' })
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if(!isMatch){
            return res.status(400).json({ message: 'Wrong password, try again' })
        }

        const token = jwt.sign(
            { userId: user.id },
            config.get('jwtSecret'),
            { expiresIn: '1h' }
        )

        res.json({ token, userId: user.id })
    
    } catch(e) {
        res.status(500).json({ message: 'Something goes wrong, try again please' })
    }
})

module.exports = router