//authRoute

const { Router } = require('express')
const router = new Router()
const User = require('../models/User.model')

const bcrypt = require('bcryptjs')
const saltRounds = 10

router.get('/signup', (req, res) => res.render('auth/signup'))

router.get('/userProfile', (req, res) => res.render('auth/user-profile'))

// POST


module.exports = router