//authRoute

const { Router } = require('express')
const router = new Router()
const User = require('../models/User.model')

const mongoose = require("mongoose");
const bcryptjs = require('bcryptjs')
const saltRounds = 10

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

router.get('/signup', isLoggedOut, (req, res) => res.render('auth/signup'))

router.post('/signup', isLoggedOut, (req, res, next) => {
    const { username, password } = req.body;

    if (!username || !password) 
    {
        res.render("auth/signup", {
        errorMessage: "All fields are mandatory. Please provide your username and password."
        });
        return;
    }

    bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
        return User.create({
            // username: username
            username,
            passwordHash: hashedPassword
        });
    })
    .then((userFromDB) => {
        // console.log("Newly created user is: ", userFromDB);
        res.redirect("/userProfile");
    })
    .catch((error) => {
        if (error instanceof mongoose.Error.ValidationError) {
            res.status(500).render("auth/signup", { errorMessage: error.message });
        } else if (error.code === 11000) {
            res.status(500).render("auth/signup", {
            errorMessage: "Username needs to be unique. This username is already used."
            });
        } else {
            next(error);
        }
    });

})

router.get("/login", isLoggedOut, (req, res) => res.render("auth/login"));

router.post("/login", isLoggedOut, (req, res, next) => {
    
    console.log('SESSION =====> ', req.session);

    const { username, password } = req.body;

    if (username === "" || password === "") {
    res.render("auth/login", {errorMessage: "Please enter both, username and password to login."});
    return;
    }

    User.findOne({ username }) 
    .then((user) => {
        if (!user) 
        {
            res.render('auth/login', { errorMessage: 'Username is not registered. Try with other username.' });
            return;
        } else if (bcryptjs.compareSync(password, user.passwordHash)) 
        {
            req.session.currentUser = user;
            res.redirect('/userProfile');
            console.log('aqui')
        } else 
        {
            res.render('auth/login', { errorMessage: 'Incorrect password.' });
        }
    })
    .catch(error => next(error));
    
});

router.get("/userProfile", isLoggedIn, (req, res) => {
    res.render("users/user-profile", { userInSession: req.session.currentUser });
});


router.post("/logout", isLoggedIn, (req, res) => {
    req.session.destroy()
    res.redirect("/")
})

router.get("/main", isLoggedIn, (req, res) => res.render('auth/main'))
router.get("/private", isLoggedIn, (req, res) => res.render('auth/private'))

module.exports = router;