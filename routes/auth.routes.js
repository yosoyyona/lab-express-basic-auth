//authRoute

const { Router } = require('express')
const router = new Router()
const User = require('../models/User.model')

const mongoose = require("mongoose");
const bcryptjs = require('bcryptjs')
const saltRounds = 10

router.get('/signup', (req, res) => res.render('auth/signup'))

router.get('/userProfile', (req, res) => res.render('user/user-profile'))

// POST
router.post('/signup', (req, res, next) => {
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

router.get("/login", (req, res) => res.render("auth/login"));

router.post("/login", (req, res, next) => {
    console.log("SESSION =====> ", req.session);
    const { username, password } = req.body;

    if (username === "" || password === "") {
    res.render("auth/login", {errorMessage: "Please enter both, email and password to login."});
    return;
    }

    User.findOne({ username }) // <== check if there's user with the provided email
    .then((user) => {
        // <== "user" here is just a placeholder and represents the response from the DB
        if (!user) {
        // <== if there's no user with provided email, notify the user who is trying to login
        res.render("auth/login", {errorMessage: "Username is not registered. Try with other username."});
        return;
        }
        // if there's a user, compare provided password
        // with the hashed password saved in the database
        else if (bcryptjs.compareSync(password, user.passwordHash)) {
    
        req.session.currentUser = user;
        res.redirect("users/userProfile");
        } else {
        // if the two passwords DON'T match, render the login form again
        // and send the error message to the user
        res.render("auth/login", {errorMessage: "Incorrect password."});
        }
    })
    .catch((error) => next(error));
});

router.get("/userProfile", (req, res) => {
    res.render("users/user-profile", {userInSession: req.session.currentUser});
});

module.exports = router