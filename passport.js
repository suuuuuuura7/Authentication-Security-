import dotenv from 'dotenv';
dotenv.config();
import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';

const app = express();
const port = 3000;

// 1. Basic Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// 2. Session Setup
app.use(session({
    secret: process.env.SECRET || "ourlittlesecret.", // Use env variable for better security
    resave: false,
    saveUninitialized: false
}));

// 3. Passport Initialization
app.use(passport.initialize());
app.use(passport.session()); // Corrected from session.passport()

// 4. Database Connection
mongoose.connect("mongodb://127.0.0.1:27017/userDB")
    .then(() => console.log("Successfully connected to MongoDB!"))
    .catch((err) => console.log("Error connecting to MongoDB: ", err));

// 5. Schema and Model Definition (Must come before Passport config)
const userSchema = new mongoose.Schema({
    username: String,
    password: String
});

// Plugin handles hashing and salting automatically
// Keep your current import, but change the plugin line to:
userSchema.plugin(passportLocalMongoose.default || passportLocalMongoose);

const User = mongoose.model("User", userSchema);

// 6. Passport Strategy Configuration
passport.use(User.createStrategy()); // Added parentheses ()
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// --- ROUTES ---

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/logout", (req, res, next) => {
    // Pass a callback function to handle the logout process
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        // Only redirect once the session is officially destroyed
        res.redirect("/");
    });
});


app.get("/secrets", (req, res) => {
    // isAuthenticated() returns true if a session exists
    if (req.isAuthenticated()) {
        res.render("secrets.ejs");
    } else {
        res.redirect("/login");
    }
});

app.post("/register", (req, res) => {
    // passport-local-mongoose handles the hashing, so we don't pass password directly in the object
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});