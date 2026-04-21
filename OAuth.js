import dotenv from 'dotenv';
dotenv.config();
import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import findOrCreate from "mongoose-findorcreate";

const app = express();
const port = 3000;

app.set('view engine', 'ejs');

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
    password: String,
    googleId: String,
    secret: [String]
});


// Ensure you are passing the function, not the whole module object
userSchema.plugin(passportLocalMongoose.default || passportLocalMongoose);
userSchema.plugin(findOrCreate.default || findOrCreate);

const User = mongoose.model("User", userSchema);

// 6. Passport Strategy Configuration
passport.use(User.createStrategy()); // Added parentheses ()


passport.serializeUser((user, done) => {
    // Store only the user ID in the session
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id)
        .then(user => done(null, user))
        .catch(err => done(err, null));
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",

},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id })
            .then(result => cb(null, result.doc)) // result.doc is the user
            .catch(err => cb(err, null));
    }

));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secret"
},
    function (accessToken, refreshToken, profile, cb) {
        // 1. Find the user in the DB by their unique GitHub ID
        User.findOrCreate({ githubId: profile.id }, function (err, user) {

            // 2. The 'cb' (callback) function finishes the process
            // The first argument is for errors, the second is the user object
            return cb(err, user);
        });
    }

));
// --- ROUTES ---


app.get("/", (req, res) => {
    res.render("home.ejs");
});


app.get("/auth/google", passport.authenticate('google', { scope: ["profile"] }));



app.get("/auth/google/secret",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect to the page that shows ALL secrets
        res.redirect("/secrets");
    }
);

app.get('/auth/github', passport.authenticate('github', { scope: ["user:email"] }));

app.get('/auth/github/secret',
    passport.authenticate('github', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect secret.
        res.redirect("/secrets");
    });


app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});



// app.get("/secrets", (req, res) => {
//      User.find({"secret": {$ne: null}}, function(err, foundUsers){
//     if (err){
//       console.log(err);
//     } else {
//       if (foundUsers) {
//         res.render("secrets", {usersWithSecrets: foundUsers});
//       }
//     }
//   });
// });

app.get("/secrets", async (req, res) => {
    try {
        const foundUsers = await User.find({ "secret": { $ne: null } });
        res.render("secrets", { usersWithSecrets: foundUsers });
    } catch (err) {
        console.log(err);
        res.redirect("/");
    }
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

/*
app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    console.log(req.user.id);
    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("secrets");
                })
            }
        }
    });

});
*/

app.post("/submit", async (req, res) => {
    const submittedSecret = req.body.secret;
    try {
        const foundUser = await User.findById(req.user.id);
        if (foundUser) {


            // foundUser.secret = submittedSecret;
            foundUser.secret.push(submittedSecret);
            await foundUser.save();
            res.redirect("/secrets");
        }
    } catch (err) {
        console.log(err);
    }
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