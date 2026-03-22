import dotenv from 'dotenv';
dotenv.config();
import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import encrypt from "mongoose-encryption";
import md5 from "md5";
//import bcrypt from "bcryptjs";

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

mongoose.connect("mongodb://127.0.0.1:27017/userDB")
    .then(() => {
        console.log("Successfully connected to MongoDB!");
    })
    .catch((err) => {
        console.log("Error connecting to MongoDB: ", err);
    });

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const secret = process.env.SECRET;
userSchema.plugin(encrypt, {
    secret: secret,
    encryptedFields: ['password'],
    excludeFromEncryption: ['email'] // Add this line!
});

const User = mongoose.model("User", userSchema);

app.get("/", async (req, res) => {
    res.render("home.ejs");
});

app.get("/login", async (req, res) => {
    res.render("login.ejs");
});

app.get("/register", async (req, res) => {
    res.render("register.ejs");
});

app.post("/register", async (req, res) => {
    try {
        const newUser = new User({
            email: req.body.username,
            password: req.body.password
        });

        // Use 'await' instead of a callback function
        await newUser.save();

        // If the save is successful, the code continues here:
        res.render("secrets.ejs");

    } catch (err) {
        // If there is an error (like a database crash), it jumps here:
        console.log("Error during registration:", err);
        res.redirect("/register"); // Redirect back so the user can try again
    }
});

app.post("/login", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    try {
        const foundUser = await User.findOne({ email: username });

        if (foundUser) {
            if (foundUser.password === password) {
                res.render("secrets.ejs");
                console.log("succussfully loged in 🎉");
            } else {
                console.log("wrong password!!");
                res.redirect("/login");
            }
        }

    } catch (err) {
        console.log("error duging login: ", err);
        res.redirect("/login");
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
