const userModel = require('../models/user.model')
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

const blacklistModel = require("../models/blacklist.model")


// User registration controller
async function registerUser(req, res) {

    // Request body se user ka data lena
    const { username, email, password } = req.body

    // Check karna ki same email ya username ka user pehle se exist karta hai ya nahi
    const isAlreadyRegistered = await userModel.findOne({
        $or: [
            { email },      // email match check
            { username }    // username match check
        ]
    })

    // Agar user already exist karta hai to error response bhejna
    if (isAlreadyRegistered) {
        return res.status(400).json({
            message: "User with the same email or username already exists"
        })
    }

    // Password ko secure banane ke liye bcrypt se hash karna
    const hash = await bcrypt.hash(password, 10)

    // Database me naya user create karna
    const user = await userModel.create({
        username,         // user ka username
        email,            // user ka email
        password: hash    // hashed password store karna
    })

    // JWT token generate karna taaki user authenticated rahe
    const token = jwt.sign(
        {
            id: user._id,          // user id payload me
            username: user.username
        },
        process.env.JWT_SECRET,    // secret key jo env file me stored hai
        {
            expiresIn: "3d"        // token 3 din tak valid rahega
        }
    )

    // Token ko cookie me store karna
    res.cookie("token", token)

    // Success response bhejna
    return res.status(201).json({
        message: "User registered successfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        }
    })
}


// User login controller
async function loginUser(req, res) {

    // Request body se login credentials lena
    const { email, password, username } = req.body

    // Database me user ko search karna (email ya username se)
    const user = await userModel.findOne({
        $or: [
            { email },      // email se login
            { username }    // username se login
        ]
    }).select("+password")

    // Agar user database me nahi mila to invalid credentials return karna
    if (!user) {
        return res.status(400).json({
            message: "Invalid Credentials"
        })
    }

    // User ke entered password ko database ke hashed password se compare karna
    const isPasswordValid = await bcrypt.compare(password, user.password);

    // Agar password match nahi karta to error return karna
    if (!isPasswordValid) {
        return res.status(400).json({
            message: "Invalid Credentials"
        })
    }

    // Successful login ke baad JWT token generate karna
    const token = jwt.sign(
        {
            id: user._id,           // user id payload me
            username: user.username // username payload me
        },
        process.env.JWT_SECRET,     // secret key jo env file me stored hai
        {
            expiresIn: "3d"         // token 3 din tak valid rahega
        }
    )

    // Token ko cookie me store karna taaki user authenticated rahe
    res.cookie("token", token)

    // Success response bhejna aur basic user info return karna
    return res.status(200).json({
        message: "User logged in successfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        }
    })
}


async function getMe(req, res) {
    const user = await userModel.findById(req.user.id)

    res.status(200).json({
        message: "User fetched successfully",
        user
    })
}


async function logoutUser(req, res) {
    
    const token = req.cookies.token

    res.clearCookie("token")

    await blacklistModel.create({
        token
    })

    res.status(200).json({
        message: "logout Successfully"
    })
}


module.exports = { registerUser, loginUser, getMe, logoutUser }