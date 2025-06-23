const express = require("express");
const validator = require("validator");
const User = require("../models/user");
const { validateSignUpData } = require("../utils/validation");
const { userAuth } = require("../middlewares/auth");

const authRouter = express.Router();


authRouter.post('/signup', async (req, res) => {
  try {
    // Validate the incoming data
    validateSignUpData(req);

    const { password, name, email } = req.body;

   
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User with this email already exists",
      });
    }
   

  
    const user = new User({
      name,
      email,
      password,
    
    });

    const savedUser = await user.save();
    const token = await savedUser.getJWT();

    
    
      res.cookie("token", token, {
  expires: new Date(Date.now() + 24 * 3600000), // 24 hours expiry
  httpOnly: true,
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  secure: process.env.NODE_ENV === "production", 
  path: "/"
  });
    

    res.status(201).json({
      message: "User saved successfully",
      data: savedUser,
    });

  } catch (err) {
    res.status(400).send("Error: " + err.message);
  }
});


authRouter.post("/login", async (req, res) => {
  try {
    const { password, email } = req.body;

    if (!validator.isEmail(email)) {
      throw new Error("Invalid email");
    }

    const user = await User.findOne({ email });
  
    if (!user) throw new Error("Invalid credentials");


    const isPasswordValid = await user.validatePassword(password);
    if (!isPasswordValid) throw new Error("Invalid credentials");

    
    const token = await user.getJWT();

    res.cookie("token", token, {
  expires: new Date(Date.now() + 24 * 3600000), 
  httpOnly: true,
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  secure: process.env.NODE_ENV === "production", 
  path: "/"
});

    res.status(200).json({
      message: "Login successful",
      data: {
        name: user.name,
        email: user.email,
      },
    });

  } catch (err) {
    res.status(400).send("ERROR: " + err.message);
  }
});



authRouter.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.send("Logout successfully");
});


authRouter.get("/profile", userAuth, async (req, res) => {
  try {
    const user = req.user;
    const { name, email } = user;

    res.status(200).json({
      message: "User profile fetched successfully",
      data: { name, email },
    });

  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch profile",
      error: error.message,
    });
  }
});

module.exports = authRouter;
