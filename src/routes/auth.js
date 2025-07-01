const express = require("express");
const validator = require("validator");
const User = require("../models/user");
const { validateSignUpData } = require("../utils/validation");
const { userAuth } = require("../middlewares/auth");
const jwt = require("jsonwebtoken");

const authRouter = express.Router();


authRouter.post('/signup/email', async (req, res) => {
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
  expires: new Date(Date.now() + 24 * 3600000), 
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

    // Check if user is an admin - don't allow admins to login through regular user login
    if (user.role === "admin") {
      return res.status(403).json({
        success: false,
        message: "Please use admin login page",
      });
    }

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

authRouter.post("/setup-partner", async (req, res) => {
  try {
    const { token, password } = req.body;
    
    if (!token || !password) {
      return res.status(400).json({
        success: false,
        message: "Token and password are required"
      });
    }
    
    // Verify the token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: "Invitation link has expired. Please contact the administrator for a new invitation."
        });
      }
      
      return res.status(401).json({
        success: false,
        message: "Invalid token. Please contact the administrator."
      });
    }
    
    // Extract user information from token
    const { email, name, role } = decoded;
    
    // Find the user with the email from the token
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found. Please contact the administrator."
      });
    }
    
    // Update user password and status
    user.password = password;
    user.status = "Active";
    
    await user.save();
    
    // Generate JWT for the user
    const userToken = await user.getJWT();
    
    // Set cookie
    res.cookie("token", userToken, {
      expires: new Date(Date.now() + 24 * 3600000), 
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
      secure: process.env.NODE_ENV === "production", 
      path: "/"
    });
    
    return res.status(200).json({
      success: true,
      message: "Account setup successful",
      data: {
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
    
  } catch (err) {
    console.error("Setup partner error:", err);
    return res.status(500).json({
      success: false,
      message: "Server error: " + err.message
    });
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

authRouter.post('/signup/phone', async (req, res) => {
  try {
    const { name, phoneNumber, firebaseUid } = req.body;

    if (!name || !phoneNumber || !firebaseUid) {
      return res.status(400).json({
        success: false,
        message: "Name, phone number, and Firebase UID are required",
      });
    }

    // Check if user already exists with this phone number
    let existingUser = await User.findOne({ phoneNumber });
    
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "User with this phone number already exists"
      });
    }
    else {
      // Create new user
    const user = new User({
        name,
        phoneNumber,
        firebaseUid,
       
      });
      
      await user.save();
    }

    
    const token = await user.getJWT();


    res.cookie("token", token, {
      expires: new Date(Date.now() + 24 * 3600000), 
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
      secure: process.env.NODE_ENV === "production", 
      path: "/"
    });

    res.status(201).json({
      message: "User registered successfully",
      data: {
        name: user.name,
        phoneNumber: user.phoneNumber
      },
    });

  } catch (err) {
    console.error("Phone signup error:", err);
    res.status(400).json({
      success: false,
      message: "Error: " + err.message
    });
  }
});

module.exports = authRouter;
