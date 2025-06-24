const User = require("../models/user");
const express = require("express");
const adminRouter = express.Router();
const jwt = require("jsonwebtoken");
const {adminAuth} = require("../middlewares/adminAuth")

const adminEmails = ["brand-mgmt@marshee.com"];

adminRouter.post("/admin/login", async (req, res)=>{
  const { password, email } = req.body;

  if (!password || !email) {
    return res.status(400).json({
      success: false,
      message: "email and password are required",
    });
  }


  if (!adminEmails.includes(email)) {
    return res.status(403).json({
      success: false,
      message: "Not authorized as admin",
    });
  }

  try {
    let user = await User.findOne({ email });


    if (!user) {
      user = await User.create({
        name: "Admin", 
        email,
        password,
        role: "admin",
      });
    } else {
   
      const isMatch = await user.validatePassword(password);
      if (!isMatch) {
        return res.status(401).json({
          success: false,
          message: "Invalid password",
        });
      }
    }

    if (user.role !== "admin") {
      user.role = "admin";
      await user.save();
    }

      

 
    const token = jwt.sign(
      { id: user._id, email: user.email, role: "admin" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

   
    res.cookie("adminToken", token, {
       httpOnly: true,
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  secure: process.env.NODE_ENV === "production", 
  maxAge: 24*60*60*1000
    });

    return res.status(200).json({
      success: true,
      message: "Admin logged in",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});



adminRouter.get("/admin/accounts",adminAuth, async (req, res) => {
  try {
    const users = await User.find({ role: "user" })
      .select("name email role createdAt");

    res.status(200).json({
      success: true,
      data: users,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});




adminRouter.post("/admin/logout",async(req,res)=>{

    res.clearCookie("adminToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  });
  res.status(200).json({ message: "Admin logged out" });
})

module.exports = adminRouter;
