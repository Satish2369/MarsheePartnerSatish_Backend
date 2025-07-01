const User = require("../models/user");
const express = require("express");
const adminRouter = express.Router();
const jwt = require("jsonwebtoken");
const { adminAuth } = require("../middlewares/adminAuth");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const sendInviteEmail = require("../utils/sendInviteEmail");

const adminEmails = ["brand-mgmt@marshee.com"];

adminRouter.post("/admin/login", async (req, res) => {
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
      maxAge: 24 * 60 * 60 * 1000,
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

adminRouter.post("/admin/account", adminAuth, async (req, res) => {
  try {
    const { query } = req.body;

    const users = await User.find({
      $and: [
        {
          $or: [
            { email: { $regex: query, $options: "i" } },
            { name: { $regex: query, $options: "i" } },
          ],
        },
        { role: { $ne: "admin" } },
      ],
    }).select("name email role createdAt");

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

adminRouter.post("/admin/logout", async (req, res) => {
  res.clearCookie("adminToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  });
  res.status(200).json({ message: "Admin logged out" });
});

adminRouter.get("/admin/verify", async (req, res) => {
  try {
    const { adminToken } = req.cookies;

    if (!adminToken) {
      return res.status(401).json({
        success: false,
        message: "Admin authentication required",
      });
    }

    const decoded = jwt.verify(adminToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access denied: Admins only",
      });
    }

    res.status(200).json({
      success: true,
      message: "Admin verified",
    });
  } catch (err) {
    console.error("Admin verification error:", err);
    res.status(401).json({
      success: false,
      message: "Admin authentication failed",
    });
  }
});

adminRouter.post("/admin/invite-partner", adminAuth, async (req, res) => {
  const { name, email, role } = req.body;

  try {
    if (!name || !email || !role) {
      res
        .status(400)
        .json({
          success: "failure",
          message: "email, role and name are required",
        });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      res
        .status(500)
        .json({ success: "failure", message: "email already registered" });
    }

    const token = jwt.sign({ email, role, name }, process.env.JWT_SECRET, {
      expiresIn: "5d",
    });

    const user = new User({
      name,
      email,
      password: token,
      role,
      isadminCreated: "true",
      status: "Inactive",
    });

    await user.save();

    const emailResponse = await sendInviteEmail({
      toEmail: email,
      name,
      role,
      token,
    });

    if (!emailResponse.success) {
      return res.status(500).json({
        success: false,
        message: "User created but email failed to send",
        error: emailResponse.error,
      });
    }

    return res.status(200).json({
      success: true,
      message: "Invitation sent successfully",
    });
  } catch (err) {
    console.error("Error inviting partner:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

adminRouter.get("/admin/partner/:id", adminAuth, async (req, res) => {
  try {
    const partnerId = req.params.id;

    if (!partnerId || partnerId === "undefined") {
      return res.status(400).json({
        success: false,
        message: "Invalid partner ID",
      });
    }

    if (!mongoose.Types.ObjectId.isValid(partnerId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid partner ID format",
      });
    }

    const partner = await User.findById(partnerId);

    if (!partner) {
      return res.status(404).json({
        success: false,
        message: "Partner not found",
      });
    }

    res.status(200).json({
      success: true,
      data: partner,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      message: "Server error: " + err.message,
    });
  }
});

adminRouter.patch("/admin/partner/:id", adminAuth, async (req, res) => {
  try {
    const partnerId = req.params.id;

    // Validate the ID
    if (!partnerId || partnerId === "undefined") {
      return res.status(400).json({
        success: false,
        message: "Invalid partner ID",
      });
    }

    // Check if ID is a valid MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(partnerId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid partner ID format",
      });
    }

    // Get update fields from request body
    const updateFields = req.body;
    
    // Find and update the partner
    const updatedPartner = await User.findByIdAndUpdate(
      partnerId,
      { $set: updateFields },
      { new: true, runValidators: true }
    );

    if (!updatedPartner) {
      return res.status(404).json({
        success: false,
        message: "Partner not found",
      });
    }

    res.status(200).json({
      success: true,
      data: updatedPartner,
      message: "Partner updated successfully",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      message: "Server error: " + err.message,
    });
  }
});

module.exports = adminRouter;
