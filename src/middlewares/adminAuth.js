const jwt = require("jsonwebtoken");
const User = require("../models/user");

const adminAuth = async (req, res, next) => {
  try {
    const { adminToken } = req.cookies;

    if (!adminToken) {
      return res.status(401).send("Please login as admin");
    }

    const decoded = jwt.verify(adminToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id); 

    if (!user || user.role !== "admin") {
      return res.status(403).send("Access denied: Admins only");
    }

    req.user = user;
    next();
  } catch (e) {
    res.status(400).send("ERROR " + e.message);
  }
};

module.exports = { adminAuth };
