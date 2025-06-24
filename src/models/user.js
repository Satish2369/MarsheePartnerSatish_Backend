const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required:true,
    minlength: 3,
    maxlength: 45,
  },

  email: {
    type: String,
    unique:true,
    required:true,
    lowercase: true,
    trim: true,
    validate: {
      validator: (val) => !val || validator.isEmail(val),
      message: "Invalid email",
    },
  },

  password: {
    type: String,
    required:true,
    minlength: 6,
  },

  role:{
    type:String,
    enum:["user","admin"],
    default:"user"
  }


}, { timestamps: true });

// 🔐 Hash password before save
userSchema.pre("save", async function (next) {
  if (this.isModified("password") && this.password) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// 🔑 Generate JWT
userSchema.methods.getJWT = function () {
  return jwt.sign({ _id: this._id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
};

// 🔐 Validate password
userSchema.methods.validatePassword = async function (passwordByUser) {
  return await bcrypt.compare(passwordByUser, this.password);
};

const UserModel = mongoose.model("User", userSchema);
module.exports = UserModel;
