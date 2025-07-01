const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    minlength: 3,
    maxlength: 45,
  },

  email: {
    type: String,
    unique: true,
    sparse: true, // Allow null/undefined for users who sign up with phone only
    lowercase: true,
    trim: true,
    validate: {
      validator: (val) => !val || validator.isEmail(val),
      message: "Invalid email",
    },
  },

  phoneNumber: {
    type: String,
    unique: true,
    sparse: true, // Allow null/undefined for users who sign up with email only
    validate: {
      validator: (val) => !val || /^\+[1-9]\d{1,14}$/.test(val), // E.164 format validation
      message: "Invalid phone number format. Use E.164 format (e.g., +1234567890)"
    }
  },

  firebaseUid: {
    type: String,
    sparse: true,
    unique: true, 
  },

  password: {
    type: String,
    required: function() {
      // Password only required if not using Firebase auth (no firebaseUid and no phoneNumber)
      return !this.firebaseUid && !this.phoneNumber;
    },
    minlength: 6,
  },

  role: {
    type: String,
    enum: ["partner", "owner", "manager", "admin"],
    default: "partner"
  },
  
  status: {
    type: String,
    enum: ["Active", "Inactive", "Suspended"],
    default: "Active"
  },
  isadminCreated:{
     type:String,
     enum:["true", "false"],
     default:"false"
  }

}, { timestamps: true });

userSchema.pre("save", async function (next) {
  if (this.isModified("password") && this.password) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});


userSchema.methods.getJWT = function () {
  return jwt.sign({ _id: this._id }, process.env.JWT_SECRET, {
    expiresIn: "5d",
  });
};


userSchema.methods.validatePassword = async function (passwordByUser) {

  if (!this.password) return false;
  
  return await bcrypt.compare(passwordByUser, this.password);
};

const UserModel = mongoose.model("User", userSchema);
module.exports = UserModel;
