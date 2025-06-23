
const jwt = require("jsonwebtoken");
const User = require("../models/user");

const userAuth = async (req,res,next)=>{

   try {
     const {token} = req.cookies;


     if(!token){
       return res.status(401).send("please login first ");
     }

    const decodedObj = await jwt.verify(token,process.env.JWT_SECRET);
   
    const {_id}= decodedObj;

    const user = await User.findById(_id);

    if(!user){
        throw new Error("User not found");
    }
    req.user = user; //now the next request handler will have access to this user
    next();

   }
   catch(e){
    res.status(400).send("ERROR "+ e.message)
   }
}

module.exports = {userAuth};












