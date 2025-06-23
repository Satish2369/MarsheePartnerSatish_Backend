
const validator = require("validator");


const validateSignUpData = (req)=>{


const {name,password,email}=req.body;


  if( !name ){
     throw new Error("Name is not valid!");
  }
  else if(!validator.isEmail(email)){
    throw new Error("Email is not valid!");
  }
  else if(!validator.isStrongPassword(password)){
    throw new Error("password is not strong!");
  }


}


module.exports = {validateSignUpData}