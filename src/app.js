console.log(" Backend project started");

const dotenv = require("dotenv");
const express = require("express");
const connectDB = require("./config/database");
const cookieParser = require("cookie-parser");
const cors = require("cors");


dotenv.config();

const app = express();

console.log(process.env.NODE_ENV);
const corsOptions = {
  origin:
    process.env.NODE_ENV === "development"
      ? "http://localhost:3000"
      : 
         "https://pen-pot-frontend.vercel.app"
        ,
  credentials: true,
};

console.log(process.env.NODE_ENV);

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());


const authRouter = require("./routes/auth");
app.use("/", authRouter);



connectDB()
  .then(() => {
    console.log(" MongoDB connection established");
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(` Server listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error(" Database connection failed:", err.message);
  });
