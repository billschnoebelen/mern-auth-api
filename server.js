const express = require("express");
var path = require("path");
const morgan = require("morgan"); // HTTP request logger middleware
const cors = require("cors"); // Cross-origin resource sharing
const mongoose = require("mongoose");
require("dotenv").config();

const app = express();

// connect to db
mongoose
  .connect(process.env.DATABASE, {
    useNewUrlParser: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
    useCreateIndex: true,
  })
  .then(() => console.log("DB connected"))
  .catch((err) => console.log("DB Connection ERROR: ", err));

// view engine for LinkedIn popup render
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// import routes
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/user");

// app middlewares
app.use(morgan("dev"));
app.use(express.json()); // for parsing application/json
//app.use(express.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded
//app.use(cors()); // allows all origins
if ((process.env.NODE_ENV = "development")) {
  app.use(cors({ origin: "http://localhost:3000" }));
}

//middleware
app.use("/api", authRoutes);
app.use("/api", userRoutes);

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log("API is running on port: %d", PORT, "-", process.env.NODE_ENV);
});
