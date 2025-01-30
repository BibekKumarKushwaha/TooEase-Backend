

const express = require("express");
const https = require("https");
const connectDatabase = require("./database/database");
const dotenv = require("dotenv");
const cors = require("cors");
const acceptFormData = require("express-fileupload");
const fs = require("fs");
const path = require("path");



// Import your route files
const favouritesRoutes = require("./routes/favouritesRoutes");
const userRoutes = require("./routes/userRoutes");
const productRoutes = require("./routes/productRoutes");
const cartRoutes = require("./routes/cartRoutes");
const reviewRoutes = require("./routes/reviewRoutes");
const orderRoutes = require("./routes/orderRoutes");
const contactRoutes = require("./routes/contactRoutes");
const paymentRoutes = require("./routes/PaymentRoutes");

// Create an express application
const app = express();
const Routes = require("./routes/userRoutes");
// Configure Cors Policy
const corsOptions = {
  origin: true,
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

// Middleware for parsing JSON and form data
app.use(express.json());
app.use(acceptFormData());

// Make a static public folder
app.use(express.static("./public"));

// Load environment variables
dotenv.config();



// Define the port
const PORT = process.env.PORT || 5000;

// Connect to Database
connectDatabase();


// Define Routes
app.get("/test", (req, res) => {
  res.send("Test API is working...");
});

app.use("", Routes);

app.use("/api/favourite", favouritesRoutes);
app.use("/api/user", userRoutes);
app.use("/api/product", productRoutes);
app.use("/api/cart", cartRoutes);
app.use("/api/rating", reviewRoutes);
app.use("/api/order", orderRoutes);
app.use("/api/contact", contactRoutes);
app.use("/api/payment", paymentRoutes);

// HTTPS server configuration
const options = {
  key: fs.readFileSync(path.resolve(__dirname, "server.key")),
  cert: fs.readFileSync(path.resolve(__dirname, "server.crt")),
  
};


// Start HTTPS server
https.createServer(options, app).listen(PORT, () => {
  console.log(`Secure server is running on port ${PORT}`);
});

// Export the app
module.exports = app;
