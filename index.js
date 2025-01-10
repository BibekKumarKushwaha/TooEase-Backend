const express = require("express");
const connectDatabase = require("./database/database");
const dotenv = require("dotenv");
const cors = require("cors");
const acceptFormData = require('express-fileupload');
//const cartRoutes = require("./routes/cartRoutes");
const favouritesRoutes = require("./routes/favouritesRoutes");
// Creating an express application
const app = express();

// Configure Cors Policy
const corsOptions = {
    origin: true,
    credentials: true,
    optionSuccessStatus: 200
};
app.use(cors(corsOptions));

// Express JSON Config
app.use(express.json());

// Config form data
app.use(acceptFormData());

// Make a static public folder
app.use(express.static("./public"));

// dotenv configuration
dotenv.config();

// Defining the port
const PORT = process.env.PORT || 5000;

// Connecting to Database
connectDatabase();

// Making a test endpoint
app.get("/test", (req, res) => {
    res.send("Test api is working..");
});
//cart
// app.use("/api/cart", cartRoutes);
// Use favouritesRoutes for /api/favourites endpoints
app.use("/api/favourite", favouritesRoutes);
// Configuring Routes
app.use('/api/user', require('./routes/userRoutes'));
app.use('/api/product', require('./routes/productRoutes'));
app.use("/api/cart", require("./routes/cartRoutes"));

app.use('/api/rating',require("./routes/reviewRoutes"))

app.use("/api/order", require("./routes/orderRoutes"));
app.use('/api/contact', require('./routes/contactRoutes'))
app.use('/api/rating',require("./routes/reviewRoutes"));

// Starting the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}!`);
});

// export default app
module.exports = app;
