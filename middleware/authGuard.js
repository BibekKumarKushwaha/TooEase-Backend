const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

const authGuard = async (req, res, next) => {
    console.log("Incoming Headers:", req.headers);

    // Check for Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({
            success: false,
            message: "Authorization header missing. Please login first.",
        });
    }

    // Extract token from Authorization header
    const token = authHeader.split(" ")[1];
    if (!token || token === "") {
        return res.status(401).json({
            success: false,
            message: "Token missing in the Authorization header.",
        });
    }

    try {
        // Verify the token
        const decodeUserData = jwt.verify(token, process.env.JWT_SECRET);

        // Find the user in the database and attach it to the request
        req.user = await User.findById(decodeUserData.id).select("-password");
        if (!req.user) {
            return res.status(404).json({
                success: false,
                message: "User associated with the token not found.",
            });
        }

        next(); // Proceed to the next middleware/controller
    } catch (error) {
        // Handle specific JWT errors
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({
                success: false,
                message: "Token has expired. Please login again.",
            });
        }
        if (error.name === "JsonWebTokenError") {
            return res.status(401).json({
                success: false,
                message: "Invalid token. Authentication failed.",
            });
        }

        // Log other unexpected errors
        console.error("Authentication Error:", error.message);
        return res.status(500).json({
            success: false,
            message: "Internal server error during authentication.",
        });
    }
};

module.exports = {
    authGuard,
};
