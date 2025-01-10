// const express = require('express');
// const router = express.Router();
// const { addReview, getReviews } = require('../controllers/reviewController');

// router.post('/review', addReview);  // POST /api/rating/review
// router.get('/get_review/:productId', getReviews);  // GET /api/rating/get_review/:productId

// module.exports = router;
const express = require("express");
const router = express.Router();
const { addReview, getReviewsByProduct } = require("../controllers/reviewController");
const { authGuard } = require("../middleware/authGuard"); // Adjusted path for middleware import
 
// POST route to add a review
router.post("/add", authGuard, addReview); // Added authGuard to ensure user is authenticated
 
// GET route to fetch reviews by product ID
router.get("/product/:productId", getReviewsByProduct);
 
module.exports = router;
