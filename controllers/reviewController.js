// const Review = require('../models/reviewModal');
// const Product = require('../models/productModel');

// // Add a review
// const addReview = async (req, res) => {
//     try {
//         const { productId, rating, comment } = req.body;
//         const userId = req.user._id; // Make sure `req.user` is correctly populated

//         const review = new Review({
//             user: userId,
//             product: productId,
//             rating,
//             comment
//         });

//         await review.save();
//         res.status(201).json({ message: 'Review added successfully', review });
//     } catch (error) {
//         console.error('Failed to add review:', error);
//         res.status(500).json({ error: 'Failed to add review' });
//     }
// };

// const getReviews = async (req, res) => {
//     try {
//         const { productId } = req.params;
//         const reviews = await Review.find({ product: productId })
//             .populate('user', 'firstName lastName')
//             .sort({ createdAt: -1 });
//         res.status(200).json(reviews);
//     } catch (error) {
//         console.error('Failed to fetch reviews:', error);
//         res.status(500).json({ error: 'Failed to fetch reviews' });
//     }
// };

// module.exports = {
//     addReview,
//     getReviews
// };
const Reviews = require("../models/reviewModal");
 
exports.addReview = async (req, res) => {
    const { productId, rating, comment } = req.body;
    const userId = req.user._id; // Ensure req.user is populated from authentication middleware
 
    try {
        const review = new Reviews({ productId, userId, rating, comment });
        await review.save();
        res.status(201).json({ message: "Review added successfully", review });
    } catch (error) {
        res.status(500).json({ message: "Failed to add review", error });
    }
};
 
exports.getReviewsByProduct = async (req, res) => {
    console.log(req.params.productId);
    const productId = req.params.productId;
 
    try {
        const reviews = await Reviews.find({ productId: productId })
           
 
        res.status(200).json({ reviews });
    } catch (error) {
        res.status(500).json({ message: "Failed to fetch reviews", error });
    }
};
