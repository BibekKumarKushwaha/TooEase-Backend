// const mongoose = require('mongoose');

// const reviewSchema = new mongoose.Schema({
//     user: {
//         type: mongoose.Schema.Types.ObjectId,
//         ref: 'users',
//         required: true
//     },
//     product: {
//         type: mongoose.Schema.Types.ObjectId,
//         ref: 'products',
//         required: true
//     },
//     rating: {
//         type: Number,
//         required: true,
//         min: 1,
//         max: 5
//     },
//     comment: {
//         type: String,
//         required: true,
//         maxLength: 500
//     },
//     createdAt: {
//         type: Date,
//         default: Date.now
//     }
// });

// const Review = mongoose.model('reviews', reviewSchema);

// module.exports = Review;
const mongoose = require("mongoose");
 
const reviewSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "products",
    required: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "users",
    required: true,
  },
  rating: {
    type: Number,
    required: true,
    min: 1,
    max: 5,
  },
  comment: {
    type: String,
    required: true,
  },
}, { timestamps: true });
 
const Reviews = mongoose.model("reviews", reviewSchema);
 
module.exports = Reviews