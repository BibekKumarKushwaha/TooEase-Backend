// const mongoose = require('mongoose');

// const OrderSchema = new mongoose.Schema({
//   user: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: 'users',
//     required: true,
//   },
//   product: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: 'products',
//     required: true,
//   },
//   quantity: {
//     type: Number,
//     required: true,
//   },
//   totalPrice: {
//     type: Number,
//     required: true,
//   },
//   deliveryInfo: {
//     fullName: {
//       type: String,
//       required: true,
//     },
//     phoneNumber: {
//       type: String,
//       required: true,
//     },
//     city: {
//       type: String,
//       required: true,
//     },
//     area: {
//       type: String,
//       required: true,
//     },
//     address: {
//       type: String,
//       required: true,
//     },
//   },
//   paymentMethod: {
//     type: String,
//     required: true,
//   },
//   status: {
//     type: String,
//     default: 'Pending',
//   },
//   createdAt: {
//     type: Date,
//     default: Date.now,
//   },
// });

// module.exports = mongoose.model('Order', OrderSchema);
const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "users" },
  carts: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Cart",
    },
  ],
  total: { type: Number },
  address: { type: String },
  paymentType: { type: String },
  status: { type: String, default: "pending" },
  createdAt: { type: Date, default: Date.now },
});

const Order = mongoose.model("orders", orderSchema);

module.exports = Order;
