// models/cartModel.js

const mongoose = require("mongoose");

const cartSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "products" },
  quantity: { type: Number, default: 1 },
  total: { type: Number },
  status: { type: String, default: "active" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "users" }, // If user-specific carts are needed
});

const Cart = mongoose.model("Cart", cartSchema);

module.exports = Cart;
