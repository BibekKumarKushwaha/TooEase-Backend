// models/favouritesModel.js

const mongoose = require("mongoose");

const favouriteSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "products" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // If user-specific favorites are needed
  createdAt: { type: Date, default: Date.now },
});

const Favourite = mongoose.model("Favourite", favouriteSchema);

module.exports = Favourite;
