// controllers/favouritesController.js

const Favourite = require("../models/favouritesModel");

// Add item to favorites
exports.favorite = async (req, res) => {
  try {
    console.log(req.body);
    const userId = req.user.id;

    const { productId } = req.body;

    if (!productId) {
      return res
        .status(400)
        .json({ success: false, message: "Product ID is required!" });
    }

    const existingFavorite = await Favourite.findOne({
      productId: productId,
      userId: userId,
    });

    if (existingFavorite) {
      return res.status(400).json({
        success: false,
        message: "Product already in favorites",
      });
    }

    const newFavorite = new Favourite({
      productId: productId,
      userId: userId,
    });

    await newFavorite.save();

    res.status(201).json({ success: true, message: "Favorite toggled" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error.message });
  }
};

// Get all favorite items
exports.getAllFavorites = async (req, res) => {
  try {
    const favoriteItems = await Favourite.find();
    res.json(favoriteItems);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get Favoirte for user
exports.getFavorite = async (req, res) => {
  try {
    const userId = req.user.id;
    const favoriteItems = await Favourite.find({ userId: userId }).populate(
      "productId"
    );
    res.status(200).json({
      success: true,
      favorites: favoriteItems,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Delete item from favorites
exports.deleteFavoriteItem = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const favoriteItem = await Favourite.findOne({
      productId: id,
      userId: userId,
    });

    if (!favoriteItem) {
      return res.status(404).json({ message: "Item not found" });
    }

    const favouriteId = favoriteItem._id;

    await Favourite.findByIdAndDelete(favouriteId);

    res.status(201).json({ message: "Item deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
