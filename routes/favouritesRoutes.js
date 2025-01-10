// routes/favouritesRoutes.js

const express = require("express");
const router = express.Router();
const favouritesController = require("../controllers/favouritesController");
const { authGuard } = require("../middleware/authGuard");

// Route to add item to favorites
router.post("/add", authGuard, favouritesController.favorite);

// Route to get all favorite items
router.get("/all", favouritesController.getAllFavorites);

// Route to get favorite for user
router.get("/get",authGuard, favouritesController.getFavorite);

// Route to delete item from favorites
router.delete(
  "/delete/:id",
  authGuard,
  favouritesController.deleteFavoriteItem
);

module.exports = router;
