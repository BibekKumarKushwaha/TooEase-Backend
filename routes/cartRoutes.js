// const express = require('express');
// const router = express.Router();
// const { addToCart, getCart } = require('../controllers/cartControllers');
// const { authGuard } = require('../middleware/authGuard');

// router.post('/add_to_cart', addToCart);
// router.get('/get_cart', getCart);

// module.exports = router;
// routes/cartRoutes.js

const express = require("express");
const router = express.Router();
const cartController = require("../controllers/cartControllers");
const { authGuard } = require("../middleware/authGuard");


// Route to add item to cart
router.post("/add",authGuard, cartController.addToCart);

// Route to get all cart items
router.get("/all",authGuard, cartController.getAllCartItems);

// Route to delete item from cart
router.delete("/delete/:id", cartController.deleteCartItem);
 
// Route to update item in cart
router.put("/update/:id", cartController.updateCartItem);

// Route to update status in cart
router.put("/status", authGuard, cartController.updateUserCartStatus);

module.exports = router;
