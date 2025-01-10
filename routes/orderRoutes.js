// const express = require('express');
// const { createOrder, getOrdersByUser, getAllOrders } = require('../controllers/orderController');


// const router = express.Router();

// router.post('/orders', createOrder);
// router.get('/orders/user', getOrdersByUser);
// router.get('/orders', getAllOrders);

// module.exports = router;
const router = require("express").Router();

const orderController = require("../controllers/orderController");
const { authGuard } = require("../middleware/authGuard");

router.post("/create", authGuard, orderController.addOrder);
router.get("/get", authGuard, orderController.getAllOrders);
router.put("/update/:id", authGuard, orderController.updateOrderStatus);
router.get("/user", authGuard, orderController.getUserOrders);
module.exports = router;
