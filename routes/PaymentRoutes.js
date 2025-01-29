// const router = require('express').Router();

// const paymentController = require('../controllers/paymentController');
// const { authGuard } = require('../middleware/authGuard');

// router.post('/initialize_khalti', paymentController.initializePayment);
// router.get('/complete-khalti-payment', paymentController.completeKhaltiPayment);

// module.exports = router;

const express = require("express");
const router = express.Router();
const {
  initializeKhalti,
  completeKhaltiPayment,
} = require("../controllers/paymentController");

router.post("/initialize_khalti", initializeKhalti);
router.get("/complete-khalti-payment", completeKhaltiPayment);

module.exports = router;