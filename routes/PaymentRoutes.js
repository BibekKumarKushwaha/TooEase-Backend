const router = require('express').Router();

const paymentController = require('../controllers/paymentController');
const { authGuard } = require('../middleware/authGuard');

router.post('/initialize_khalti', paymentController.initializePayment);
router.get('/complete-khalti-payment', paymentController.completeKhaltiPayment);

module.exports = router;