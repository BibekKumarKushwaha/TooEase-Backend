const {
  initializeKhaltiPayment,
  verifyKhaltiPayment,
} = require('../service/khaltiService');
const Payment = require('../models/paymentModel');
const BookingModel = require('../models/bookingModel');

// Route to initialize Khalti payment gateway
const initializePayment = async (req, res) => {
  console.log(req.body);

  try {
    const { bookings, totalPrice, website_url } = req.body;

    console.log(bookings);
    // Extract product names from populated products array
    const productNames = bookings.map((p) => p.bikeNumber).join(', ');

    if (!productNames) {
      return res.send({
        success: false,
        message: 'No booking names found',
      });
    }

    // Create a payment document without transactionId initially
    const OrderModelData = await Payment.create({
      bookings: bookings,
      paymentGateway: 'khalti',
      amount: totalPrice,
      status: 'pending', // Set the initial status to pending
    });

    // Initialize the Khalti payment
    const paymentInitate = await initializeKhaltiPayment({
      amount: totalPrice * 100, // amount should be in paisa (Rs * 100)
      purchase_order_id: OrderModelData._id, // purchase_order_id because we need to verify it later
      purchase_order_name: productNames,
      return_url: `http://localhost:5000/api/payment/complete-khalti-payment`,
      website_url,
    });

    // Update the payment record with the transactionId and pidx
    await Payment.updateOne(
      { _id: OrderModelData._id },
      {
        $set: {
          transactionId: paymentInitate.pidx, // Assuming pidx as transactionId from Khalti response
          pidx: paymentInitate.pidx,
        },
      }
    );

    res.json({
      success: true,
      OrderModelData,
      payment: paymentInitate,
    });
  } catch (error) {
    res.json({
      success: false,
      error: error.message || 'An error occurred',
    });
  }
};

// This is our return URL where we verify the payment done by the user
const completeKhaltiPayment = async (req, res) => {
  const { pidx, amount, purchase_order_id } = req.query;

  try {
    const paymentInfo = await verifyKhaltiPayment(pidx);

    // Validate the payment info
    if (
      paymentInfo?.status !== 'Completed' || // Ensure the status is "Completed"
      paymentInfo.pidx !== pidx || // Verify pidx matches
      Number(paymentInfo.total_amount) !== Number(amount) // Compare the total amount
    ) {
      return res.status(400).json({
        success: false,
        message: 'Incomplete or invalid payment information',
        paymentInfo,
      });
    }

    // // Check if payment corresponds to a valid order
    // const purchasedItemData = await OrderModel.findOne({
    //   _id: purchase_order_id,
    //   totalPrice: amount,
    // });

    // if (!purchasedItemData) {
    //   return res.status(404).json({
    //     success: false,
    //     message: "Order data not found",
    //   });
    // }

    // Update the order status to 'completed'
    // await Payment.findByIdAndUpdate(
    //   purchase_order_id,
    //   {
    //     $set: {
    //       status: "completed",
    //     },
    //   }
    // );

    // Update payment record with verification data
    const paymentData = await Payment.findOneAndUpdate(
      { _id: purchase_order_id },
      {
        $set: {
          pidx,
          transactionId: paymentInfo.transaction_id,
          // dataFromVerificationReq: paymentInfo,
          // apiQueryFromUser: req.query,
          status: 'success',
        },
      },
      { new: true }
    );
    res.redirect(`https://test-pay.khalti.com/?pidx=${pidx}`);

    // // Send success response
    // res.json({
    //   success: true,
    //   message: "Payment Successful",
    //   paymentData,
    // });
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during payment verification',
      error: error.message || 'An unknown error occurred',
    });
  }
};

module.exports = { initializePayment, completeKhaltiPayment };