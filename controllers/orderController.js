// const Order = require('../models/Order');
// const Product = require('../models/Product');
// const User = require('../models/User');

// exports.createOrder = async (req, res) => {
//   try {
//     const { productId, quantity, deliveryInfo, paymentMethod } = req.body;

//     const product = await Product.findById(productId);
//     if (!product) {
//       return res.status(404).json({ message: 'Product not found' });
//     }

//     const user = await User.findById(req.user.id);
//     if (!user) {
//       return res.status(404).json({ message: 'User not found' });
//     }

//     const totalPrice = product.productPrice * quantity;

//     const order = new Order({
//       user: req.user.id,
//       product: productId,
//       quantity,
//       totalPrice,
//       deliveryInfo,
//       paymentMethod,
//     });

//     await order.save();

//     res.status(201).json({ message: 'Order created successfully', order });
//   } catch (error) {
//     res.status(500).json({ message: 'Server error', error });
//   }
// };

// exports.getOrdersByUser = async (req, res) => {
//   try {
//     const orders = await Order.find({ user: req.user.id }).populate('product');
//     res.status(200).json(orders);
//   } catch (error) {
//     res.status(500).json({ message: 'Server error', error });
//   }
// };

// exports.getAllOrders = async (req, res) => {
//   try {
//     const orders = await Order.find().populate('product').populate('user');
//     res.status(200).json(orders);
//   } catch (error) {
//     res.status(500).json({ message: 'Server error', error });
//   }
// };
const orderModel = require("../models/orderModel");

exports.addOrder = async (req, res) => {
  console.log(req.body);
  const { carts, address, totalAmount, paymentType } = req.body;

  try {
    const order = await orderModel({
      carts,
      address,
      total: totalAmount,
      paymentType,
      userId: req.user.id,
    });

    await order.save();

    res.status(200).json({ success: true, order });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error.message });
  }
};

exports.getAllOrders = async (req, res) => {
  try {
    const orders = await orderModel
      .find({})
      .populate("carts")
      .populate("userId")
      .sort({ createdAt: -1, status: 1 });
    res.json({
      success: true,
      orders,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.getUserOrders = async (req, res) => {
  try {
    const orders = await orderModel
      .find({ userId: req.user.id })
      .populate("carts")
      .populate({
        path: "carts",
        populate: {
          path: "productId",
          model: "products",
        },
      })
      .sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      orders,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.updateOrderStatus = async (req, res) => {
  const { status } = req.body;
  const { id } = req.params;

  try {
    const order = await orderModel.findById(id);
    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    await orderModel.findByIdAndUpdate(id, { status });

    res.status(200).json({ success: true, message: "Order status updated" });
  } catch (e) {
    res.status(500).json({ error: error.message });
  }
};
