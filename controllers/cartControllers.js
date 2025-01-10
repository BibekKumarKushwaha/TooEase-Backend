
const path = require("path");
const Cart = require("../models/cartModel");

exports.addToCart = async (req, res) => {
  const { productId, quantity, total } = req.body;
  const id = req.user.id;

  if (!productId || !quantity || !total) {
    return res.status(400).json({ message: "Please enter all fields" });
  }

  try {
    const itemInCart = await Cart.findOne({
      productId: productId,
      userId: id,
      status: "active",
    });

    if (itemInCart) {
      itemInCart.quantity += parseInt(quantity, 10);
      itemInCart.total = itemInCart.quantity * (total / quantity);
      await itemInCart.save();
      return res
        .status(200)
        .json({ message: "Item quantity updated", cartItem: itemInCart });
    }

    const cartItem = new Cart({
      productId: productId,
      quantity: parseInt(quantity, 10),
      total: total,
      userId: id,
    });

    await cartItem.save();
    res.status(200).json({ message: "Item added to cart", cartItem });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


// Get all cart items
exports.getAllCartItems = async (req, res) => {
  const id = req.user.id;
  try {
    //  join cart with products
    const cartItems = await Cart.find({
      userId: id,
      status: "active",
    }).populate("productId");
    console.log(cartItems);
    res.status(200).json({ carts: cartItems });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Delete item from cart
exports.deleteCartItem = async (req, res) => {
  try {
    console.log(req.params);
    const { id } = req.params;
    console.log(req.params);
    await Cart.findByIdAndDelete(id);
    res.json({ message: "Item deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Update cart item endpoint
exports.updateCartItem = async (req, res) => {
  try {
    const { id } = req.params; // Extract id from URL params
    let { quantity, total } = req.body; // Extract quantity from request body

    // Convert quantity to a number if it's provided as a string
    quantity = Number(quantity);
    console.log(typeof quantity);
    // Validate quantity here if needed
    if (isNaN(quantity) || quantity <= 0) {
      return res
        .status(400)
        .json({ error: "Quantity must be a valid number greater than zero" });
    }

    // Update the cart item based on id
    await Cart.findByIdAndUpdate(id, { quantity, total });

    // Respond with success message
    res.status(200).json({ message: "Item updated successfully" });
  } catch (error) {
    // Handle errors
    console.error("Error updating cart item:", error);
    res.status(500).json({ error: error.message });
  }
};

exports.updateUserCartStatus = async (req, res) => {
  try {
    const id = req.user.id;
    const { status } = req.body;

    const cartItems = await Cart.updateMany({ userId: id }, { status: status });
    res
      .status(200)
      .json({ message: "Cart status updated successfully", cartItems });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

