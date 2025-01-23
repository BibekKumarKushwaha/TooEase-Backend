// purchasedItemsModel.js
const mongoose = require('mongoose');

const purchasedItemSchema = new mongoose.Schema({
    item: { type: mongoose.Schema.Types.ObjectId, ref: 'Item' },
    totalPrice: Number,
    paymentMethod: { type: String, enum: ['khalti'] },
    status: { type: String, enum: ['pending', 'completed'] },
}, { timestamps: true });

module.exports = mongoose.model('PurchasedItem', purchasedItemSchema);