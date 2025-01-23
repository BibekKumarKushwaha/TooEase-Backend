// paymentModel.js
const mongoose = require("mongoose");

const paymentSchema = new mongoose.Schema(
  {
    transactionId: String,
    pidx: String,
    productId: { type: mongoose.Schema.Types.ObjectId, ref: "PurchasedItem" },
    amount: Number,
    dataFromVerificationReq: Object,
    apiQueryFromUser: Object,
    paymentGateway: { type: String, enum: ["khalti"] },
    status: {
      type: String,
      enum: ["success", "pending", "failed"],
      default: "pending",
    },
    paymentDate: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Payment", paymentSchema);