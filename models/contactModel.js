const mongoose = require('mongoose');
 
const contactMessageSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    message: { type: String, required: true }
}, { timestamps: true });
 
const ContactMessage = mongoose.model('ContactMessage', contactMessageSchema);
 
module.exports = ContactMessage;