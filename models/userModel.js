const mongoose = require('mongoose')
const userSchema = new mongoose.Schema({
    firstName : {
        type: String,
        require : true
    },
    lastName : {
        type : String,
        require : true
    },
    email : {
        type : String,
        require : true,
        unique : true
    },
    phone : {
        type : Number,
        require : true,
    },
    password : {
        type : String,
        require : true
    },
    isAdmin: {
        type: Boolean,
        default: false
    },
    resetPasswordOTP : {
        type: Number,
        default : null
    },
    resetPasswordExpires: {
        type: Date,
        default: null
    }

})

const User = mongoose.model('users',userSchema)
module.exports = User;
 