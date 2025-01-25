const userModel = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendOtp = require('../service/sendOtp');


// Define password policy
const PASSWORD_POLICY = {
  minLength: 8,
  maxLength: 20,
  regex: /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
};
const MAX_LOGIN_ATTEMPTS = 5; // Maximum allowed login attempts before lockout
const LOCK_TIME = 15 * 60 * 1000; // Lockout time in milliseconds (15 minutes)


// Track reused passwords and expiry
const PASSWORD_HISTORY_LIMIT = 5; // Number of previous passwords to store
const PASSWORD_EXPIRY_DAYS = 90; // Password expiry in days

// Function to validate password strength
const isPasswordValid = (password) => {
  if (
    password.length < PASSWORD_POLICY.minLength ||
    password.length > PASSWORD_POLICY.maxLength ||
    !PASSWORD_POLICY.regex.test(password)
  ) {
    return false;
  }
  return true;
};

// Function to check password reuse
const isPasswordReused = async (user, newPassword) => {
  for (const hashedOldPassword of user.passwordHistory || []) {
    if (await bcrypt.compare(newPassword, hashedOldPassword)) {
      return true;
    }
  }
  return false;
};

// Create User Function
const createUser = async (req, res) => {
  console.log(req.body);

  const { firstName, lastName, email, phone, password } = req.body;

  if (!firstName || !lastName || !email || !password || !phone) {
    return res.status(400).json({
      success: false,
      message: "Please enter all fields!",
    });
  }

  if (!isPasswordValid(password)) {
    return res.status(400).json({
      success: false,
      message:
        "Password must be 8-20 characters long, include uppercase, lowercase, numbers, and special characters!",
    });
  }

  try {
    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists!",
      });
    }

    const randomSalt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, randomSalt);

    const newUser = new userModel({
      firstName,
      lastName,
      email,
      phone,
      password: hashedPassword,
      passwordHistory: [hashedPassword], // Initialize password history
      passwordLastChanged: new Date(), // Track password change date
    });

    await newUser.save();

    res.status(201).json({
      success: true,
      message: "User Created Successfully!",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error!",
    });
  }
};




const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Please enter all fields!",
    });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User does not exist!",
      });
    }

    // Check if the account is locked and reset if the lock period has passed
    if (user.lockUntil && user.lockUntil <= Date.now()) {
      user.loginAttempts = 0;
      user.lockUntil = undefined;
      await user.save();
    }

    // If the account is still locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000); // Time in seconds
      return res.status(403).json({
        success: false,
        message: "Account is locked due to multiple failed login attempts.",
        remainingTime, // Remaining lockout time in seconds
      });
    }

    // Compare password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;

      // Lock account if max attempts exceeded
      if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.lockUntil = Date.now() + LOCK_TIME;
        await user.save();
        return res.status(403).json({
          success: false,
          message: "Account locked due to multiple failed login attempts.",
          remainingTime: LOCK_TIME / 1000, // Lock time in seconds
        });
      }

      await user.save();
      return res.status(400).json({
        success: false,
        message: "Password not matched!",
        remainingAttempts: MAX_LOGIN_ATTEMPTS - user.loginAttempts,
      });
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h", // Optional: Token expiration time
    });

    res.status(200).json({
      success: true,
      message: "User logged in successfully!",
      token,
      userData: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error!",
    });
  }
};
// Change Password Function
const changePassword = async (req, res) => {
  const { email, currentPassword, newPassword } = req.body;

  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      message: "Please enter all fields!",
    });
  }

  if (!isPasswordValid(newPassword)) {
    return res.status(400).json({
      success: false,
      message:
        "New password must be 8-20 characters long, include uppercase, lowercase, numbers, and special characters!",
    });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User does not exist!",
      });
    }

    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect!",
      });
    }

    if (await isPasswordReused(user, newPassword)) {
      return res.status(400).json({
        success: false,
        message: "New password cannot be one of your recent passwords!",
      });
    }

    const randomSalt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, randomSalt);

    user.password = hashedNewPassword;
    user.passwordHistory = [hashedNewPassword, ...user.passwordHistory.slice(0, PASSWORD_HISTORY_LIMIT - 1)];
    user.passwordLastChanged = new Date();

    await user.save();

    res.status(200).json({
      success: true,
      message: "Password changed successfully!",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error!",
    });
  }
};


const forgotPassword = async (req, res) => {
    console.log(req.body);
   
    const { phone } = req.body;
   
    if (!phone) {
      return res.status(400).json({
        success: false,
        message: "Please enter your phone number",
      });
    }
    try {
      const user = await userModel.findOne({ phone: phone });
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }
      // Generate OTP
      const randomOTP = Math.floor(100000 + Math.random() * 900000);
      console.log(randomOTP);
   
      user.resetPasswordOTP = randomOTP;
      user.resetPasswordExpires = Date.now() + 600000; // 10 minutes
      await user.save();
   
      // Send OTP to user phone number
      const isSent = await sendOtp(phone, randomOTP);
   
      if (!isSent) {
        return res.status(400).json({
          success: false,
          message: "Error in sending OTP",
        });
      }
   
      res.status(200).json({
        success: true,
        message: "OTP sent to your phone number",
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        success: false,
        message: "Internal server error",
      });
    }
  };

//verify otp and change password
const verifyOtpAndSetPassword = async (req, res) => {
    //get data
    const { phone, otp, newPassword } = req.body;
    if (!phone || !otp || !newPassword) {
        return res.status(400).json({
            'success': false,
            'message': 'required fields are missing!'
        });
    }
    try {
        const user = await userModel.findOne({ phone: phone });

        //verify otp
        if (user.resetPasswordOTP != otp) {
            return res.status(400).json({
                'success': false,
                'message': 'invalid otp!!'
            });
        }
        if (user.resetPasswordExpires < Date.now()) {
            return res.status(400).json({
                'success': false,
                'message': 'OTP Expired!'
            });
        }
        //password hash
        const randomSalt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, randomSalt);

        //update password
        user.password = hashedPassword;
        await user.save();

        //response
        res.status(200).json({
            'success': true,
            'message': 'OTP verified and password updated!'
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            'success': false,
            'message': 'server error!'
        });
    }
};
const getUserProfile = async (req, res) => {
    const token = req.headers.authorization.split(' ')[1]; // Assuming Bearer token
    if (!token) {
        return res.status(401).json({ message: 'Authorization token is missing' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

// const updateUserProfile = async (req, res) => {
//     const token = req.headers.authorization.split(' ')[1]; // Assuming Bearer token
//     if (!token) {
//         return res.status(401).json({ message: 'Authorization token is missing' });
//     }
//     try {
//         const decoded = jwt.verify(token, process.env.JWT_SECRET);
//         const user = await userModel.findById(decoded.id);
//         if (!user) {
//             return res.status(404).json({ message: 'User not found' });
//         }

//         const { firstName, lastName, phone, password } = req.body;
//         if (firstName) user.firstName = firstName;
//         if (lastName) user.lastName = lastName;
//         if (phone) user.phone = phone;
//         if (password) user.password = await bcrypt.hash(password, 10);

//         await user.save();
//         res.json(user);
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ message: 'Server error' });
//     }
// };
const updateUserProfile = async (req, res) => {
  const token = req.headers.authorization.split(' ')[1]; // Assuming Bearer token
  if (!token) {
      return res.status(401).json({ message: 'Authorization token is missing' });
  }

  try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await userModel.findById(decoded.id);
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      const { firstName, lastName, phone, password } = req.body;

      // Update basic profile information
      if (firstName) user.firstName = firstName;
      if (lastName) user.lastName = lastName;
      if (phone) user.phone = phone;

      // Handle password update
      if (password) {
          // Check if the new password matches the previous ones
          for (const hashedOldPassword of user.passwordHistory || []) {
              const isReused = await bcrypt.compare(password, hashedOldPassword);
              if (isReused) {
                  return res.status(400).json({
                      success: false,
                      message: 'New password cannot be one of your recent passwords!',
                  });
              }
          }

          // Validate new password against policy
          const passwordPolicy = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/;
          if (!passwordPolicy.test(password)) {
              return res.status(400).json({
                  success: false,
                  message:
                      'Password must be 8-20 characters long, include uppercase, lowercase, numbers, and special characters!',
              });
          }

          // Hash the new password and update password history
          const randomSalt = await bcrypt.genSalt(10);
          const hashedPassword = await bcrypt.hash(password, randomSalt);

          user.password = hashedPassword;
          user.passwordHistory = [hashedPassword, ...(user.passwordHistory || []).slice(0, 4)]; // Keep up to 5 passwords
          user.passwordLastChanged = new Date();
      }

      await user.save();
      res.json({
          success: true,
          message: 'Profile updated successfully!',
          user,
      });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
  }
};

const getUserDetails = async (req, res) => {
    try {
      const userId = req.params.id; // Assume you have user ID available in params
      const user = await User.findById(userId).select('firstName, lastName, phone');
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  };
  
  // Get User Token
const getToken = async (req, res) => {
  try {
    console.log(req.body);
    const { id } = req.body;
 
    const user = await userModel.findById(id);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'User not found',
      });
    }
 
    const jwtToken = await jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      (options = {
        expiresIn:
          Date.now() + process.env.JWT_TOKEN_EXPIRE * 24 * 60 * 60 * 1000 ||
          '1d',
      })
    );
 
    return res.status(200).json({
      success: true,
      message: 'Token generated successfully!',
      token: jwtToken,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: error,
    });
  }
};
//Get Current Profile
const getCurrentProfile = async (req, res) => {
  // const id = req.user.id;
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded =jwt.verify(token,process.env.JWT_SECRET);
   
    const user = await userModel.findById(decoded.id);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'User not found',
      });
    }
    res.status(200).json({
      success: true,
      message: 'User fetched successfully',
      user: user,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error,
    });
  }
};
  
  

// Exporting
module.exports = {
    createUser,
    loginUser,
    forgotPassword,
    verifyOtpAndSetPassword,
    getUserProfile,
    updateUserProfile,
    getUserDetails,
    getToken,
    getCurrentProfile,
    changePassword,
};