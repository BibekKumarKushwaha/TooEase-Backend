const userModel = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendOtp = require('../service/sendOtp');
const sendEmail = require('../service/emailService');

const crypto = require('crypto');

const PASSWORD_POLICY = {
  minLength: 8,
  maxLength: 20,
  regex: /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
};






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

// Lockout tiers
const LOCKOUT_CONFIG = [
  { attempts: 5, lockTime: 15 * 1000 },       // Lock 15s after 5 attempts
  { attempts: 10, lockTime: 60 * 1000 },      // Lock 1m after 10 attempts
  { attempts: 15, lockTime: 5 * 60 * 1000 },  // Lock 5m after 15 attempts
  { attempts: Infinity, lockTime: 60 * 60 * 1000 }, // 1h after 20+ attempts
];

// Given current total attempts, find lock time from the config
const getLockTime = (attempts) => {
  for (const config of LOCKOUT_CONFIG) {
    if (attempts <= config.attempts) {
      return config.lockTime;
    }
  }
  return 0;
};
const verifyEmail = async (req, res) => {
  try {
      const token = req.params.token;

      // Hash the received token to compare with the stored one
      const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

      // Find the user with the matching token and ensure it hasn't expired
      const user = await userModel.findOne({
          emailVerificationToken: hashedToken,
          emailVerificationTokenExpire: { $gt: Date.now() }, // Ensure the token hasn't expired
      });

      if (!user) {
          return res.json({ success: false, message: "Invalid or expired token" });
      }

      // Mark the user's email as verified
      user.isEmailVerified = true;
      user.emailVerificationToken = undefined; // Clear the token fields
      user.emailVerificationTokenExpire = undefined;

      await user.save();

      res.json({ success: true, message: "Email verified successfully" });
  } catch (error) {
      console.error("Verification Error:", error);
      res.json({ success: false, message: "Server error" });
  }
};
// // Create User Function
// const createUser = async (req, res) => {
//   const { firstName, lastName, email, phone, password } = req.body;

//   // Check for missing fields
//   if (!firstName || !lastName || !email || !phone || !password) {
//     return res.status(400).json({
//       success: false,
//       message: "Please enter all fields!",
//     });
//   }

//   // Validate password strength
//   if (!isPasswordValid(password)) {
//     return res.status(400).json({
//       success: false,
//       message:
//         "Password must be 8-20 characters long, include uppercase, lowercase, numbers, and special characters!",
//     });
//   }

//   try {
//     const existingUser = await userModel.findOne({ email });

//     if (existingUser) {
//       return res.status(400).json({
//         success: false,
//         message: "User already exists!",
//       });
//     }

//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     const newUser = new userModel({
//       firstName,
//       lastName,
//       email,
//       phone,
//       password: hashedPassword,
//       passwordHistory: [hashedPassword], // Add initial password to history
//       passwordLastChanged: new Date(), // Record the password change date
//     });

//     await newUser.save();

//     res.status(201).json({
//       success: true,
//       message: "User registered successfully!",
//     });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({
//       success: false,
//       message: "Internal Server Error!",
//     });
//   }
// };

// Create User Function with Email Verification
const createUser = async (req, res) => {
  // Log incoming request data (optional, useful for debugging)
  console.log("Incoming Request Data:", req.body);

  const { firstName, lastName, email, phone, password } = req.body;

  // Check for missing fields
  if (!firstName || !lastName || !email || !phone || !password) {
    return res.status(400).json({
      success: false,
      message: "Please enter all fields!",
    });
  }

  // Validate password strength
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

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Generate email verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(verificationToken).digest("hex");

    const newUser = new userModel({
      firstName,
      lastName,
      email,
      phone,
      password: hashedPassword,
      passwordHistory: [hashedPassword], // Add initial password to history
      passwordLastChanged: new Date(), // Record the password change date
      isEmailVerified: false, // Initialize email verification status
      emailVerificationToken: hashedToken, // Store hashed verification token
      emailVerificationTokenExpire: Date.now() + 10 * 60 * 1000, // Token expires in 10 minutes
    });

    await newUser.save();

    // Log email before sending (optional)
    console.log("Sending verification email to:", newUser.email);

    if (!newUser.email) {
      console.error("Error: Email is missing in newUser");
    } else {
      const verificationURL = `${process.env.FRONTEND_URL || "https://localhost:3000"}/verify-email/${verificationToken}`;
      const message = `Please click on the link to verify your email: \n\n ${verificationURL}`;

      await sendEmail({
        email: newUser.email,
        subject: "Email Verification",
        message,
      });
    }

    res.status(201).json({
      success: true,
      message: "User registered successfully! Verification email sent.",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error!",
    });
  }
};

// Login User Function
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  // Check for missing fields
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

    // Check if user is locked
    if (user.isLocked) {
      // If the lock time has passed, remove the lock but DO NOT reset attempts
      if (user.lockUntil <= Date.now()) {
        user.lockUntil = null;
        // <-- IMPORTANT: do NOT reset user.loginAttempts here
        await user.save();
      } else {
        // If user is still locked, respond with time remaining
        const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000);
        return res.status(403).json({
          success: false,
          message: "Account is locked due to multiple failed login attempts.",
          remainingTime,
        });
      }
    }

    // Validate password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      // Increment attempts
      user.loginAttempts = (user.loginAttempts || 0) + 1;

      // Determine lock time based on the *new* total attempts
      const lockTime = getLockTime(user.loginAttempts);

      // If the user meets the minimum attempts to be locked (5 or more)
      if (lockTime > 0 && user.loginAttempts >= LOCKOUT_CONFIG[0].attempts) {
        user.lockUntil = Date.now() + lockTime;
        await user.save();
        return res.status(403).json({
          success: false,
          message: "Account locked due to multiple failed login attempts.",
          remainingTime: lockTime / 1000, // lock time in seconds
        });
      }

      await user.save();
      return res.status(400).json({
        success: false,
        message: "Password not matched!",
        remainingAttempts:
          LOCKOUT_CONFIG.find((config) => user.loginAttempts <= config.attempts)
            ?.attempts - user.loginAttempts,
      });
    }

    // Check for password expiry
    if (user.passwordLastChanged) {
      const passwordLastChanged = new Date(user.passwordLastChanged);
      const passwordExpiryDate = new Date(
        passwordLastChanged.setDate(passwordLastChanged.getDate() + PASSWORD_EXPIRY_DAYS)
      );

      if (new Date() > passwordExpiryDate) {
        return res.status(400).json({
          success: false,
          message: "Password has expired. Please reset your password.",
        });
      }
    }

    // If password is correct, reset attempts & lock
    user.loginAttempts = 0;
    user.lockUntil = null;
    user.isLoggedIn = true;
    console.log(`User ${user.email} is logging in. isLoggedIn set to ${user.isLoggedIn}`);
    await user.save();

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
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
        phone: user.phone,
        isAdmin: user.isAdmin,
        isLoggedIn: user.isLoggedIn,
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

  // Check for missing fields
  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      message: "Please enter all fields!",
    });
  }

  // Validate new password strength
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

const getAllUsers = async (req, res) => {
  try {
      const users = await userModel.find().select('-password -resetPasswordOTP -resetPasswordExpires -passwordHistory'); // Exclude sensitive fields
      res.status(200).json({
          success: true,
          users,
      });
  } catch (error) {
      console.error(error);
      res.status(500).json({
          success: false,
          message: "Internal Server Error!",
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

// ... existing imports and code

// Logout User Function
const logoutUser = async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1]; // Assuming Bearer token
    if (!token) {
      return res.status(401).json({ message: 'Authorization token is missing' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await userModel.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.isLoggedIn = false; // Set isLoggedIn to false
    await user.save();

    res.status(200).json({
      success: true,
      message: 'User logged out successfully!',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
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
    getAllUsers,
    logoutUser,
    verifyEmail
};