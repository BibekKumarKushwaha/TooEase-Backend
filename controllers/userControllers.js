// const userModel = require('../models/userModel');
// const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken');
// const sendOtp = require('../service/sendOtp');

// const createUser = async (req, res) => {
//     // res.send("Create user API is working!")

//     //1.Check incoming data
//     console.log(req.body);

//     //2.Destructure the incoming data
//     const { firstName, lastName, email, phone, password } = req.body;

//     //3.Validate the data
//     if (!firstName || !lastName || !email || !password || !phone) {
//         // res.send("Please enter all fields!")
//         res.status(400).json({
//             "success": false,
//             "message": "Please enter all fields!"
//         });
//         return;
//     }

//     //4.Error Handling(try catch)
//     try {
//         //5.Check if the user is already registered
//         const existingUser = await userModel.findOne({ email: email });
//         //5.1 If user found: send response
//         if (existingUser) {
//             return res.json({
//                 "success": false,
//                 "message": "User already exists!"
//             });
//         }

//         // Hashing / encryption of the password
//         const randomSalt = await bcrypt.genSalt(10);
//         const hashedPassword = await bcrypt.hash(password, randomSalt);

//         //5.2 If user is new:

//         const newUser = new userModel({
//             //Field : Client's Value
//             firstName: firstName,
//             lastName: lastName,
//             email: email,
//             phone: phone,
//             password: hashedPassword
//         });

//         //Save to database
//         await newUser.save();

//         //send the response
//         res.status(201).json({
//             "success": true,
//             "message": "User Created Successfully!"
//         });
//     } catch (error) {
//         console.log(error);
//         res.status(400).json({
//             "success": false,
//             "message": "Internal server Error!"
//         });
//     }
// };

// //login function
// const loginUser = async (req, res) => {
//     // res.send("Login API is working !")

//     //Check incoming data
//     console.log(req.body);

//     //Destructuring the data
//     const { email, password } = req.body;

//     //Validation
//     if (!email || !password) {
//         return res.json({
//             "success": false,
//             "message": "Please enter all fields!"
//         });
//     }

//     //try catch
//     try {

//         //find user (email)
//         const user = await userModel.findOne({ email: email });
//         //found data: firstName, lastName, email, password

//         //not found(error message)
//         if (!user) {
//             return res.status(400).json({
//                 "success": false,
//                 "message": "User does not exist!"
//             });
//         }

//         //compare password(bcrypt)
//         const isValidPassword = await bcrypt.compare(password, user.password);

//         //not valid(error)
//         if (!isValidPassword) {
//             return res.status(400).json({
//                 "success": false,
//                 "message": "Password not matched!"
//             });
//         }
//         //token(Generate - user Data+KEY)
//         const token = await jwt.sign(
//             { id: user._id },
//             process.env.JWT_SECRET
//         );
//         //response (token, user data)
//         res.status(201).json({
//             "success": true,
//             "message": "User logged in successfully!",
//             "token": token,
//             "userData": user
//         });


//     } catch (error) {
//         console.log(error);
//         return res.status(400).json({
//             "success": false,
//             "message": "Please enter all fields!"
//         });
//     }
// };


// const forgotPassword = async (req, res) => {
//     console.log(req.body);
   
//     const { phone } = req.body;
   
//     if (!phone) {
//       return res.status(400).json({
//         success: false,
//         message: "Please enter your phone number",
//       });
//     }
//     try {
//       const user = await userModel.findOne({ phone: phone });
//       if (!user) {
//         return res.status(404).json({
//           success: false,
//           message: "User not found",
//         });
//       }
//       // Generate OTP
//       const randomOTP = Math.floor(100000 + Math.random() * 900000);
//       console.log(randomOTP);
   
//       user.resetPasswordOTP = randomOTP;
//       user.resetPasswordExpires = Date.now() + 600000; // 10 minutes
//       await user.save();
   
//       // Send OTP to user phone number
//       const isSent = await sendOtp(phone, randomOTP);
   
//       if (!isSent) {
//         return res.status(400).json({
//           success: false,
//           message: "Error in sending OTP",
//         });
//       }
   
//       res.status(200).json({
//         success: true,
//         message: "OTP sent to your phone number",
//       });
//     } catch (error) {
//       console.log(error);
//       return res.status(500).json({
//         success: false,
//         message: "Internal server error",
//       });
//     }
//   };

// //verify otp and change password
// const verifyOtpAndSetPassword = async (req, res) => {
//     //get data
//     const { phone, otp, newPassword } = req.body;
//     if (!phone || !otp || !newPassword) {
//         return res.status(400).json({
//             'success': false,
//             'message': 'required fields are missing!'
//         });
//     }
//     try {
//         const user = await userModel.findOne({ phone: phone });

//         //verify otp
//         if (user.resetPasswordOTP != otp) {
//             return res.status(400).json({
//                 'success': false,
//                 'message': 'invalid otp!!'
//             });
//         }
//         if (user.resetPasswordExpires < Date.now()) {
//             return res.status(400).json({
//                 'success': false,
//                 'message': 'OTP Expired!'
//             });
//         }
//         //password hash
//         const randomSalt = await bcrypt.genSalt(10);
//         const hashedPassword = await bcrypt.hash(newPassword, randomSalt);

//         //update password
//         user.password = hashedPassword;
//         await user.save();

//         //response
//         res.status(200).json({
//             'success': true,
//             'message': 'OTP verified and password updated!'
//         });

//     } catch (error) {
//         console.log(error);
//         return res.status(500).json({
//             'success': false,
//             'message': 'server error!'
//         });
//     }
// };
// const getUserProfile = async (req, res) => {
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
//         res.json(user);
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ message: 'Server error' });
//     }
// };

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
// const getUserDetails = async (req, res) => {
//     try {
//       const userId = req.params.id; // Assume you have user ID available in params
//       const user = await User.findById(userId).select('firstName, lastName, phone');
//       if (!user) {
//         return res.status(404).json({ message: 'User not found' });
//       }
//       res.json(user);
//     } catch (error) {
//       res.status(500).json({ message: 'Server error', error });
//     }
//   };
  

//   const getToken = async (req, res) => {
//     try {
//       console.log(req.body);
//       const { id } = req.body;
   
//       const user = await userModel.findById(id);
//       if (!user) {
//         return res.status(400).json({
//           success: false,
//           message: 'User not found',
//         });
//       }
   
//       const jwtToken = await jwt.sign(
//         { id: user._id, isAdmin: user.isAdmin },
//         process.env.JWT_SECRET,
//         (options = {
//           expiresIn:
//             Date.now() + process.env.JWT_TOKEN_EXPIRE * 24 * 60 * 60 * 1000 ||
//             '1d',
//         })
//       );
   
//       return res.status(200).json({
//         success: true,
//         message: 'Token generated successfully!',
//         token: jwtToken,
//       });
//     } catch (error) {
//       console.log(error);
//       return res.status(500).json({
//         success: false,
//         message: 'Internal Server Error',
//         error: error,
//       });
//     }
//   };
//     //Get Current Profile
//     const getCurrentProfile = async (req, res) => {
//       // const id = req.user.id;
//       try {
//         const token = req.headers.authorization.split(" ")[1];
//         const decoded =jwt.verify(token,process.env.JWT_SECRET);
       
//         const user = await userModel.findById(decoded.id);
//         if (!user) {
//           return res.status(400).json({
//             success: false,
//             message: 'User not found',
//           });
//         }
//         res.status(200).json({
//           success: true,
//           message: 'User fetched successfully',
//           user: user,
//         });
//       } catch (error) {
//         console.log(error);
//         res.status(500).json({
//           success: false,
//           message: 'Internal server error backend',
//           error: error,
//         });
//       }
//     };

// // Exporting
// module.exports = {
//     createUser,
//     loginUser,
//     forgotPassword,
//     verifyOtpAndSetPassword,
//     getUserProfile,
//     updateUserProfile,
//     getUserDetails,
//     getCurrentProfile,
//     getToken,
// };
const userModel = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendOtp = require('../service/sendOtp');

const createUser = async (req, res) => {
    // res.send("Create user API is working!")

    //1.Check incoming data
    console.log(req.body);

    //2.Destructure the incoming data
    const { firstName, lastName, email, phone, password } = req.body;

    //3.Validate the data
    if (!firstName || !lastName || !email || !password || !phone) {
        // res.send("Please enter all fields!")
        res.status(400).json({
            "success": false,
            "message": "Please enter all fields!"
        });
        return;
    }

    //4.Error Handling(try catch)
    try {
        //5.Check if the user is already registered
        const existingUser = await userModel.findOne({ email: email });
        //5.1 If user found: send response
        if (existingUser) {
            return res.json({
                "success": false,
                "message": "User already exists!"
            });
        }

        // Hashing / encryption of the password
        const randomSalt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, randomSalt);

        //5.2 If user is new:

        const newUser = new userModel({
            //Field : Client's Value
            firstName: firstName,
            lastName: lastName,
            email: email,
            phone: phone,
            password: hashedPassword
        });

        //Save to database
        await newUser.save();

        //send the response
        res.status(201).json({
            "success": true,
            "message": "User Created Successfully!"
        });
    } catch (error) {
        console.log(error);
        res.status(400).json({
            "success": false,
            "message": "Internal server Error!"
        });
    }
};

//login function
const loginUser = async (req, res) => {
    // res.send("Login API is working !")

    //Check incoming data
    console.log(req.body);

    //Destructuring the data
    const { email, password } = req.body;

    //Validation
    if (!email || !password) {
        return res.json({
            "success": false,
            "message": "Please enter all fields!"
        });
    }

    //try catch
    try {

        //find user (email)
        const user = await userModel.findOne({ email: email });
        //found data: firstName, lastName, email, password

        //not found(error message)
        if (!user) {
            return res.status(400).json({
                "success": false,
                "message": "User does not exist!"
            });
        }

        //compare password(bcrypt)
        const isValidPassword = await bcrypt.compare(password, user.password);

        //not valid(error)
        if (!isValidPassword) {
            return res.status(400).json({
                "success": false,
                "message": "Password not matched!"
            });
        }
        //token(Generate - user Data+KEY)
        const token = await jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET
        );
        //response (token, user data)
        res.status(201).json({
            "success": true,
            "message": "User logged in successfully!",
            "token": token,
            "userData": user
        });


    } catch (error) {
        console.log(error);
        return res.status(400).json({
            "success": false,
            "message": "Please enter all fields!"
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
        if (firstName) user.firstName = firstName;
        if (lastName) user.lastName = lastName;
        if (phone) user.phone = phone;
        if (password) user.password = await bcrypt.hash(password, 10);

        await user.save();
        res.json(user);
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
};