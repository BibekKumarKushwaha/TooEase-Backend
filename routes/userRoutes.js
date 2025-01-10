const router = require("express").Router();
const userController = require('../controllers/userControllers');
const { authGuard } = require("../middleware/authGuard");
 
// Creating user registration route
router.post('/create', userController.createUser)
 
//login routes
router.post('/login',userController.loginUser)

//forgot password
router.post ('/forgot_password', userController.forgotPassword)

//verify otp and reset the password
router.post ('/verify_otp', userController.verifyOtpAndSetPassword)

//profile
router.get('/profile', userController.getUserProfile);
router.put('/profile', userController.updateUserProfile);
 
// Controller(Export)-> Routes (import)-> use ->(index.js)

//get user data 
router.get('/user/:id',userController.getUserDetails);


router.get("/token",userController.getToken);

router.get("/profile/get", userController.getCurrentProfile);
//Exporting the routes
module.exports = router;
