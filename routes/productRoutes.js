const router =require('express').Router();
const productController =require('../controllers/productControllers');
const { authGuard, } = require('../middleware/authGuard');

router.post('/create', productController.CreateProduct)

//fetch all products
router.get('/get_all_products',productController.getAllProducts)


//single product
router.get('/get_single_product/:id',productController.getSingleProduct)

//delete product
router.delete('/delete_product/:id',authGuard,productController.deleteProduct)

//update product
router.put('/update_product/:id',authGuard,productController.updateProudct)

//pagination
router.get('/pagination',productController.paginationProducts);

//get product count
router.get('/get_product_count',productController.getProductCount)




module.exports=router


