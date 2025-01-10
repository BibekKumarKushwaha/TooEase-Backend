const path = require('path')
const productModel = require('../models/productModel')
const fs = require('fs')//file system
const CreateProduct = async (req, res) => {
    //check incoming data
    console.log(req.body)
    console.log(req.files)

    //destructiing the body data (json)
    const { productName,
        productPrice,
        productCategory,
        productDescription
    } = req.body;
    //validation (task)
    if (!productName || !productPrice || !productCategory || !productDescription) {
        return res.status(400).json({
            "success": false,
            "message": "enter all fields"
        })
    }
    //validate if there is image '
    if (!req.files || !req.files.productImage) {
        return res.status(400).json({
            "success": false,
            "message": "Image not foumd"
        })
    }
    const { productImage } = req.files;

    //upload image
    //1. generate new image name (abc.png) -> (213456-abc.png)
    const imageName = `${Date.now()}-${productImage.name}`;
    //2. make a upload path(/path/upload-directory)
    const imageUploadPath = path.join(__dirname, `../public/products/${imageName}`)
    //3. Move to that directory (await,try-catch)

    //save to database
    const newProduct = new productModel({
        productName: productName,
        productPrice: productPrice,
        productCategory: productCategory,
        productDescription: productDescription,
        productImage: imageName
    })
    const product = await newProduct.save()
    res.status(201).json({
        "success": true,
        "message": "product create successfully",
        "data": product
    })
    try {
        await productImage.mv(imageUploadPath)

    } catch (error) {
        console.log(error)
        res.status(500).json({
            "success": false,
            "message": "internal server error",
            "error": error
        })

    }


};

//fetch all products
const getAllProducts = async (req, res) => {
    //try catch
    try {
        const allProducts = await productModel.find({})
        res.status(201).json({
            "success": true,
            "message": "products fethched successfully",
            "products": allProducts
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({
            "success": false,
            "message": "internal server error",
            "error": error
        })

    }
    //fetch all products
    //send response

}

//fetch single product
const getSingleProduct = async (req, res) => {
    //get product id from url(params)
    console.log(req.params)
    const productId = req.params.id;
    try {
        const product = await productModel.findById(req.params.id)
        console.log(product)
        // if(!product){
        //     res.status(400).json({
        //         "success": false,
        //         "message" : "no server found"
        //     })

        // }
        res.status(201).json({
            "success": true,
            "message": "product fethched successfully",
            "product": product
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({
            "success": false,
            "message": "internal server error",
            "error": error
        })

    }


}

//delete product
const deleteProduct = async (req, res) => {
    try {
        await productModel.findByIdAndDelete(req.params.id)
        res.status(201).json({
            "success": true,
            "message": "product deleted successfully"
        })

    } catch (error) {
        res.status(500).json({
            "success": false,
            "message": "internal server error",
            "error": error
        })
    }

}

// update product
//1. get product id (URL)
//2. if image :
//3. new image should be uploaded
//4. old image should be deleted
//5. find product (database) productImage
//6. find that image in directory
//7. delete that image
//8. update that product

const updateProudct = async (req, res) => {
    try {
        //if there is image 
        if (req.files && req.files.productImage) {
            //destructiing the body
            const { productImage } = req.files;

            //upload image to /public/products folder
            //1. generate new image name (abc.png) -> (213456-abc.png)
            const imageName = `${Date.now()}-${productImage.name}`;
            //2. make a upload path(/path/upload-directory)
            const imageUploadPath = path.join(__dirname, `../public/products/${imageName}`)
            
            //3. Move to folder
            await productImage.mv(imageUploadPath)

            //req.params(id), req.body(updated data)=> (productName,productPrice,productCategory,productDescription), req.files(image)
            //add new field to req.body (productImage -> name)
            req.body.productImage = imageName; //image uploaded (generated name)
            //if image is uploaded and req.body is assigned 
            if(req.body.productImage){
                const existingProduct = await productModel.findById(req.params.id)

                //sea
                const oldImagePath = path.join(__dirname, `../public/products/${existingProduct.productImage}`)

                //delete old image from filesystem
                fs.unlinkSync(oldImagePath)

            }


        }

        //update the data 
        const updatedProduct = await productModel.findByIdAndUpdate(req.params.id, req.body);
        res.status(201).json({
            success: true,
            message: "product updated successfully",
            product: updatedProduct
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({
            success: false,
            message: "internal server error",
            error: error
        })

    }

}

//pagination
// const paginationProducts = async (req,res) => {
//     //result per page 
//     const pageNo = req.query.page || 1;

//     //result per page 
//     const resultPerPage = 2;
//     try{
//         //find all products, skip, limit
//         const products =await productModel.find({})
//         .skip((pageNo - 1 )*resultPerPage)
//         .limit(resultPerPage)

//         //if page 6 is requested, result 0
//         if(products.length === 0){
//             return res.status(400).json({
//                 'success' : false,
//                 'message': "No product found"
                
//             })
//         }

//         //response
//         res.status(201).json({
//             'success': true,
//             'message': "product fetched",
//             'products': products
//         })


//     }catch(error){
//         console.log(error)
//         res.status(500).json({
//             'success' : false,
//             'message' : "Internal server error"
//         })

//     }

//}
// Pagination
const paginationProducts = async (req, res) => {
    try {
      // page no
      const PageNo = parseInt(req.query.page) || 1;
      // per page count
      const resultPerPage = parseInt(req.query.limit) || 2;
   
      // Search query
      const searchQuery = req.query.q || '';
      const sortOrder = req.query.sort || 'asc';
   
      const filter = {};
      if (searchQuery) {
        filter.productName = { $regex: searchQuery, $options: 'i' };
      }
   
      // Sorting
      const sort = sortOrder === 'asc' ? { productPrice: 1 } : { productPrice: -1 };
   
      // Find products with filters, pagination, and sorting
      const products = await productModel
        .find(filter)
        .skip((PageNo - 1) * resultPerPage)
        .limit(resultPerPage)
        .sort(sort);
   
      // If the requested page has no results
      if (products.length === 0) {
        return res.status(400).json({
          success: false,
          message: "No products found",
        });
      }
   
      // Send response
      res.status(200).json({
        success: true,
        message: "products fetched successfully",
        products: products,
      });
    } catch (error) {
      console.log(error);
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error,
      });
    }
  };
  const getProductCount = async (req, res) => {
    try {
      const productCount = await productModel.countDocuments({});
   
      res.status(200).json({
        success: true,
        message: 'product count fetched successfully',
        productCount: productCount,
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


module.exports = {
    CreateProduct,
    getAllProducts,
    getSingleProduct,
    deleteProduct,
    updateProudct,
    paginationProducts,
    getProductCount
};