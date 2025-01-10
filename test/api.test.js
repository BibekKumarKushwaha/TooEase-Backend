
const request = require('supertest');
const app = require('../index');
const ContactMessage = require('../models/contactModel'); // Make sure the path is correct

// Test token for admin (use an actual token from your environment)
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY2NzdhNGM1YWQ2NTVkYTE1ZmE0N2IxOCIsImlzQWRtaW4iOmZhbHNlLCJpYXQiOjE3MTkxMTcwMDN9.83IXXGwWAhulpITsLQLsBt5Lk_tIyGw_RQfcDkyDEtM';
const productId = '66b4787f8eb6361d72e2493c';
describe('Testing API', () => {
     //testing '/test' api case
     it('GET /test | Response with text', async () => {
        //request sending and receiving response
        const response = await request(app).get('/test') //check in index.js file
 
        //if its sucessfull, then status code should be 200
        expect(response.statusCode).toBe(200)
 
        //Compare received text with expected text
        expect(response.text).toEqual('Test api is working..')
 
    })
    // Test for creating a user
    it('POST /api/user/create | Should create a new user', async () => {
        const response = await request(app).post('/api/user/create').send({
            "firstName": "John1",
            "lastName": "Shah",
            "email": "john1@gmail.com",
            "password": "John@@1",
            "phone": "1234567890"
        });

        if (!response.body.success) {
            expect(response.statusCode).toBe(200);
            expect(response.body.message).toEqual('User already exists!');
        } else {
            expect(response.statusCode).toBe(201);
            expect(response.body.message).toEqual('User Created Successfully!');
        }
    });

    // Test for incorrect login
    it('POST /api/user/login | Should fail with incorrect password', async () => {
        const response = await request(app).post('/api/user/login').send({
            'email': 'john@gmail.com',
            'password': 'wrongpassword'
        });

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Password not matched!');
    });

    // Test for missing fields during user creation
    it('POST /api/user/create | Should fail with missing fields', async () => {
        const response = await request(app).post('/api/user/create').send({
            "firstName": "John",
            "email": "john@gmail.com"
        });

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Please enter all fields!');
    });

    // Test for fetching all products
    it('GET /api/product/get_all_products | Should fetch all products', async () => {
        const response = await request(app)
            .get('/api/product/get_all_products')
            .set('Authorization', `Bearer ${token}`);

        expect(response.statusCode).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.products).toBeDefined();
        expect(Array.isArray(response.body.products)).toBe(true);
    });

 

    // Test for fetching a single product by ID
    it('GET /api/product/get_single_product/:id | Should fetch a single product by ID', async () => {
        const productId = '66b477058eb6361d72e248c4'; // Replace with a valid product ID
        const response = await request(app)
            .get(`/api/product/get_single_product/${productId}`)
            .set('Authorization', `Bearer ${token}`);

        expect(response.statusCode).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.product).toBeDefined();
    });

    

    // Test for updating a cart item
    it('PUT /api/cart/update/:id | Should update a cart item', async () => {
        const cartItemId = '66b47a7e8eb6361d72e24a81'; // Replace with a valid cart item ID
        const response = await request(app)
            .put(`/api/cart/update/${cartItemId}`)
            .set('Authorization', `Bearer ${token}`)
            .send({
                quantity: 3,
                total: 300
            });

        expect(response.statusCode).toBe(200);
        expect(response.body.message).toEqual('Item updated successfully');
    });
    
    

  
});

describe('Testing Reviews and Favorites API', () => {
    
    

    // Test for fetching reviews by product ID
    it('GET /api/rating/product/:productId | Should fetch reviews for a product', async () => {
        const response = await request(app)
            .get(`/api/rating/product/${productId}`)
            .set('Authorization', `Bearer ${token}`);

        expect(response.statusCode).toBe(200);
        expect(response.body.reviews).toBeDefined();
        expect(Array.isArray(response.body.reviews)).toBe(true);
    });
    

    
});
 // Ensure this path is correct
 // Ensure this path is correct

// Helper function to create a test contact message
const createTestContactMessage = async () => {
    const message = new ContactMessage({
        firstName: 'Test',
        lastName: 'User',
        email: 'testuser@example.com',
        message: 'This is a test message.'
    });
    await message.save();
    return message;
};

describe('Contact API', () => {
    // Test for submitting a contact form
  

    // Test for getting all contact messages
    it('GET /api/contact/all | Should fetch all contact messages', async () => {
        await createTestContactMessage();

        const response = await request(app).get('/api/contact/all');

        expect(response.statusCode).toBe(200);
        expect(response.body.contacts).toBeDefined();
        expect(Array.isArray(response.body.contacts)).toBe(true);
        expect(response.body.contacts.length).toBeGreaterThan(0); 
        expect(response.body.contacts[0]).toHaveProperty('firstName');
        expect(response.body.contacts[0]).toHaveProperty('lastName');
        expect(response.body.contacts[0]).toHaveProperty('email');
        expect(response.body.contacts[0]).toHaveProperty('message');
    });

     // Test for server error when retrieving contacts
     it('GET /api/contact/all | Should return server error on failure', async () => {
        // Mock the ContactMessage model to simulate an error
        jest.spyOn(ContactMessage, 'find').mockImplementation(() => {
            throw new Error('Simulated error');
        });

        const response = await request(app).get('/api/contact/all');

        expect(response.statusCode).toBe(500);
        expect(response.text).toContain('Server error');
    });
    // 14. Test for updating cart status with invalid status
  it('PUT /api/cart/status | Update cart status with invalid status', async () => {
    const response = await request(app).put('/api/cart/status').send({
      status: 'invalid_status'
    });

    expect(response.statusCode).toBe(400);
    expect(response.body).toHaveProperty('message', 'Invalid cart status');
  });
});
