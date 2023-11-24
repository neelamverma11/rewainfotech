const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
require('./models');
const { userCtrl, authenticateToken } = require('./Controllers/userController');

const app = express();

app.use(bodyParser.json());
app.use(cors());

// Unprotected routes
app.post('/api/create-account', userCtrl.postUsers);
app.post('/api/login', userCtrl.loginUser);
app.get('/api/dashboard', userCtrl.getUsers);
app.put('/api/edit-profile/:id', userCtrl.updateUserProfile);
app.get('/api/dashboard/:id', userCtrl.getUser);

// Protected routes 
// app.put('/api/dashboard/:id', authenticateToken, userCtrl.updateUser);
app.put('/api/change-password/:id', authenticateToken, userCtrl.updateUserPassword);

app.listen(3000, () => console.log('express server is running port 3000'));
