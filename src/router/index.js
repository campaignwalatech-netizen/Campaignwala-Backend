const express = require('express');
const router = express.Router();

// Import route modules
const userRoutes = require('../modules/users/user.router');
const categoryRoutes = require('../modules/categories/categories.router');
const offerRoutes = require('../modules/offers/offers.router');

// Health check for API
router.get('/health', (req, res) => {
    res.json({
        success: true,
        message: 'API is healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Mount route modules
router.use('/users', userRoutes);
router.use('/categories', categoryRoutes);
router.use('/offers', offerRoutes);

module.exports = router;
