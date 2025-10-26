const express = require('express');
const router = express.Router();

// Import route modules
const userRoutes = require('../modules/users/user.router');
const categoryRoutes = require('../modules/categories/categories.router');
const offerRoutes = require('../modules/offers/offers.router');
const slideRoutes = require('../modules/slides/slides.router');
const leadRoutes = require('../modules/leads/leads.router');
const walletRoutes = require('../modules/wallet/wallet.router');

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
router.use('/slides', slideRoutes);
router.use('/leads', leadRoutes);
router.use('/wallet', walletRoutes);

module.exports = router;
