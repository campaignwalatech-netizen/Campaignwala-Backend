const express = require('express');
const router = express.Router();

// Import route modules
const userRoutes = require('../modules/users/user.router');
const categoryRoutes = require('../modules/categories/categories.router');
const offerRoutes = require('../modules/offers/offers.router');
const slideRoutes = require('../modules/slides/slides.router');
const leadRoutes = require('../modules/leads/leads.router');
const walletRoutes = require('../modules/wallet/wallet.router');
const withdrawalRoutes = require('../modules/withdrawal/withdrawal.router');
const notificationRoutes = require('../modules/notifications/notification.router');
const queryRoutes = require('../modules/queries/query.router');
const adminLogRoutes = require('../modules/adminlogs/adminlog.router');

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
router.use('/withdrawals', withdrawalRoutes);
router.use('/notifications', notificationRoutes);
router.use('/queries', queryRoutes);
router.use('/adminlogs', adminLogRoutes);

module.exports = router;
