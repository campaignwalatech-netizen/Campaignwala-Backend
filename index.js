const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const connectDB = require('./src/config/db');
const swaggerSetup = require('./src/config/swagger');
const routes = require('./src/router/index');

// Load environment variables
dotenv.config();

// Create Express app
const app = express();

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors());
// Increase payload limit for base64 images (10MB)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log('🟢 ===== INCOMING REQUEST =====');
    console.log(`🟢 [${timestamp}] ${req.method} ${req.path}`);
    console.log('🟢 Full URL:', req.originalUrl);
    console.log('🟢 Headers:', req.headers.authorization ? '✅ Has Token' : '❌ No Token');
    console.log('🟢 ==============================');
    next();
});

// Swagger Documentation
swaggerSetup(app);

// Routes
app.use('/api', routes);

// Health check route
app.get('/', (req, res) => {
    res.json({
        message: 'Campaignwala Panels Backend API is running!',
        version: '1.0.0',
        documentation: '/api-docs'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`API Documentation: http://localhost:${PORT}/api-docs`);
});

module.exports = app;
