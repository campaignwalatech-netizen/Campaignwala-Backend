const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Campaignwala Panels Backend API',
            version: '1.0.0',
            description: 'API documentation for Campaignwala Panels Backend with user authentication and role management',
            contact: {
                name: 'API Support',
                email: 'support@campaignwala.com'
            }
        },
        servers: [
            {
                url: process.env.NODE_ENV === 'production'
                    ? 'https://your-production-url.com'
                    : `http://localhost:${process.env.PORT || 5000}`,
                description: process.env.NODE_ENV === 'production' ? 'Production server' : 'Development server'
            }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            },
            schemas: {
                User: {
                    type: 'object',
                    properties: {
                        _id: {
                            type: 'string',
                            description: 'User ID'
                        },
                        phoneNumber: {
                            type: 'string',
                            description: 'User phone number',
                            example: '9876543210'
                        },
                        role: {
                            type: 'string',
                            enum: ['user', 'admin'],
                            description: 'User role'
                        },
                        isVerified: {
                            type: 'boolean',
                            description: 'Phone number verification status'
                        },
                        createdAt: {
                            type: 'string',
                            format: 'date-time'
                        },
                        updatedAt: {
                            type: 'string',
                            format: 'date-time'
                        }
                    }
                },
                ApiResponse: {
                    type: 'object',
                    properties: {
                        success: {
                            type: 'boolean'
                        },
                        message: {
                            type: 'string'
                        },
                        data: {
                            type: 'object'
                        }
                    }
                },
                Error: {
                    type: 'object',
                    properties: {
                        success: {
                            type: 'boolean',
                            example: false
                        },
                        message: {
                            type: 'string'
                        },
                        error: {
                            type: 'string'
                        }
                    }
                }
            }
        },
        security: [
            {
                bearerAuth: []
            }
        ]
    },
    apis: ['./src/modules/**/*.router.js', './src/router/**/*.js'] // paths to files containing OpenAPI definitions
};

const specs = swaggerJsdoc(options);

const swaggerSetup = (app) => {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs, {
        explorer: true,
        customCss: '.swagger-ui .topbar { display: none }',
        customSiteTitle: 'Campaignwala API Docs'
    }));
};

module.exports = swaggerSetup;