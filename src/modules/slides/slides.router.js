const express = require('express');
const router = express.Router();
const {
    getAllSlides,
    getSlideById,
    createSlide,
    updateSlide,
    deleteSlide,
    getSlideStats,
    updateSlideOrder,
    incrementSlideViews
} = require('./slides.controller');

/**
 * @swagger
 * components:
 *   schemas:
 *     Slide:
 *       type: object
 *       required:
 *         - offerTitle
 *         - category
 *         - OffersId
 *         - backgroundImage
 *       properties:
 *         _id:
 *           type: string
 *           description: Slide ID
 *         offerTitle:
 *           type: string
 *           description: Offer title
 *           example: Zero Fee Demat Account
 *         category:
 *           type: string
 *           description: Category ID (ObjectId reference)
 *           example: 507f1f77bcf86cd799439011
 *         OffersId:
 *           type: string
 *           description: Unique offers ID
 *           example: OFFER001
 *         backgroundImage:
 *           type: string
 *           description: Background image URL or base64
 *           example: https://example.com/slide.png
 *         order:
 *           type: number
 *           description: Display order
 *           example: 1
 *         status:
 *           type: string
 *           enum: [active, inactive]
 *           description: Slide status
 *           example: active
 *         views:
 *           type: number
 *           description: Number of views
 *           example: 1250
 *         description:
 *           type: string
 *           description: Slide description
 *           example: Get amazing offers on demat account
 *         createdAt:
 *           type: string
 *           format: date-time
 *           description: Creation timestamp
 *         updatedAt:
 *           type: string
 *           format: date-time
 *           description: Last update timestamp
 */

/**
 * @swagger
 * /api/slides:
 *   get:
 *     summary: Get all slides
 *     tags: [Slides]
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [all, active, inactive]
 *         description: Filter by status
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category ID
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in offerTitle, OffersId, and description
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *         description: Items per page
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           default: order
 *         description: Sort field
 *       - in: query
 *         name: order
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: asc
 *         description: Sort order
 *     responses:
 *       200:
 *         description: Slides retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Slides retrieved successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     slides:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Slide'
 *                     pagination:
 *                       type: object
 *                       properties:
 *                         total:
 *                           type: number
 *                         page:
 *                           type: number
 *                         limit:
 *                           type: number
 *                         pages:
 *                           type: number
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/', getAllSlides);

/**
 * @swagger
 * /api/slides/stats:
 *   get:
 *     summary: Get slide statistics
 *     tags: [Slides]
 *     responses:
 *       200:
 *         description: Statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Slide statistics retrieved successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     total:
 *                       type: number
 *                       example: 50
 *                     active:
 *                       type: number
 *                       example: 45
 *                     inactive:
 *                       type: number
 *                       example: 5
 *                     totalViews:
 *                       type: number
 *                       example: 15000
 *       500:
 *         description: Server error
 */
router.get('/stats', getSlideStats);

/**
 * @swagger
 * /api/slides/{id}:
 *   get:
 *     summary: Get slide by ID
 *     tags: [Slides]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Slide ID
 *     responses:
 *       200:
 *         description: Slide retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Slide retrieved successfully
 *                 data:
 *                   $ref: '#/components/schemas/Slide'
 *       404:
 *         description: Slide not found
 *       500:
 *         description: Server error
 */
router.get('/:id', getSlideById);

/**
 * @swagger
 * /api/slides:
 *   post:
 *     summary: Create new slide
 *     tags: [Slides]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - offerTitle
 *               - category
 *               - OffersId
 *               - backgroundImage
 *             properties:
 *               offerTitle:
 *                 type: string
 *                 example: Zero Fee Demat Account
 *               category:
 *                 type: string
 *                 example: 507f1f77bcf86cd799439011
 *               OffersId:
 *                 type: string
 *                 example: OFFER001
 *               backgroundImage:
 *                 type: string
 *                 example: data:image/png;base64,iVBORw0KGgoAAAANS...
 *               order:
 *                 type: number
 *                 example: 1
 *               status:
 *                 type: string
 *                 enum: [active, inactive]
 *                 example: active
 *               description:
 *                 type: string
 *                 example: Get amazing offers on demat account
 *     responses:
 *       201:
 *         description: Slide created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Slide created successfully
 *                 data:
 *                   $ref: '#/components/schemas/Slide'
 *       400:
 *         description: Validation error or duplicate OffersId
 *       500:
 *         description: Server error
 */
router.post('/', createSlide);

/**
 * @swagger
 * /api/slides/{id}:
 *   put:
 *     summary: Update slide
 *     tags: [Slides]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Slide ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               offerTitle:
 *                 type: string
 *                 example: Updated Offer Title
 *               category:
 *                 type: string
 *                 example: 507f1f77bcf86cd799439011
 *               OffersId:
 *                 type: string
 *                 example: OFFER001
 *               backgroundImage:
 *                 type: string
 *                 example: data:image/png;base64,iVBORw0KGgoAAAANS...
 *               order:
 *                 type: number
 *                 example: 2
 *               status:
 *                 type: string
 *                 enum: [active, inactive]
 *                 example: active
 *               description:
 *                 type: string
 *                 example: Updated description
 *     responses:
 *       200:
 *         description: Slide updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Slide updated successfully
 *                 data:
 *                   $ref: '#/components/schemas/Slide'
 *       400:
 *         description: Validation error or duplicate OffersId
 *       404:
 *         description: Slide not found
 *       500:
 *         description: Server error
 */
router.put('/:id', updateSlide);

/**
 * @swagger
 * /api/slides/{id}:
 *   delete:
 *     summary: Delete slide
 *     tags: [Slides]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Slide ID
 *     responses:
 *       200:
 *         description: Slide deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Slide deleted successfully
 *                 data:
 *                   $ref: '#/components/schemas/Slide'
 *       404:
 *         description: Slide not found
 *       500:
 *         description: Server error
 */
router.delete('/:id', deleteSlide);

/**
 * @swagger
 * /api/slides/order/update:
 *   patch:
 *     summary: Update slide order in bulk
 *     tags: [Slides]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - slides
 *             properties:
 *               slides:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: 507f1f77bcf86cd799439011
 *                     order:
 *                       type: number
 *                       example: 1
 *     responses:
 *       200:
 *         description: Slide order updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Slide order updated successfully
 *       400:
 *         description: Invalid slides array
 *       500:
 *         description: Server error
 */
router.patch('/order/update', updateSlideOrder);

/**
 * @swagger
 * /api/slides/{id}/view:
 *   patch:
 *     summary: Increment slide views
 *     tags: [Slides]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Slide ID
 *     responses:
 *       200:
 *         description: Slide views incremented successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Slide views incremented successfully
 *                 data:
 *                   $ref: '#/components/schemas/Slide'
 *       404:
 *         description: Slide not found
 *       500:
 *         description: Server error
 */
router.patch('/:id/view', incrementSlideViews);

module.exports = router;
