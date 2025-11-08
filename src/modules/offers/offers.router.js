const express = require('express');
const router = express.Router();
const upload = require('../../middleware/upload.middleware');
const {
  getAllOffers,
  getOfferById,
  createOffer,
  updateOffer,
  deleteOffer,
  approveOffer,
  rejectOffer,
  getOfferStats,
  bulkUploadOffers,
  getOffersByCategory
} = require('./offers.controller');

/**
 * @swagger
 * components:
 *   schemas:
 *     Offer:
 *       type: object
 *       required:
 *         - name
 *         - category
 *       properties:
 *         _id:
 *           type: string
 *           description: Offer ID
 *         name:
 *           type: string
 *           description: Offer name
 *           example: Premium Digital Campaign
 *         category:
 *           type: string
 *           description: Offer category
 *           example: Digital Marketing
 *         description:
 *           type: string
 *           description: Offer description
 *         latestStage:
 *           type: string
 *           enum: [Upload, Number, Pending, Completed]
 *           description: Latest stage
 *         commission1:
 *           type: string
 *           description: First commission
 *           example: ₹5,000
 *         commission1Comment:
 *           type: string
 *           description: Comment for commission 1
 *         commission2:
 *           type: string
 *           description: Second commission
 *           example: ₹1,200
 *         commission2Comment:
 *           type: string
 *           description: Comment for commission 2
 *         link:
 *           type: string
 *           description: Offer link
 *         image:
 *           type: string
 *           description: Offer image URL or base64
 *         video:
 *           type: string
 *           description: Video filename or URL
 *         videoLink:
 *           type: string
 *           description: Video link URL
 *         termsAndConditions:
 *           type: string
 *           description: Terms and conditions
 *         isApproved:
 *           type: boolean
 *           description: Approval status
 *         leadId:
 *           type: string
 *           description: Lead ID
 *         offersId:
 *           type: string
 *           description: Auto-generated unique Offers ID
 *           example: OFF-L5X8K9M-ABC12
 *           readOnly: true
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 */

/**
 * @swagger
 * /api/offers:
 *   get:
 *     summary: Get all offers
 *     tags: [Offers]
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [all, Active, Hold, Pending, Completed, Rejected]
 *         description: Filter by status (deprecated - kept for backward compatibility)
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category
 *       - in: query
 *         name: isApproved
 *         schema:
 *           type: boolean
 *         description: Filter by approval status
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in name, description, leadId
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           default: createdAt
 *       - in: query
 *         name: order
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *     responses:
 *       200:
 *         description: Offers retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     offers:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Offer'
 *                     pagination:
 *                       type: object
 */
router.get('/', getAllOffers);

/**
 * @swagger
 * /api/offers/stats:
 *   get:
 *     summary: Get offer statistics
 *     tags: [Offers]
 *     responses:
 *       200:
 *         description: Statistics retrieved successfully
 */
router.get('/stats', getOfferStats);

/**
 * @swagger
 * /api/offers/category/{categoryId}:
 *   get:
 *     summary: Get offers by category
 *     tags: [Offers]
 *     description: Retrieves all offers for a specific category with their IDs
 *     parameters:
 *       - in: path
 *         name: categoryId
 *         required: true
 *         schema:
 *           type: string
 *         description: Category ID
 *     responses:
 *       200:
 *         description: Offers retrieved successfully
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
 *                   example: Offers retrieved successfully
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       _id:
 *                         type: string
 *                         description: Offer MongoDB ID
 *                       name:
 *                         type: string
 *                         description: Offer name
 *                       leadId:
 *                         type: string
 *                         description: Lead ID
 *                       offersId:
 *                         type: string
 *                         description: Auto-generated unique Offers ID
 */
router.get('/category/:categoryId', getOffersByCategory);

/**
 * @swagger
 * /api/offers/bulk-upload:
 *   post:
 *     summary: Bulk upload offers from Excel/CSV file
 *     tags: [Offers]
 *     description: Upload an Excel (.xlsx, .xls) or CSV file to create multiple offers at once. Maximum file size is 10MB.
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - file
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *                 description: Excel or CSV file with offers data. Required columns - leadId, name, category, commission1. Optional columns - commission2, customerContact, description, status, isApproved
 *     responses:
 *       201:
 *         description: Bulk upload completed successfully
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
 *                   example: "Bulk upload completed: 45 offers created, 5 failed"
 *                 data:
 *                   type: object
 *                   properties:
 *                     totalRows:
 *                       type: number
 *                       example: 50
 *                     successCount:
 *                       type: number
 *                       example: 45
 *                     failedCount:
 *                       type: number
 *                       example: 5
 *                     successItems:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           row:
 *                             type: number
 *                             example: 2
 *                           leadId:
 *                             type: string
 *                             example: "LEAD001"
 *                           name:
 *                             type: string
 *                             example: "Premium Campaign"
 *                     failedItems:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           row:
 *                             type: number
 *                             example: 10
 *                           data:
 *                             type: object
 *                           error:
 *                             type: string
 *                             example: "Duplicate leadId"
 *       400:
 *         description: Invalid file format or validation error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Validation failed: Missing required fields"
 *                 errors:
 *                   type: object
 *                   properties:
 *                     missingFields:
 *                       type: array
 *                       items:
 *                         type: string
 *                       example: ["leadId", "name", "category"]
 *                     invalidRows:
 *                       type: array
 *                       items:
 *                         type: object
 *       500:
 *         description: Server error during bulk upload
 */
router.post('/bulk-upload', upload.single('file'), bulkUploadOffers);

/**
 * @swagger
 * /api/offers/{id}:
 *   get:
 *     summary: Get offer by ID
 *     tags: [Offers]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Offer retrieved successfully
 *       404:
 *         description: Offer not found
 */
router.get('/:id', getOfferById);

/**
 * @swagger
 * /api/offers:
 *   post:
 *     summary: Create new offer
 *     tags: [Offers]
 *     description: Creates a new offer with auto-generated unique offersId
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Offer'
 *     responses:
 *       201:
 *         description: Offer created successfully with auto-generated offersId
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
 *                   example: Offer created successfully
 *                 data:
 *                   $ref: '#/components/schemas/Offer'
 */
router.post('/', createOffer);

/**
 * @swagger
 * /api/offers/{id}:
 *   put:
 *     summary: Update offer
 *     tags: [Offers]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Offer'
 *     responses:
 *       200:
 *         description: Offer updated successfully
 */
router.put('/:id', updateOffer);

/**
 * @swagger
 * /api/offers/{id}:
 *   delete:
 *     summary: Delete offer
 *     tags: [Offers]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Offer deleted successfully
 */
router.delete('/:id', deleteOffer);

/**
 * @swagger
 * /api/offers/{id}/approve:
 *   post:
 *     summary: Approve offer
 *     tags: [Offers]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Offer approved successfully
 */
router.post('/:id/approve', approveOffer);

/**
 * @swagger
 * /api/offers/{id}/reject:
 *   post:
 *     summary: Reject offer
 *     tags: [Offers]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               reason:
 *                 type: string
 *     responses:
 *       200:
 *         description: Offer rejected successfully
 */
router.post('/:id/reject', rejectOffer);

module.exports = router;
