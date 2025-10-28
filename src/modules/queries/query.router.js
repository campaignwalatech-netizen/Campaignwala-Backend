const express = require('express');
const router = express.Router();
const {
  getAllQueries,
  getQueryById,
  createQuery,
  updateQuery,
  deleteQuery,
  addReply,
  updateQueryStatus,
  getQueryStats,
  getQueriesByEmail,
  bulkDeleteQueries
} = require('./query.controller');

/**
 * @swagger
 * components:
 *   schemas:
 *     Reply:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           description: Reply ID
 *         message:
 *           type: string
 *           description: Reply message
 *         repliedBy:
 *           type: string
 *           description: Admin user ID who replied
 *         repliedByName:
 *           type: string
 *           description: Admin name
 *           example: Admin
 *         date:
 *           type: string
 *           format: date-time
 *           description: Reply date
 *     Query:
 *       type: object
 *       required:
 *         - user
 *         - email
 *         - subject
 *         - message
 *       properties:
 *         _id:
 *           type: string
 *           description: Query MongoDB ID
 *         queryId:
 *           type: string
 *           description: Auto-generated unique Query ID
 *           example: QRY-L5X8K9M-ABC
 *           readOnly: true
 *         user:
 *           type: string
 *           description: User name
 *           example: John Doe
 *         userId:
 *           type: string
 *           description: Reference to User (optional)
 *         email:
 *           type: string
 *           description: User email
 *           example: john@example.com
 *         subject:
 *           type: string
 *           description: Query subject
 *           example: Login Issue
 *         message:
 *           type: string
 *           description: Query message
 *         status:
 *           type: string
 *           enum: [Open, Replied, Closed]
 *           default: Open
 *         hasReplied:
 *           type: boolean
 *           default: false
 *         replies:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Reply'
 *         priority:
 *           type: string
 *           enum: [Low, Medium, High, Urgent]
 *           default: Medium
 *         category:
 *           type: string
 *           enum: [Technical, Account, Payment, General, Feature Request, Other]
 *           default: General
 *         attachments:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               filename:
 *                 type: string
 *               url:
 *                 type: string
 *               uploadedAt:
 *                 type: string
 *                 format: date-time
 *         isResolved:
 *           type: boolean
 *           default: false
 *         resolvedAt:
 *           type: string
 *           format: date-time
 *         resolvedBy:
 *           type: string
 *           description: Admin user ID who resolved
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 */

/**
 * @swagger
 * /api/queries:
 *   get:
 *     summary: Get all queries with filters
 *     tags: [Queries]
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [all, Open, Replied, Closed]
 *         description: Filter by status
 *       - in: query
 *         name: priority
 *         schema:
 *           type: string
 *           enum: [all, Low, Medium, High, Urgent]
 *         description: Filter by priority
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in user, email, subject, message
 *       - in: query
 *         name: user
 *         schema:
 *           type: string
 *         description: Filter by user name
 *       - in: query
 *         name: email
 *         schema:
 *           type: string
 *         description: Filter by email
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
 *         description: Queries retrieved successfully
 *       500:
 *         description: Server error
 */
router.get('/', getAllQueries);

/**
 * @swagger
 * /api/queries/stats:
 *   get:
 *     summary: Get query statistics
 *     tags: [Queries]
 *     responses:
 *       200:
 *         description: Statistics retrieved successfully
 *       500:
 *         description: Server error
 */
router.get('/stats', getQueryStats);

/**
 * @swagger
 * /api/queries/email/{email}:
 *   get:
 *     summary: Get queries by user email
 *     tags: [Queries]
 *     parameters:
 *       - in: path
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *     responses:
 *       200:
 *         description: User queries retrieved successfully
 *       500:
 *         description: Server error
 */
router.get('/email/:email', getQueriesByEmail);

/**
 * @swagger
 * /api/queries/{id}:
 *   get:
 *     summary: Get query by ID
 *     tags: [Queries]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Query retrieved successfully
 *       404:
 *         description: Query not found
 *       500:
 *         description: Server error
 */
router.get('/:id', getQueryById);

/**
 * @swagger
 * /api/queries:
 *   post:
 *     summary: Create new query
 *     tags: [Queries]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - user
 *               - email
 *               - subject
 *               - message
 *             properties:
 *               user:
 *                 type: string
 *                 example: John Doe
 *               userId:
 *                 type: string
 *               email:
 *                 type: string
 *                 example: john@example.com
 *               subject:
 *                 type: string
 *                 example: Login Issue
 *               message:
 *                 type: string
 *               priority:
 *                 type: string
 *                 enum: [Low, Medium, High, Urgent]
 *                 default: Medium
 *               category:
 *                 type: string
 *                 enum: [Technical, Account, Payment, General, Feature Request, Other]
 *                 default: General
 *               attachments:
 *                 type: array
 *                 items:
 *                   type: object
 *     responses:
 *       201:
 *         description: Query created successfully
 *       400:
 *         description: Validation error
 *       500:
 *         description: Server error
 */
router.post('/', createQuery);

/**
 * @swagger
 * /api/queries/{id}:
 *   put:
 *     summary: Update query
 *     tags: [Queries]
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
 *             type: object
 *             properties:
 *               subject:
 *                 type: string
 *               message:
 *                 type: string
 *               status:
 *                 type: string
 *               priority:
 *                 type: string
 *               category:
 *                 type: string
 *     responses:
 *       200:
 *         description: Query updated successfully
 *       404:
 *         description: Query not found
 *       500:
 *         description: Server error
 */
router.put('/:id', updateQuery);

/**
 * @swagger
 * /api/queries/{id}:
 *   delete:
 *     summary: Delete query
 *     tags: [Queries]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Query deleted successfully
 *       404:
 *         description: Query not found
 *       500:
 *         description: Server error
 */
router.delete('/:id', deleteQuery);

/**
 * @swagger
 * /api/queries/{id}/reply:
 *   post:
 *     summary: Add reply to query
 *     tags: [Queries]
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
 *             type: object
 *             required:
 *               - message
 *             properties:
 *               message:
 *                 type: string
 *                 example: Thank you for reaching out. We will resolve this issue.
 *               repliedBy:
 *                 type: string
 *                 description: Admin user ID
 *               repliedByName:
 *                 type: string
 *                 example: Admin
 *                 default: Admin
 *     responses:
 *       200:
 *         description: Reply added successfully
 *       400:
 *         description: Validation error
 *       404:
 *         description: Query not found
 *       500:
 *         description: Server error
 */
router.post('/:id/reply', addReply);

/**
 * @swagger
 * /api/queries/{id}/status:
 *   patch:
 *     summary: Update query status
 *     tags: [Queries]
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
 *             type: object
 *             required:
 *               - status
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [Open, Replied, Closed]
 *     responses:
 *       200:
 *         description: Status updated successfully
 *       400:
 *         description: Invalid status
 *       404:
 *         description: Query not found
 *       500:
 *         description: Server error
 */
router.patch('/:id/status', updateQueryStatus);

/**
 * @swagger
 * /api/queries/bulk-delete:
 *   post:
 *     summary: Delete multiple queries
 *     tags: [Queries]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - ids
 *             properties:
 *               ids:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Queries deleted successfully
 *       400:
 *         description: Bad request
 *       500:
 *         description: Server error
 */
router.post('/bulk-delete', bulkDeleteQueries);

module.exports = router;
