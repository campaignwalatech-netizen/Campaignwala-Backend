const express = require('express');
const router = express.Router();
const {
  getAllAdminLogs,
  getAdminLogById,
  createAdminLog,
  deleteAdminLog,
  getAdminLogStats,
  getLogsByAdminId,
  bulkDeleteAdminLogs,
  clearOldLogs
} = require('./adminlog.controller');

/**
 * @swagger
 * components:
 *   schemas:
 *     AdminLog:
 *       type: object
 *       required:
 *         - adminName
 *         - action
 *       properties:
 *         _id:
 *           type: string
 *           description: MongoDB ObjectId
 *         logId:
 *           type: string
 *           description: Unique log ID (auto-generated)
 *           example: LOG-1234567890-5678
 *         adminId:
 *           type: string
 *           description: Admin user ID reference
 *         adminName:
 *           type: string
 *           description: Name of admin who performed action
 *           example: Super Admin
 *         adminRole:
 *           type: string
 *           description: Role of the admin
 *           example: Super Admin
 *         action:
 *           type: string
 *           description: Description of action performed
 *           example: Updated Offer #145
 *         actionType:
 *           type: string
 *           enum: [create, update, delete, approve, reject, login, logout, system, other]
 *           description: Type of action
 *           example: update
 *         module:
 *           type: string
 *           enum: [users, offers, categories, leads, withdrawals, notifications, queries, slides, wallet, system, authentication, other]
 *           description: Module/feature affected
 *           example: offers
 *         severity:
 *           type: string
 *           enum: [info, success, warning, error]
 *           description: Log severity level
 *           example: info
 *         ipAddress:
 *           type: string
 *           description: IP address of admin
 *           example: 192.168.1.100
 *         userAgent:
 *           type: string
 *           description: Browser user agent
 *         details:
 *           type: string
 *           description: Detailed description of the action
 *           example: Modified offer title and description...
 *         metadata:
 *           type: object
 *           description: Additional metadata as JSON
 *         targetId:
 *           type: string
 *           description: ID of affected entity
 *         targetType:
 *           type: string
 *           description: Type of affected entity
 *         status:
 *           type: string
 *           enum: [success, failed, pending]
 *           description: Status of the action
 *           example: success
 *         errorMessage:
 *           type: string
 *           description: Error message if action failed
 *         createdAt:
 *           type: string
 *           format: date-time
 *           description: Timestamp when log was created
 *         updatedAt:
 *           type: string
 *           format: date-time
 *           description: Timestamp when log was last updated
 */

/**
 * @swagger
 * /api/adminlogs:
 *   get:
 *     summary: Get all admin logs
 *     description: Retrieve all admin activity logs with optional filtering, search, and pagination
 *     tags: [Admin Logs]
 *     parameters:
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [info, success, warning, error]
 *         description: Filter by severity level
 *       - in: query
 *         name: actionType
 *         schema:
 *           type: string
 *           enum: [create, update, delete, approve, reject, login, logout, system, other]
 *         description: Filter by action type
 *       - in: query
 *         name: module
 *         schema:
 *           type: string
 *           enum: [users, offers, categories, leads, withdrawals, notifications, queries, slides, wallet, system, authentication, other]
 *         description: Filter by module
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [success, failed, pending]
 *         description: Filter by status
 *       - in: query
 *         name: adminId
 *         schema:
 *           type: string
 *         description: Filter by admin user ID
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in admin name, action, details, IP address
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter logs from this date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter logs until this date
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Page number for pagination
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *         description: Number of logs per page
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           default: createdAt
 *         description: Field to sort by
 *       - in: query
 *         name: sortOrder
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *         description: Sort order
 *     responses:
 *       200:
 *         description: Admin logs retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     logs:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/AdminLog'
 *                     pagination:
 *                       type: object
 *                       properties:
 *                         currentPage:
 *                           type: integer
 *                         totalPages:
 *                           type: integer
 *                         totalLogs:
 *                           type: integer
 *                         limit:
 *                           type: integer
 *                         hasNextPage:
 *                           type: boolean
 *                         hasPreviousPage:
 *                           type: boolean
 *       500:
 *         description: Server error
 */
router.get('/', getAllAdminLogs);

/**
 * @swagger
 * /api/adminlogs/stats:
 *   get:
 *     summary: Get admin log statistics
 *     description: Get comprehensive statistics about admin activities
 *     tags: [Admin Logs]
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
 *                 data:
 *                   type: object
 *                   properties:
 *                     total:
 *                       type: integer
 *                       description: Total number of logs
 *                     recentActivity:
 *                       type: integer
 *                       description: Logs in last 24 hours
 *                     bySeverity:
 *                       type: object
 *                       description: Count by severity level
 *                     byActionType:
 *                       type: object
 *                       description: Count by action type
 *                     byModule:
 *                       type: object
 *                       description: Count by module
 *                     byStatus:
 *                       type: object
 *                       description: Count by status
 *                     mostActiveAdmins:
 *                       type: array
 *                       description: Top 10 most active admins
 *       500:
 *         description: Server error
 */
router.get('/stats', getAdminLogStats);

/**
 * @swagger
 * /api/adminlogs/admin/{adminId}:
 *   get:
 *     summary: Get logs by admin ID
 *     description: Retrieve all logs for a specific admin user
 *     tags: [Admin Logs]
 *     parameters:
 *       - in: path
 *         name: adminId
 *         required: true
 *         schema:
 *           type: string
 *         description: Admin user ID
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           default: createdAt
 *       - in: query
 *         name: sortOrder
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *     responses:
 *       200:
 *         description: Logs retrieved successfully
 *       500:
 *         description: Server error
 */
router.get('/admin/:adminId', getLogsByAdminId);

/**
 * @swagger
 * /api/adminlogs/{id}:
 *   get:
 *     summary: Get admin log by ID
 *     description: Retrieve a single admin log by MongoDB ID or logId
 *     tags: [Admin Logs]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Log ID (MongoDB _id or logId)
 *     responses:
 *       200:
 *         description: Log retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   $ref: '#/components/schemas/AdminLog'
 *       404:
 *         description: Log not found
 *       500:
 *         description: Server error
 */
router.get('/:id', getAdminLogById);

/**
 * @swagger
 * /api/adminlogs:
 *   post:
 *     summary: Create admin log entry
 *     description: Create a new admin activity log entry
 *     tags: [Admin Logs]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - adminName
 *               - action
 *             properties:
 *               adminId:
 *                 type: string
 *                 description: Admin user ID
 *               adminName:
 *                 type: string
 *                 description: Admin name
 *                 example: Super Admin
 *               adminRole:
 *                 type: string
 *                 description: Admin role
 *                 example: Super Admin
 *               action:
 *                 type: string
 *                 description: Action description
 *                 example: Updated Offer #145
 *               actionType:
 *                 type: string
 *                 enum: [create, update, delete, approve, reject, login, logout, system, other]
 *                 example: update
 *               module:
 *                 type: string
 *                 enum: [users, offers, categories, leads, withdrawals, notifications, queries, slides, wallet, system, authentication, other]
 *                 example: offers
 *               severity:
 *                 type: string
 *                 enum: [info, success, warning, error]
 *                 example: info
 *               ipAddress:
 *                 type: string
 *                 example: 192.168.1.100
 *               userAgent:
 *                 type: string
 *               details:
 *                 type: string
 *                 example: Modified offer title and description...
 *               metadata:
 *                 type: object
 *               targetId:
 *                 type: string
 *               targetType:
 *                 type: string
 *               status:
 *                 type: string
 *                 enum: [success, failed, pending]
 *                 example: success
 *               errorMessage:
 *                 type: string
 *     responses:
 *       201:
 *         description: Log created successfully
 *       400:
 *         description: Validation error
 *       500:
 *         description: Server error
 */
router.post('/', createAdminLog);

/**
 * @swagger
 * /api/adminlogs/{id}:
 *   delete:
 *     summary: Delete admin log
 *     description: Delete a single admin log by ID
 *     tags: [Admin Logs]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Log ID (MongoDB _id or logId)
 *     responses:
 *       200:
 *         description: Log deleted successfully
 *       404:
 *         description: Log not found
 *       500:
 *         description: Server error
 */
router.delete('/:id', deleteAdminLog);

/**
 * @swagger
 * /api/adminlogs/bulk-delete:
 *   post:
 *     summary: Bulk delete admin logs
 *     description: Delete multiple admin logs at once
 *     tags: [Admin Logs]
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
 *                 description: Array of log IDs to delete
 *                 example: ["LOG-123-456", "LOG-789-012"]
 *     responses:
 *       200:
 *         description: Logs deleted successfully
 *       400:
 *         description: Invalid request
 *       500:
 *         description: Server error
 */
router.post('/bulk-delete', bulkDeleteAdminLogs);

/**
 * @swagger
 * /api/adminlogs/clear-old:
 *   post:
 *     summary: Clear old logs
 *     description: Delete logs older than specified number of days
 *     tags: [Admin Logs]
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               days:
 *                 type: integer
 *                 default: 90
 *                 description: Delete logs older than this many days
 *                 example: 90
 *     responses:
 *       200:
 *         description: Old logs cleared successfully
 *       500:
 *         description: Server error
 */
router.post('/clear-old', clearOldLogs);

module.exports = router;
