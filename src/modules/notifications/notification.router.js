const express = require('express');
const router = express.Router();
const {
  sendNotification,
  getAllNotifications,
  getNotificationById,
  deleteNotification,
  getNotificationStats,
  getUserNotifications,
  bulkDeleteNotifications
} = require('./notification.controller');

/**
 * @swagger
 * components:
 *   schemas:
 *     Notification:
 *       type: object
 *       required:
 *         - type
 *         - title
 *         - message
 *       properties:
 *         _id:
 *           type: string
 *           description: Notification MongoDB ID
 *         notificationId:
 *           type: string
 *           description: Auto-generated unique Notification ID
 *           example: NOTIF-L5X8K9M-ABC
 *           readOnly: true
 *         type:
 *           type: string
 *           enum: [profile, offer, announcement, system]
 *           description: Notification type
 *         title:
 *           type: string
 *           description: Notification title
 *           example: Complete Your Profile
 *         message:
 *           type: string
 *           description: Notification message
 *         recipients:
 *           type: array
 *           items:
 *             type: string
 *           description: Array of user IDs or 'all'
 *         recipientCount:
 *           type: number
 *           description: Number of recipients
 *         targetSegments:
 *           type: array
 *           items:
 *             type: string
 *           description: Target segments for notification
 *         offerDetails:
 *           type: object
 *           properties:
 *             offerTitle:
 *               type: string
 *             discount:
 *               type: string
 *             expiryDate:
 *               type: string
 *               format: date
 *             description:
 *               type: string
 *         status:
 *           type: string
 *           enum: [pending, sent, failed]
 *           default: sent
 *         sentBy:
 *           type: string
 *           description: Admin user ID who sent the notification
 *         sentDate:
 *           type: string
 *           format: date-time
 *         deliveryStats:
 *           type: object
 *           properties:
 *             sent:
 *               type: number
 *             delivered:
 *               type: number
 *             failed:
 *               type: number
 *         metadata:
 *           type: object
 *           properties:
 *             filterBy:
 *               type: string
 *             searchQuery:
 *               type: string
 *             selectedUserIds:
 *               type: array
 *               items:
 *                 type: string
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 */

/**
 * @swagger
 * /api/notifications/send:
 *   post:
 *     summary: Send notification to users
 *     tags: [Notifications]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - type
 *               - title
 *               - message
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [profile, offer, announcement, system]
 *                 example: profile
 *               title:
 *                 type: string
 *                 example: Complete Your Profile
 *               message:
 *                 type: string
 *                 example: Complete your profile to unlock all features
 *               recipients:
 *                 type: array
 *                 items:
 *                   type: string
 *                 example: ["all"]
 *               targetSegments:
 *                 type: array
 *                 items:
 *                   type: string
 *               offerDetails:
 *                 type: object
 *                 properties:
 *                   offerTitle:
 *                     type: string
 *                   discount:
 *                     type: string
 *                   expiryDate:
 *                     type: string
 *                   description:
 *                     type: string
 *               filterBy:
 *                 type: string
 *                 enum: [all, incomplete, active, inactive]
 *                 example: all
 *               searchQuery:
 *                 type: string
 *               selectedUserIds:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       201:
 *         description: Notification sent successfully
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
 *                   example: Notification sent successfully
 *                 data:
 *                   $ref: '#/components/schemas/Notification'
 *       400:
 *         description: Bad request
 *       500:
 *         description: Server error
 */
router.post('/send', sendNotification);

/**
 * @swagger
 * /api/notifications:
 *   get:
 *     summary: Get all notifications with filters
 *     tags: [Notifications]
 *     parameters:
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *           enum: [all, profile, offer, announcement, system]
 *         description: Filter by notification type
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [all, pending, sent, failed]
 *         description: Filter by status
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in title, message, or notification ID
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
 *           default: sentDate
 *         description: Sort field
 *       - in: query
 *         name: order
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *         description: Sort order
 *     responses:
 *       200:
 *         description: Notifications retrieved successfully
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
 *                 data:
 *                   type: object
 *                   properties:
 *                     notifications:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Notification'
 *                     pagination:
 *                       type: object
 *                       properties:
 *                         total:
 *                           type: integer
 *                         page:
 *                           type: integer
 *                         limit:
 *                           type: integer
 *                         pages:
 *                           type: integer
 *       500:
 *         description: Server error
 */
router.get('/', getAllNotifications);

/**
 * @swagger
 * /api/notifications/stats:
 *   get:
 *     summary: Get notification statistics
 *     tags: [Notifications]
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
 *                 data:
 *                   type: object
 *                   properties:
 *                     total:
 *                       type: integer
 *                     byType:
 *                       type: object
 *                     byStatus:
 *                       type: object
 *                     totalRecipients:
 *                       type: integer
 *                     recentCount:
 *                       type: integer
 *       500:
 *         description: Server error
 */
router.get('/stats', getNotificationStats);

/**
 * @swagger
 * /api/notifications/user:
 *   get:
 *     summary: Get notifications for current user
 *     tags: [Notifications]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *         description: Filter by type
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
 *         description: User notifications retrieved
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get('/user', getUserNotifications);

/**
 * @swagger
 * /api/notifications/{id}:
 *   get:
 *     summary: Get notification by ID
 *     tags: [Notifications]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Notification ID
 *     responses:
 *       200:
 *         description: Notification retrieved successfully
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
 *                 data:
 *                   $ref: '#/components/schemas/Notification'
 *       404:
 *         description: Notification not found
 *       500:
 *         description: Server error
 */
router.get('/:id', getNotificationById);

/**
 * @swagger
 * /api/notifications/{id}:
 *   delete:
 *     summary: Delete notification by ID
 *     tags: [Notifications]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Notification ID
 *     responses:
 *       200:
 *         description: Notification deleted successfully
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
 *                 data:
 *                   $ref: '#/components/schemas/Notification'
 *       404:
 *         description: Notification not found
 *       500:
 *         description: Server error
 */
router.delete('/:id', deleteNotification);

/**
 * @swagger
 * /api/notifications/bulk-delete:
 *   post:
 *     summary: Delete multiple notifications
 *     tags: [Notifications]
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
 *                 example: ["123abc", "456def"]
 *     responses:
 *       200:
 *         description: Notifications deleted successfully
 *       400:
 *         description: Bad request
 *       500:
 *         description: Server error
 */
router.post('/bulk-delete', bulkDeleteNotifications);

module.exports = router;
