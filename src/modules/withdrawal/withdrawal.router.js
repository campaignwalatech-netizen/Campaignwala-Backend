const express = require('express');
const router = express.Router();
const {
  createWithdrawalRequest,
  getAllWithdrawals,
  getWithdrawalById,
  getWithdrawalsByUserId,
  approveWithdrawal,
  rejectWithdrawal,
  deleteWithdrawal,
  getWithdrawalStats
} = require('./withdrawal.controller');

/**
 * @swagger
 * components:
 *   schemas:
 *     Withdrawal:
 *       type: object
 *       required:
 *         - userId
 *         - amount
 *       properties:
 *         _id:
 *           type: string
 *           description: Withdrawal MongoDB ID
 *         withdrawalId:
 *           type: string
 *           description: Auto-generated unique Withdrawal ID
 *           example: WDR-L5X8K9M-A1B
 *           readOnly: true
 *         userId:
 *           type: string
 *           description: User ID who requested withdrawal
 *         amount:
 *           type: number
 *           description: Withdrawal amount
 *           example: 500
 *         status:
 *           type: string
 *           enum: [pending, approved, rejected, processing]
 *           default: pending
 *         requestDate:
 *           type: string
 *           format: date-time
 *         processedDate:
 *           type: string
 *           format: date-time
 *         processedBy:
 *           type: string
 *           description: Admin ID who processed the request
 *         reason:
 *           type: string
 *           description: Status reason
 *         rejectionReason:
 *           type: string
 *           description: Reason for rejection
 *         bankDetails:
 *           type: object
 *           properties:
 *             accountHolderName:
 *               type: string
 *             accountNumber:
 *               type: string
 *             ifscCode:
 *               type: string
 *             bankName:
 *               type: string
 *             upiId:
 *               type: string
 *         transactionId:
 *           type: string
 *           description: Transaction ID for approved withdrawal
 *         remarks:
 *           type: string
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 */

/**
 * @swagger
 * /api/withdrawals:
 *   post:
 *     summary: Create withdrawal request
 *     tags: [Withdrawals]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *               - amount
 *             properties:
 *               userId:
 *                 type: string
 *               amount:
 *                 type: number
 *               bankDetails:
 *                 type: object
 *     responses:
 *       201:
 *         description: Withdrawal request created successfully
 *       400:
 *         description: Bad request
 *       404:
 *         description: User or wallet not found
 */
router.post('/', createWithdrawalRequest);

/**
 * @swagger
 * /api/withdrawals:
 *   get:
 *     summary: Get all withdrawal requests (Admin)
 *     tags: [Withdrawals]
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [all, pending, approved, rejected, processing]
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *       - in: query
 *         name: userId
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
 *           default: 100
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           default: requestDate
 *       - in: query
 *         name: order
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *     responses:
 *       200:
 *         description: Withdrawals retrieved successfully
 */
router.get('/', getAllWithdrawals);

/**
 * @swagger
 * /api/withdrawals/stats:
 *   get:
 *     summary: Get withdrawal statistics
 *     tags: [Withdrawals]
 *     responses:
 *       200:
 *         description: Statistics retrieved successfully
 */
router.get('/stats', getWithdrawalStats);

/**
 * @swagger
 * /api/withdrawals/user/{userId}:
 *   get:
 *     summary: Get withdrawals by user ID
 *     tags: [Withdrawals]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: status
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
 *           default: 100
 *     responses:
 *       200:
 *         description: User withdrawals retrieved successfully
 */
router.get('/user/:userId', getWithdrawalsByUserId);

/**
 * @swagger
 * /api/withdrawals/{id}:
 *   get:
 *     summary: Get withdrawal by ID
 *     tags: [Withdrawals]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Withdrawal retrieved successfully
 *       404:
 *         description: Withdrawal not found
 */
router.get('/:id', getWithdrawalById);

/**
 * @swagger
 * /api/withdrawals/{id}/approve:
 *   put:
 *     summary: Approve withdrawal request (Admin)
 *     tags: [Withdrawals]
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
 *               adminId:
 *                 type: string
 *               transactionId:
 *                 type: string
 *               remarks:
 *                 type: string
 *     responses:
 *       200:
 *         description: Withdrawal approved successfully
 *       400:
 *         description: Bad request or insufficient balance
 *       404:
 *         description: Withdrawal not found
 */
router.put('/:id/approve', approveWithdrawal);

/**
 * @swagger
 * /api/withdrawals/{id}/reject:
 *   put:
 *     summary: Reject withdrawal request (Admin)
 *     tags: [Withdrawals]
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
 *               - rejectionReason
 *             properties:
 *               adminId:
 *                 type: string
 *               rejectionReason:
 *                 type: string
 *               remarks:
 *                 type: string
 *     responses:
 *       200:
 *         description: Withdrawal rejected successfully
 *       400:
 *         description: Bad request
 *       404:
 *         description: Withdrawal not found
 */
router.put('/:id/reject', rejectWithdrawal);

/**
 * @swagger
 * /api/withdrawals/{id}:
 *   delete:
 *     summary: Delete withdrawal request
 *     tags: [Withdrawals]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Withdrawal deleted successfully
 *       404:
 *         description: Withdrawal not found
 */
router.delete('/:id', deleteWithdrawal);

module.exports = router;
