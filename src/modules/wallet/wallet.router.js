const express = require('express');
const router = express.Router();
const {
  getWalletByUserId,
  addCredit,
  addDebit,
  getAllWallets
} = require('./wallet.controller');

/**
 * @swagger
 * /api/wallet/user/{userId}:
 *   get:
 *     summary: Get wallet by user ID
 *     tags: [Wallet]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Wallet fetched successfully
 */
router.get('/user/:userId', getWalletByUserId);

/**
 * @swagger
 * /api/wallet/credit:
 *   post:
 *     summary: Add credit to wallet
 *     tags: [Wallet]
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
 *               description:
 *                 type: string
 *               leadId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Credit added successfully
 */
router.post('/credit', addCredit);

/**
 * @swagger
 * /api/wallet/debit:
 *   post:
 *     summary: Deduct amount from wallet
 *     tags: [Wallet]
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
 *               description:
 *                 type: string
 *     responses:
 *       200:
 *         description: Debit processed successfully
 */
router.post('/debit', addDebit);

/**
 * @swagger
 * /api/wallet/all:
 *   get:
 *     summary: Get all wallets (Admin only)
 *     tags: [Wallet]
 *     responses:
 *       200:
 *         description: All wallets fetched successfully
 */
router.get('/all', getAllWallets);

module.exports = router;
