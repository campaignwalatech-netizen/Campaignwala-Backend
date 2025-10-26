const express = require('express');
const router = express.Router();
const {
  getAllLeads,
  getLeadById,
  createLead,
  updateLeadStatus,
  deleteLead,
  getLeadStats,
  approveLead,
  rejectLead
} = require('./leads.controller');

/**
 * @swagger
 * components:
 *   schemas:
 *     Lead:
 *       type: object
 *       required:
 *         - offerId
 *         - hrUserId
 *         - hrName
 *         - hrContact
 *         - customerName
 *         - customerContact
 *       properties:
 *         _id:
 *           type: string
 *           description: Lead MongoDB ID
 *         leadId:
 *           type: string
 *           description: Auto-generated unique Lead ID
 *           example: LD-A3X8K9M2
 *           readOnly: true
 *         offerId:
 *           type: string
 *           description: Reference to Offer
 *         offerName:
 *           type: string
 *           description: Offer name
 *         category:
 *           type: string
 *           description: Offer category
 *         hrUserId:
 *           type: string
 *           description: HR User ID (who shared the link)
 *         hrName:
 *           type: string
 *           description: HR Name
 *         hrContact:
 *           type: string
 *           description: HR Contact Number
 *         customerName:
 *           type: string
 *           description: Customer Name (who filled the form)
 *         customerContact:
 *           type: string
 *           description: Customer Contact Number
 *         status:
 *           type: string
 *           enum: [pending, approved, completed, rejected]
 *           default: pending
 *         offer:
 *           type: string
 *           description: Commission/Offer amount
 *         sharedLink:
 *           type: string
 *           description: Shared link URL
 *         remarks:
 *           type: string
 *           description: Additional remarks
 *         rejectionReason:
 *           type: string
 *           description: Reason for rejection
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 */

/**
 * @swagger
 * /api/leads:
 *   get:
 *     summary: Get all leads
 *     tags: [Leads]
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [all, pending, approved, completed, rejected]
 *         description: Filter by status
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in leadId, offerName, category, hrName, customerName, customerContact
 *       - in: query
 *         name: hrUserId
 *         schema:
 *           type: string
 *         description: Filter by HR User ID
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
 *         description: Leads retrieved successfully
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
 *                     leads:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Lead'
 *                     pagination:
 *                       type: object
 */
router.get('/', getAllLeads);

/**
 * @swagger
 * /api/leads/stats:
 *   get:
 *     summary: Get lead statistics
 *     tags: [Leads]
 *     parameters:
 *       - in: query
 *         name: hrUserId
 *         schema:
 *           type: string
 *         description: Filter stats by HR User ID
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
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     total:
 *                       type: number
 *                     pending:
 *                       type: number
 *                     approved:
 *                       type: number
 *                     completed:
 *                       type: number
 *                     rejected:
 *                       type: number
 */
router.get('/stats', getLeadStats);

/**
 * @swagger
 * /api/leads/{id}:
 *   get:
 *     summary: Get lead by ID
 *     tags: [Leads]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Lead retrieved successfully
 *       404:
 *         description: Lead not found
 */
router.get('/:id', getLeadById);

/**
 * @swagger
 * /api/leads:
 *   post:
 *     summary: Create new lead (from shared link)
 *     tags: [Leads]
 *     description: Creates a new lead when a customer fills the form from a shared link
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - offerId
 *               - hrUserId
 *               - hrName
 *               - hrContact
 *               - customerName
 *               - customerContact
 *             properties:
 *               offerId:
 *                 type: string
 *                 description: Offer ID
 *               hrUserId:
 *                 type: string
 *                 description: HR User ID (who shared the link)
 *               hrName:
 *                 type: string
 *                 description: HR Name
 *               hrContact:
 *                 type: string
 *                 description: HR Contact
 *               customerName:
 *                 type: string
 *                 description: Customer Full Name
 *               customerContact:
 *                 type: string
 *                 description: Customer Phone Number
 *     responses:
 *       201:
 *         description: Lead created successfully
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
 *                   $ref: '#/components/schemas/Lead'
 */
router.post('/', createLead);

/**
 * @swagger
 * /api/leads/{id}:
 *   put:
 *     summary: Update lead status
 *     tags: [Leads]
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
 *               status:
 *                 type: string
 *                 enum: [pending, approved, completed, rejected]
 *               remarks:
 *                 type: string
 *               rejectionReason:
 *                 type: string
 *     responses:
 *       200:
 *         description: Lead updated successfully
 */
router.put('/:id', updateLeadStatus);

/**
 * @swagger
 * /api/leads/{id}:
 *   delete:
 *     summary: Delete lead
 *     tags: [Leads]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Lead deleted successfully
 */
router.delete('/:id', deleteLead);

/**
 * @swagger
 * /api/leads/{id}/approve:
 *   post:
 *     summary: Approve lead
 *     tags: [Leads]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Lead approved successfully
 */
router.post('/:id/approve', approveLead);

/**
 * @swagger
 * /api/leads/{id}/reject:
 *   post:
 *     summary: Reject lead
 *     tags: [Leads]
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
 *               rejectionReason:
 *                 type: string
 *     responses:
 *       200:
 *         description: Lead rejected successfully
 */
router.post('/:id/reject', rejectLead);

module.exports = router;
