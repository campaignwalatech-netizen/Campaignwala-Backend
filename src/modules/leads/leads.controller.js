const Lead = require('./leads.model');
const Offer = require('../offers/offers.model');
const User = require('../users/user.model'); // Import User model
const Wallet = require('../wallet/wallet.model'); // Import Wallet model

// Get all leads with filters
const getAllLeads = async (req, res) => {
  try {
    const { 
      status, 
      search, 
      hrUserId,
      page = 1, 
      limit = 100,
      sortBy = 'createdAt',
      order = 'desc'
    } = req.query;

    // Build filter object
    const filter = {};
    
    if (status && status !== 'all') {
      filter.status = status.toLowerCase();
    }

    if (hrUserId) {
      filter.hrUserId = hrUserId;
    }

    if (search) {
      filter.$or = [
        { leadId: { $regex: search, $options: 'i' } },
        { offerName: { $regex: search, $options: 'i' } },
        { category: { $regex: search, $options: 'i' } },
        { hrName: { $regex: search, $options: 'i' } },
        { customerName: { $regex: search, $options: 'i' } },
        { customerContact: { $regex: search, $options: 'i' } }
      ];
    }

    // Calculate pagination
    const skip = (page - 1) * limit;
    const sortOrder = order === 'asc' ? 1 : -1;

    // Get leads with pagination
    const leads = await Lead.find(filter)
      .populate('offerId', 'name category commission1 image')
      .populate('hrUserId', 'name email phone')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Lead.countDocuments(filter);

    res.status(200).json({
      success: true,
      message: 'Leads retrieved successfully',
      data: {
        leads,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching leads',
      error: error.message
    });
  }
};

// Get lead by ID
const getLeadById = async (req, res) => {
  try {
    const lead = await Lead.findById(req.params.id)
      .populate('offerId')
      .populate('hrUserId', 'name email phone');

    if (!lead) {
      return res.status(404).json({
        success: false,
        message: 'Lead not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Lead retrieved successfully',
      data: lead
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching lead',
      error: error.message
    });
  }
};

// Create new lead (from shared link)
const createLead = async (req, res) => {
  try {
    const {
      offerId,
      hrUserId,
      customerName,
      customerContact
    } = req.body;

    // Validate required fields
    if (!offerId || !hrUserId || !customerName || !customerContact) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: offerId, hrUserId, customerName, customerContact'
      });
    }

    // Get offer details
    const offer = await Offer.findById(offerId);
    if (!offer) {
      return res.status(404).json({
        success: false,
        message: 'Offer not found'
      });
    }

    // Get HR user details automatically
    const hrUser = await User.findById(hrUserId);
    if (!hrUser) {
      return res.status(404).json({
        success: false,
        message: 'HR User not found'
      });
    }

    console.log('🔍 HR User Details:', {
      id: hrUser._id,
      name: hrUser.name,
      phone: hrUser.phoneNumber,
      email: hrUser.email
    });

    // Create new lead with auto-fetched HR details
    const newLead = new Lead({
      offerId: offer._id,
      offerName: offer.name,
      category: offer.category,
      hrUserId: hrUser._id,
      hrName: hrUser.name || 'User',
      hrContact: hrUser.phoneNumber || hrUser.phone || 'N/A',
      customerName,
      customerContact,
      offer: offer.commission1 || '',
      commission1: offer.commission1 || 0,
      commission2: offer.commission2 || 0,
      status: 'pending'
    });

    await newLead.save();

    res.status(201).json({
      success: true,
      message: 'Lead created successfully',
      data: newLead
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error creating lead',
      error: error.message
    });
  }
};

// Update lead status
const updateLeadStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, remarks, rejectionReason } = req.body;

    const validStatuses = ['pending', 'approved', 'completed', 'rejected'];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status. Must be one of: pending, approved, completed, rejected'
      });
    }

    const updateData = {};
    if (status) updateData.status = status;
    if (remarks) updateData.remarks = remarks;
    if (rejectionReason) updateData.rejectionReason = rejectionReason;

    const lead = await Lead.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!lead) {
      return res.status(404).json({
        success: false,
        message: 'Lead not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Lead updated successfully',
      data: lead
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating lead',
      error: error.message
    });
  }
};

// Delete lead
const deleteLead = async (req, res) => {
  try {
    const lead = await Lead.findByIdAndDelete(req.params.id);

    if (!lead) {
      return res.status(404).json({
        success: false,
        message: 'Lead not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Lead deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting lead',
      error: error.message
    });
  }
};

// Get lead statistics
const getLeadStats = async (req, res) => {
  try {
    const { hrUserId } = req.query;
    const filter = hrUserId ? { hrUserId } : {};

    const stats = await Lead.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    const total = await Lead.countDocuments(filter);

    const formattedStats = {
      total,
      pending: 0,
      approved: 0,
      completed: 0,
      rejected: 0
    };

    stats.forEach(stat => {
      formattedStats[stat._id] = stat.count;
    });

    res.status(200).json({
      success: true,
      message: 'Lead statistics retrieved successfully',
      data: formattedStats
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching lead statistics',
      error: error.message
    });
  }
};

// Approve lead (change status to approved)
const approveLead = async (req, res) => {
  try {
    const { id } = req.params;
    
    const lead = await Lead.findById(id);

    if (!lead) {
      return res.status(404).json({
        success: false,
        message: 'Lead not found'
      });
    }

    let commissionToAdd = 0;
    let commissionMessage = '';
    let newStatus = lead.status;

    // Check current status and determine what commission to pay
    if (lead.status === 'pending' && !lead.commission1Paid) {
      // First approval - Pay Commission 1
      commissionToAdd = lead.commission1 || 0;
      lead.commission1Paid = true;
      
      // Check if Commission 2 exists
      if (lead.commission2 && lead.commission2 > 0) {
        // Has Commission 2, so move to "approved" status
        newStatus = 'approved';
        commissionMessage = `Commission 1 (₹${commissionToAdd}) credited. Approve again for Commission 2.`;
      } else {
        // No Commission 2, directly move to "completed"
        newStatus = 'completed';
        commissionMessage = `Commission 1 (₹${commissionToAdd}) credited. Lead completed.`;
      }
      
    } else if (lead.status === 'approved' && !lead.commission2Paid) {
      // Second approval - Pay Commission 2
      commissionToAdd = lead.commission2 || 0;
      lead.commission2Paid = true;
      newStatus = 'completed';
      commissionMessage = `Commission 2 (₹${commissionToAdd}) credited. Lead completed.`;
      
    } else {
      return res.status(400).json({
        success: false,
        message: 'Lead already fully approved or no commission pending'
      });
    }

    // Update lead status
    lead.status = newStatus;
    
    // Add commission to HR user's wallet
    if (commissionToAdd > 0) {
      let wallet = await Wallet.findOne({ userId: lead.hrUserId });
      
      // Create wallet if doesn't exist
      if (!wallet) {
        wallet = new Wallet({ userId: lead.hrUserId });
      }

      // Add commission as credit
      wallet.balance += commissionToAdd;
      wallet.totalEarned += commissionToAdd;
      wallet.transactions.push({
        type: 'credit',
        amount: commissionToAdd,
        description: `${lead.commission1Paid && !lead.commission2Paid ? 'Commission 1' : 'Commission 2'} from lead ${lead.leadId} - ${lead.offerName}`,
        leadId: lead._id
      });

      await wallet.save();

      console.log(`✅ Added ₹${commissionToAdd} to HR User ${lead.hrUserId} wallet`);
      console.log(`📊 New balance: ₹${wallet.balance}`);
    }

    // Save lead changes
    await lead.save();

    res.status(200).json({
      success: true,
      message: commissionMessage,
      data: {
        lead,
        commissionPaid: commissionToAdd,
        newStatus: newStatus,
        commission1Paid: lead.commission1Paid,
        commission2Paid: lead.commission2Paid
      }
    });
  } catch (error) {
    console.error('Error approving lead:', error);
    res.status(500).json({
      success: false,
      message: 'Error approving lead',
      error: error.message
    });
  }
};

// Reject lead
const rejectLead = async (req, res) => {
  try {
    const { id } = req.params;
    const { rejectionReason } = req.body;

    const lead = await Lead.findByIdAndUpdate(
      id,
      { 
        status: 'rejected',
        rejectionReason: rejectionReason || ''
      },
      { new: true }
    );

    if (!lead) {
      return res.status(404).json({
        success: false,
        message: 'Lead not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Lead rejected successfully',
      data: lead
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error rejecting lead',
      error: error.message
    });
  }
};

module.exports = {
  getAllLeads,
  getLeadById,
  createLead,
  updateLeadStatus,
  deleteLead,
  getLeadStats,
  approveLead,
  rejectLead
};
