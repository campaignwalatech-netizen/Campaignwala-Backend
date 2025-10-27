const Withdrawal = require('./withdrawal.model');
const Wallet = require('../wallet/wallet.model');
const User = require('../users/user.model');

// Create withdrawal request
const createWithdrawalRequest = async (req, res) => {
  try {
    const { userId, amount, bankDetails } = req.body;

    // Validate required fields
    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID or amount'
      });
    }

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check wallet balance
    let wallet = await Wallet.findOne({ userId });
    if (!wallet) {
      return res.status(404).json({
        success: false,
        message: 'Wallet not found'
      });
    }

    if (wallet.balance < amount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance',
        data: {
          requested: amount,
          available: wallet.balance
        }
      });
    }

    // Create withdrawal request
    const withdrawal = await Withdrawal.create({
      userId,
      amount,
      status: 'pending',
      reason: 'Awaiting admin approval',
      bankDetails: bankDetails || {}
    });

    await withdrawal.populate('userId', 'name email phoneNumber');

    res.status(201).json({
      success: true,
      message: 'Withdrawal request created successfully',
      data: withdrawal
    });
  } catch (error) {
    console.error('Error creating withdrawal request:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create withdrawal request',
      error: error.message
    });
  }
};

// Get all withdrawal requests (Admin)
const getAllWithdrawals = async (req, res) => {
  try {
    const { 
      status, 
      search,
      userId,
      page = 1, 
      limit = 100,
      sortBy = 'requestDate',
      order = 'desc'
    } = req.query;

    // Build filter object
    const filter = {};
    
    if (status && status !== 'all') {
      filter.status = status;
    }

    if (userId) {
      filter.userId = userId;
    }

    if (search) {
      filter.$or = [
        { withdrawalId: { $regex: search, $options: 'i' } },
        { transactionId: { $regex: search, $options: 'i' } }
      ];
    }

    // Calculate pagination
    const skip = (page - 1) * limit;
    const sortOrder = order === 'asc' ? 1 : -1;

    // Get withdrawals with pagination
    const withdrawals = await Withdrawal.find(filter)
      .populate('userId', 'name email phoneNumber')
      .populate('processedBy', 'name email')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Withdrawal.countDocuments(filter);

    res.status(200).json({
      success: true,
      message: 'Withdrawals retrieved successfully',
      data: {
        withdrawals,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    console.error('Error fetching withdrawals:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch withdrawals',
      error: error.message
    });
  }
};

// Get withdrawal by ID
const getWithdrawalById = async (req, res) => {
  try {
    const { id } = req.params;

    const withdrawal = await Withdrawal.findById(id)
      .populate('userId', 'name email phoneNumber')
      .populate('processedBy', 'name email');

    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message: 'Withdrawal not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Withdrawal retrieved successfully',
      data: withdrawal
    });
  } catch (error) {
    console.error('Error fetching withdrawal:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch withdrawal',
      error: error.message
    });
  }
};

// Get withdrawals by user ID
const getWithdrawalsByUserId = async (req, res) => {
  try {
    const { userId } = req.params;
    const { 
      status,
      page = 1, 
      limit = 100,
      sortBy = 'requestDate',
      order = 'desc'
    } = req.query;

    // Build filter
    const filter = { userId };
    
    if (status && status !== 'all') {
      filter.status = status;
    }

    // Calculate pagination
    const skip = (page - 1) * limit;
    const sortOrder = order === 'asc' ? 1 : -1;

    // Get withdrawals
    const withdrawals = await Withdrawal.find(filter)
      .populate('processedBy', 'name email')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Withdrawal.countDocuments(filter);

    res.status(200).json({
      success: true,
      message: 'Withdrawals retrieved successfully',
      data: {
        withdrawals,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    console.error('Error fetching user withdrawals:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch withdrawals',
      error: error.message
    });
  }
};

// Approve withdrawal request (Admin)
const approveWithdrawal = async (req, res) => {
  try {
    const { id } = req.params;
    const { adminId, transactionId, remarks } = req.body;

    // Find withdrawal
    const withdrawal = await Withdrawal.findById(id);
    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message: 'Withdrawal not found'
      });
    }

    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: `Withdrawal is already ${withdrawal.status}`
      });
    }

    // Check wallet balance again
    const wallet = await Wallet.findOne({ userId: withdrawal.userId });
    if (!wallet || wallet.balance < withdrawal.amount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient wallet balance',
        data: {
          requested: withdrawal.amount,
          available: wallet?.balance || 0
        }
      });
    }

    // Deduct from wallet
    wallet.balance -= withdrawal.amount;
    wallet.totalWithdrawn += withdrawal.amount;
    wallet.transactions.push({
      type: 'debit',
      amount: withdrawal.amount,
      description: `Withdrawal approved - ${withdrawal.withdrawalId}`
    });
    await wallet.save();

    // Update withdrawal
    withdrawal.status = 'approved';
    withdrawal.processedDate = new Date();
    withdrawal.processedBy = adminId || null;
    withdrawal.transactionId = transactionId || '';
    withdrawal.reason = 'Processed successfully';
    withdrawal.remarks = remarks || '';
    await withdrawal.save();

    await withdrawal.populate('userId', 'name email phoneNumber');
    await withdrawal.populate('processedBy', 'name email');

    res.status(200).json({
      success: true,
      message: 'Withdrawal approved successfully',
      data: withdrawal
    });
  } catch (error) {
    console.error('Error approving withdrawal:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve withdrawal',
      error: error.message
    });
  }
};

// Reject withdrawal request (Admin)
const rejectWithdrawal = async (req, res) => {
  try {
    const { id } = req.params;
    const { adminId, rejectionReason, remarks } = req.body;

    if (!rejectionReason) {
      return res.status(400).json({
        success: false,
        message: 'Rejection reason is required'
      });
    }

    // Find withdrawal
    const withdrawal = await Withdrawal.findById(id);
    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message: 'Withdrawal not found'
      });
    }

    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: `Withdrawal is already ${withdrawal.status}`
      });
    }

    // Update withdrawal
    withdrawal.status = 'rejected';
    withdrawal.processedDate = new Date();
    withdrawal.processedBy = adminId || null;
    withdrawal.rejectionReason = rejectionReason;
    withdrawal.reason = rejectionReason;
    withdrawal.remarks = remarks || '';
    await withdrawal.save();

    await withdrawal.populate('userId', 'name email phoneNumber');
    await withdrawal.populate('processedBy', 'name email');

    res.status(200).json({
      success: true,
      message: 'Withdrawal rejected successfully',
      data: withdrawal
    });
  } catch (error) {
    console.error('Error rejecting withdrawal:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject withdrawal',
      error: error.message
    });
  }
};

// Delete withdrawal request
const deleteWithdrawal = async (req, res) => {
  try {
    const { id } = req.params;

    const withdrawal = await Withdrawal.findByIdAndDelete(id);

    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message: 'Withdrawal not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Withdrawal deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting withdrawal:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete withdrawal',
      error: error.message
    });
  }
};

// Get withdrawal statistics
const getWithdrawalStats = async (req, res) => {
  try {
    const totalRequests = await Withdrawal.countDocuments();
    const pendingRequests = await Withdrawal.countDocuments({ status: 'pending' });
    const approvedRequests = await Withdrawal.countDocuments({ status: 'approved' });
    const rejectedRequests = await Withdrawal.countDocuments({ status: 'rejected' });

    // Calculate total amounts
    const approvedWithdrawals = await Withdrawal.find({ status: 'approved' });
    const totalApprovedAmount = approvedWithdrawals.reduce((sum, w) => sum + w.amount, 0);

    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' });
    const totalPendingAmount = pendingWithdrawals.reduce((sum, w) => sum + w.amount, 0);

    res.status(200).json({
      success: true,
      data: {
        totalRequests,
        pendingRequests,
        approvedRequests,
        rejectedRequests,
        totalApprovedAmount,
        totalPendingAmount
      }
    });
  } catch (error) {
    console.error('Error fetching withdrawal stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch withdrawal statistics',
      error: error.message
    });
  }
};

module.exports = {
  createWithdrawalRequest,
  getAllWithdrawals,
  getWithdrawalById,
  getWithdrawalsByUserId,
  approveWithdrawal,
  rejectWithdrawal,
  deleteWithdrawal,
  getWithdrawalStats
};
