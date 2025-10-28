const Query = require('./query.model');
const User = require('../users/user.model');

/**
 * Get all queries with filters and search
 */
const getAllQueries = async (req, res) => {
  try {
    const {
      status,
      priority,
      category,
      search,
      user,
      email,
      page = 1,
      limit = 100,
      sortBy = 'createdAt',
      order = 'desc'
    } = req.query;

    // Build query
    const query = {};

    if (status && status !== 'all') {
      query.status = status;
    }

    if (priority && priority !== 'all') {
      query.priority = priority;
    }

    if (category && category !== 'all') {
      query.category = category;
    }

    if (user) {
      query.user = { $regex: user, $options: 'i' };
    }

    if (email) {
      query.email = { $regex: email, $options: 'i' };
    }

    if (search && search.trim() !== '') {
      query.$or = [
        { user: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { subject: { $regex: search, $options: 'i' } },
        { message: { $regex: search, $options: 'i' } },
        { queryId: { $regex: search, $options: 'i' } }
      ];
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOrder = order === 'desc' ? -1 : 1;

    // Execute query
    const queries = await Query.find(query)
      .populate('userId', 'name email phoneNumber')
      .populate('replies.repliedBy', 'name email')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await Query.countDocuments(query);

    res.status(200).json({
      success: true,
      message: 'Queries retrieved successfully',
      data: {
        queries,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / parseInt(limit))
        }
      }
    });
  } catch (error) {
    console.error('Error fetching queries:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch queries',
      error: error.message
    });
  }
};

/**
 * Get query by ID
 */
const getQueryById = async (req, res) => {
  try {
    const { id } = req.params;

    const query = await Query.findById(id)
      .populate('userId', 'name email phoneNumber')
      .populate('replies.repliedBy', 'name email')
      .lean();

    if (!query) {
      return res.status(404).json({
        success: false,
        message: 'Query not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Query retrieved successfully',
      data: query
    });
  } catch (error) {
    console.error('Error fetching query:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch query',
      error: error.message
    });
  }
};

/**
 * Create new query
 */
const createQuery = async (req, res) => {
  try {
    const {
      user,
      userId,
      email,
      subject,
      message,
      priority = 'Medium',
      category = 'General',
      attachments = []
    } = req.body;

    // Validate required fields
    if (!user || !email || !subject || !message) {
      return res.status(400).json({
        success: false,
        message: 'User, email, subject, and message are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Create query
    const newQuery = await Query.create({
      user,
      userId,
      email,
      subject,
      message,
      priority,
      category,
      attachments,
      status: 'Open',
      hasReplied: false,
      replies: []
    });

    await newQuery.populate('userId', 'name email phoneNumber');

    res.status(201).json({
      success: true,
      message: 'Query created successfully',
      data: newQuery
    });
  } catch (error) {
    console.error('Error creating query:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        error: Object.values(error.errors).map(err => err.message)
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to create query',
      error: error.message
    });
  }
};

/**
 * Update query
 */
const updateQuery = async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // Don't allow updating certain fields
    delete updates.queryId;
    delete updates.createdAt;
    delete updates.replies;

    const query = await Query.findByIdAndUpdate(
      id,
      { ...updates, updatedAt: Date.now() },
      { new: true, runValidators: true }
    )
      .populate('userId', 'name email phoneNumber')
      .populate('replies.repliedBy', 'name email');

    if (!query) {
      return res.status(404).json({
        success: false,
        message: 'Query not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Query updated successfully',
      data: query
    });
  } catch (error) {
    console.error('Error updating query:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        error: Object.values(error.errors).map(err => err.message)
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to update query',
      error: error.message
    });
  }
};

/**
 * Delete query
 */
const deleteQuery = async (req, res) => {
  try {
    const { id } = req.params;

    const query = await Query.findByIdAndDelete(id);

    if (!query) {
      return res.status(404).json({
        success: false,
        message: 'Query not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Query deleted successfully',
      data: query
    });
  } catch (error) {
    console.error('Error deleting query:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete query',
      error: error.message
    });
  }
};

/**
 * Add reply to query
 */
const addReply = async (req, res) => {
  try {
    const { id } = req.params;
    const { message, repliedBy, repliedByName = 'Admin' } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Reply message is required'
      });
    }

    const query = await Query.findById(id);

    if (!query) {
      return res.status(404).json({
        success: false,
        message: 'Query not found'
      });
    }

    // Add reply
    query.replies.push({
      message: message.trim(),
      repliedBy,
      repliedByName,
      date: new Date()
    });

    query.hasReplied = true;
    if (query.status === 'Open') {
      query.status = 'Replied';
    }

    await query.save();

    await query.populate('userId', 'name email phoneNumber');
    await query.populate('replies.repliedBy', 'name email');

    res.status(200).json({
      success: true,
      message: 'Reply added successfully',
      data: query
    });
  } catch (error) {
    console.error('Error adding reply:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add reply',
      error: error.message
    });
  }
};

/**
 * Update query status
 */
const updateQueryStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status || !['Open', 'Replied', 'Closed'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Valid status is required (Open, Replied, or Closed)'
      });
    }

    const query = await Query.findById(id);

    if (!query) {
      return res.status(404).json({
        success: false,
        message: 'Query not found'
      });
    }

    query.status = status;

    if (status === 'Closed') {
      query.isResolved = true;
      query.resolvedAt = new Date();
      if (req.user) {
        query.resolvedBy = req.user._id;
      }
    } else {
      query.isResolved = false;
      query.resolvedAt = null;
      query.resolvedBy = null;
    }

    await query.save();

    await query.populate('userId', 'name email phoneNumber');
    await query.populate('replies.repliedBy', 'name email');

    res.status(200).json({
      success: true,
      message: 'Query status updated successfully',
      data: query
    });
  } catch (error) {
    console.error('Error updating query status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update query status',
      error: error.message
    });
  }
};

/**
 * Get query statistics
 */
const getQueryStats = async (req, res) => {
  try {
    const total = await Query.countDocuments();
    const byStatus = await Query.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);
    const byPriority = await Query.aggregate([
      { $group: { _id: '$priority', count: { $sum: 1 } } }
    ]);
    const byCategory = await Query.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } }
    ]);

    // Recent queries (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentCount = await Query.countDocuments({
      createdAt: { $gte: sevenDaysAgo }
    });

    // Queries with replies
    const repliedCount = await Query.countDocuments({ hasReplied: true });

    // Resolved queries
    const resolvedCount = await Query.countDocuments({ isResolved: true });

    res.status(200).json({
      success: true,
      message: 'Query statistics retrieved successfully',
      data: {
        total,
        byStatus: byStatus.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        byPriority: byPriority.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        byCategory: byCategory.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        recentCount,
        repliedCount,
        resolvedCount
      }
    });
  } catch (error) {
    console.error('Error fetching query stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch query statistics',
      error: error.message
    });
  }
};

/**
 * Get queries by user email
 */
const getQueriesByEmail = async (req, res) => {
  try {
    const { email } = req.params;
    const { page = 1, limit = 20 } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const queries = await Query.find({ email })
      .populate('userId', 'name email phoneNumber')
      .populate('replies.repliedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await Query.countDocuments({ email });

    res.status(200).json({
      success: true,
      message: 'User queries retrieved successfully',
      data: {
        queries,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / parseInt(limit))
        }
      }
    });
  } catch (error) {
    console.error('Error fetching user queries:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user queries',
      error: error.message
    });
  }
};

/**
 * Bulk delete queries
 */
const bulkDeleteQueries = async (req, res) => {
  try {
    const { ids } = req.body;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an array of query IDs'
      });
    }

    const result = await Query.deleteMany({
      _id: { $in: ids }
    });

    res.status(200).json({
      success: true,
      message: `${result.deletedCount} queries deleted successfully`,
      data: {
        deletedCount: result.deletedCount
      }
    });
  } catch (error) {
    console.error('Error bulk deleting queries:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete queries',
      error: error.message
    });
  }
};

module.exports = {
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
};
