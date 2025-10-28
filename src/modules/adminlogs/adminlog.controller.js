const AdminLog = require('./adminlog.model');
const User = require('../users/user.model');

/**
 * Get all admin logs with filters and search
 */
const getAllAdminLogs = async (req, res) => {
  try {
    const {
      severity,
      actionType,
      module,
      status,
      adminId,
      search,
      startDate,
      endDate,
      page = 1,
      limit = 100,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    // Build query
    const query = {};

    if (severity) {
      query.severity = severity;
    }

    if (actionType) {
      query.actionType = actionType;
    }

    if (module) {
      query.module = module;
    }

    if (status) {
      query.status = status;
    }

    if (adminId) {
      query.adminId = adminId;
    }

    // Date range filter
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) {
        query.createdAt.$gte = new Date(startDate);
      }
      if (endDate) {
        query.createdAt.$lte = new Date(endDate);
      }
    }

    // Text search
    if (search) {
      query.$text = { $search: search };
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sort = {};
    sort[sortBy] = sortOrder === 'asc' ? 1 : -1;

    // Execute query
    const logs = await AdminLog.find(query)
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .populate('adminId', 'name email role')
      .lean();

    // Get total count
    const total = await AdminLog.countDocuments(query);

    res.status(200).json({
      success: true,
      data: {
        logs,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(total / parseInt(limit)),
          totalLogs: total,
          limit: parseInt(limit),
          hasNextPage: parseInt(page) < Math.ceil(total / parseInt(limit)),
          hasPreviousPage: parseInt(page) > 1
        }
      }
    });
  } catch (error) {
    console.error('Error fetching admin logs:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch admin logs',
      error: error.message
    });
  }
};

/**
 * Get admin log by ID
 */
const getAdminLogById = async (req, res) => {
  try {
    const { id } = req.params;

    // Find by MongoDB _id or logId
    const log = await AdminLog.findOne({
      $or: [{ _id: id }, { logId: id }]
    }).populate('adminId', 'name email role');

    if (!log) {
      return res.status(404).json({
        success: false,
        message: 'Admin log not found'
      });
    }

    res.status(200).json({
      success: true,
      data: log
    });
  } catch (error) {
    console.error('Error fetching admin log:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch admin log',
      error: error.message
    });
  }
};

/**
 * Create admin log entry
 */
const createAdminLog = async (req, res) => {
  try {
    const {
      adminId,
      adminName,
      adminRole,
      action,
      actionType,
      module,
      severity,
      ipAddress,
      userAgent,
      details,
      metadata,
      targetId,
      targetType,
      status,
      errorMessage
    } = req.body;

    // Validation
    if (!adminName || !action) {
      return res.status(400).json({
        success: false,
        message: 'Admin name and action are required'
      });
    }

    // Create log
    const log = new AdminLog({
      adminId,
      adminName,
      adminRole,
      action,
      actionType,
      module,
      severity,
      ipAddress,
      userAgent,
      details,
      metadata,
      targetId,
      targetType,
      status,
      errorMessage
    });

    await log.save();

    res.status(201).json({
      success: true,
      message: 'Admin log created successfully',
      data: log
    });
  } catch (error) {
    console.error('Error creating admin log:', error);
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to create admin log',
      error: error.message
    });
  }
};

/**
 * Delete admin log
 */
const deleteAdminLog = async (req, res) => {
  try {
    const { id } = req.params;

    // Find and delete by MongoDB _id or logId
    const log = await AdminLog.findOneAndDelete({
      $or: [{ _id: id }, { logId: id }]
    });

    if (!log) {
      return res.status(404).json({
        success: false,
        message: 'Admin log not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Admin log deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting admin log:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete admin log',
      error: error.message
    });
  }
};

/**
 * Get admin log statistics
 */
const getAdminLogStats = async (req, res) => {
  try {
    const total = await AdminLog.countDocuments();
    
    // Count by severity
    const bySeverity = await AdminLog.aggregate([
      { $group: { _id: '$severity', count: { $sum: 1 } } }
    ]);

    // Count by action type
    const byActionType = await AdminLog.aggregate([
      { $group: { _id: '$actionType', count: { $sum: 1 } } }
    ]);

    // Count by module
    const byModule = await AdminLog.aggregate([
      { $group: { _id: '$module', count: { $sum: 1 } } }
    ]);

    // Count by status
    const byStatus = await AdminLog.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);

    // Recent activity (last 24 hours)
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentActivity = await AdminLog.countDocuments({
      createdAt: { $gte: yesterday }
    });

    // Most active admins
    const mostActiveAdmins = await AdminLog.aggregate([
      { $group: { _id: '$adminName', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    res.status(200).json({
      success: true,
      data: {
        total,
        recentActivity,
        bySeverity: bySeverity.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        byActionType: byActionType.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        byModule: byModule.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        byStatus: byStatus.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        mostActiveAdmins
      }
    });
  } catch (error) {
    console.error('Error fetching admin log stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch statistics',
      error: error.message
    });
  }
};

/**
 * Get logs by admin ID
 */
const getLogsByAdminId = async (req, res) => {
  try {
    const { adminId } = req.params;
    const { page = 1, limit = 50, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

    const query = { adminId };

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sort = {};
    sort[sortBy] = sortOrder === 'asc' ? 1 : -1;

    const logs = await AdminLog.find(query)
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await AdminLog.countDocuments(query);

    res.status(200).json({
      success: true,
      data: {
        logs,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(total / parseInt(limit)),
          totalLogs: total,
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('Error fetching admin logs by admin ID:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch logs',
      error: error.message
    });
  }
};

/**
 * Bulk delete admin logs
 */
const bulkDeleteAdminLogs = async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an array of log IDs to delete'
      });
    }

    // Delete logs by _id or logId
    const result = await AdminLog.deleteMany({
      $or: [
        { _id: { $in: ids } },
        { logId: { $in: ids } }
      ]
    });

    res.status(200).json({
      success: true,
      message: `Successfully deleted ${result.deletedCount} log(s)`,
      deletedCount: result.deletedCount
    });
  } catch (error) {
    console.error('Error bulk deleting admin logs:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete logs',
      error: error.message
    });
  }
};

/**
 * Clear old logs (older than specified days)
 */
const clearOldLogs = async (req, res) => {
  try {
    const { days = 90 } = req.body;

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - parseInt(days));

    const result = await AdminLog.deleteMany({
      createdAt: { $lt: cutoffDate }
    });

    res.status(200).json({
      success: true,
      message: `Successfully deleted logs older than ${days} days`,
      deletedCount: result.deletedCount
    });
  } catch (error) {
    console.error('Error clearing old logs:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to clear old logs',
      error: error.message
    });
  }
};

module.exports = {
  getAllAdminLogs,
  getAdminLogById,
  createAdminLog,
  deleteAdminLog,
  getAdminLogStats,
  getLogsByAdminId,
  bulkDeleteAdminLogs,
  clearOldLogs
};
