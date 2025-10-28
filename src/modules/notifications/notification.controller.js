const Notification = require('./notification.model');
const User = require('../users/user.model');

/**
 * Send notification to users
 */
const sendNotification = async (req, res) => {
  try {
    const {
      type,
      title,
      message,
      recipients = [],
      targetSegments = [],
      offerDetails = {},
      filterBy = 'all',
      searchQuery = '',
      selectedUserIds = []
    } = req.body;

    // Validate required fields
    if (!type || !title || !message) {
      return res.status(400).json({
        success: false,
        message: 'Type, title, and message are required'
      });
    }

    // Validate type
    const validTypes = ['profile', 'offer', 'announcement', 'system'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid notification type'
      });
    }

    // Determine recipients based on filter
    let recipientList = [];
    let recipientCount = 0;

    if (recipients.includes('all') || filterBy === 'all') {
      // Send to all users
      const allUsers = await User.find({ isActive: true }, '_id');
      recipientList = allUsers.map(user => user._id.toString());
      recipientCount = allUsers.length;
    } else if (selectedUserIds && selectedUserIds.length > 0) {
      // Send to specific selected users
      recipientList = selectedUserIds;
      recipientCount = selectedUserIds.length;
    } else if (filterBy && filterBy !== 'all') {
      // Apply filters based on filterBy parameter
      const query = { isActive: true };
      
      if (filterBy === 'incomplete') {
        // Users with incomplete profiles (missing KYC or basic info)
        query.$or = [
          { 'kyc.isVerified': { $ne: true } },
          { name: { $exists: false } },
          { email: { $exists: false } }
        ];
      } else if (filterBy === 'active') {
        query.isActive = true;
      } else if (filterBy === 'inactive') {
        query.isActive = false;
      }

      // Apply search query if provided
      if (searchQuery && searchQuery.trim() !== '') {
        query.$or = [
          { name: { $regex: searchQuery, $options: 'i' } },
          { email: { $regex: searchQuery, $options: 'i' } },
          { phoneNumber: { $regex: searchQuery, $options: 'i' } }
        ];
      }

      const filteredUsers = await User.find(query, '_id');
      recipientList = filteredUsers.map(user => user._id.toString());
      recipientCount = filteredUsers.length;
    }

    // Create notification
    const notification = await Notification.create({
      type,
      title,
      message,
      recipients: recipientList,
      recipientCount,
      targetSegments,
      offerDetails: type === 'offer' ? offerDetails : undefined,
      status: 'sent',
      sentBy: req.user ? req.user._id : null,
      sentDate: new Date(),
      deliveryStats: {
        sent: recipientCount,
        delivered: recipientCount,
        failed: 0
      },
      metadata: {
        filterBy,
        searchQuery,
        selectedUserIds
      }
    });

    res.status(201).json({
      success: true,
      message: 'Notification sent successfully',
      data: notification
    });
  } catch (error) {
    console.error('Error sending notification:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send notification',
      error: error.message
    });
  }
};

/**
 * Get all notifications with filters and search
 */
const getAllNotifications = async (req, res) => {
  try {
    const {
      type,
      status,
      search,
      page = 1,
      limit = 100,
      sortBy = 'sentDate',
      order = 'desc'
    } = req.query;

    // Build query
    const query = {};

    if (type && type !== 'all') {
      query.type = type;
    }

    if (status && status !== 'all') {
      query.status = status;
    }

    if (search && search.trim() !== '') {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { message: { $regex: search, $options: 'i' } },
        { notificationId: { $regex: search, $options: 'i' } }
      ];
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOrder = order === 'desc' ? -1 : 1;

    // Execute query
    const notifications = await Notification.find(query)
      .populate('sentBy', 'name email')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await Notification.countDocuments(query);

    res.status(200).json({
      success: true,
      message: 'Notifications retrieved successfully',
      data: {
        notifications,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / parseInt(limit))
        }
      }
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch notifications',
      error: error.message
    });
  }
};

/**
 * Get notification by ID
 */
const getNotificationById = async (req, res) => {
  try {
    const { id } = req.params;

    const notification = await Notification.findById(id)
      .populate('sentBy', 'name email')
      .lean();

    if (!notification) {
      return res.status(404).json({
        success: false,
        message: 'Notification not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Notification retrieved successfully',
      data: notification
    });
  } catch (error) {
    console.error('Error fetching notification:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch notification',
      error: error.message
    });
  }
};

/**
 * Delete notification
 */
const deleteNotification = async (req, res) => {
  try {
    const { id } = req.params;

    const notification = await Notification.findByIdAndDelete(id);

    if (!notification) {
      return res.status(404).json({
        success: false,
        message: 'Notification not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Notification deleted successfully',
      data: notification
    });
  } catch (error) {
    console.error('Error deleting notification:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete notification',
      error: error.message
    });
  }
};

/**
 * Get notification statistics
 */
const getNotificationStats = async (req, res) => {
  try {
    const total = await Notification.countDocuments();
    const byType = await Notification.aggregate([
      { $group: { _id: '$type', count: { $sum: 1 } } }
    ]);
    const byStatus = await Notification.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);

    // Total recipients reached
    const totalRecipientsResult = await Notification.aggregate([
      { $group: { _id: null, total: { $sum: '$recipientCount' } } }
    ]);
    const totalRecipients = totalRecipientsResult[0]?.total || 0;

    // Recent notifications (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentCount = await Notification.countDocuments({
      sentDate: { $gte: sevenDaysAgo }
    });

    res.status(200).json({
      success: true,
      message: 'Notification statistics retrieved successfully',
      data: {
        total,
        byType: byType.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        byStatus: byStatus.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        totalRecipients,
        recentCount
      }
    });
  } catch (error) {
    console.error('Error fetching notification stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch notification statistics',
      error: error.message
    });
  }
};

/**
 * Get user notifications (for end users to view their notifications)
 */
const getUserNotifications = async (req, res) => {
  try {
    const userId = req.user._id.toString();
    const {
      type,
      page = 1,
      limit = 20
    } = req.query;

    // Build query - find notifications where user is in recipients or recipients is 'all'
    const query = {
      $or: [
        { recipients: userId },
        { recipients: 'all' },
        { recipients: { $size: 0 } } // Empty array means all users
      ]
    };

    if (type && type !== 'all') {
      query.type = type;
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const notifications = await Notification.find(query)
      .sort({ sentDate: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('-recipients -metadata')
      .lean();

    const total = await Notification.countDocuments(query);

    res.status(200).json({
      success: true,
      message: 'User notifications retrieved successfully',
      data: {
        notifications,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / parseInt(limit))
        }
      }
    });
  } catch (error) {
    console.error('Error fetching user notifications:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user notifications',
      error: error.message
    });
  }
};

/**
 * Bulk delete notifications
 */
const bulkDeleteNotifications = async (req, res) => {
  try {
    const { ids } = req.body;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an array of notification IDs'
      });
    }

    const result = await Notification.deleteMany({
      _id: { $in: ids }
    });

    res.status(200).json({
      success: true,
      message: `${result.deletedCount} notifications deleted successfully`,
      data: {
        deletedCount: result.deletedCount
      }
    });
  } catch (error) {
    console.error('Error bulk deleting notifications:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete notifications',
      error: error.message
    });
  }
};

module.exports = {
  sendNotification,
  getAllNotifications,
  getNotificationById,
  deleteNotification,
  getNotificationStats,
  getUserNotifications,
  bulkDeleteNotifications
};
