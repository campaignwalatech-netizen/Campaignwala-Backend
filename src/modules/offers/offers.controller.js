const Offer = require('./offers.model');

/**
 * Get all offers with optional filtering and pagination
 */
const getAllOffers = async (req, res) => {
  try {
    const { 
      status, 
      category,
      isApproved,
      search, 
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

    if (category && category !== 'all') {
      query.category = category;
    }

    if (isApproved !== undefined) {
      query.isApproved = isApproved === 'true';
    }
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { leadId: { $regex: search, $options: 'i' } },
        { company: { $regex: search, $options: 'i' } }
      ];
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOrder = order === 'desc' ? -1 : 1;

    // Execute query
    const offers = await Offer.find(query)
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await Offer.countDocuments(query);

    res.status(200).json({
      success: true,
      message: 'Offers retrieved successfully',
      data: {
        offers,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / parseInt(limit))
        }
      }
    });
  } catch (error) {
    console.error('Error fetching offers:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch offers',
      error: error.message
    });
  }
};

/**
 * Get offer by ID
 */
const getOfferById = async (req, res) => {
  try {
    const { id } = req.params;

    const offer = await Offer.findById(id).lean();

    if (!offer) {
      return res.status(404).json({
        success: false,
        message: 'Offer not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Offer retrieved successfully',
      data: offer
    });
  } catch (error) {
    console.error('Error fetching offer:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch offer',
      error: error.message
    });
  }
};

/**
 * Create new offer
 */
const createOffer = async (req, res) => {
  try {
    const offerData = req.body;

    // Validate required fields
    if (!offerData.name || !offerData.category) {
      return res.status(400).json({
        success: false,
        message: 'Name and category are required fields'
      });
    }

    // Create offer
    const offer = await Offer.create(offerData);

    res.status(201).json({
      success: true,
      message: 'Offer created successfully',
      data: offer
    });
  } catch (error) {
    console.error('Error creating offer:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        error: Object.values(error.errors).map(e => e.message).join(', ')
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to create offer',
      error: error.message
    });
  }
};

/**
 * Update offer
 */
const updateOffer = async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;

    // Check if offer exists
    const offer = await Offer.findById(id);

    if (!offer) {
      return res.status(404).json({
        success: false,
        message: 'Offer not found'
      });
    }

    // Update offer
    Object.keys(updateData).forEach(key => {
      offer[key] = updateData[key];
    });

    await offer.save();

    res.status(200).json({
      success: true,
      message: 'Offer updated successfully',
      data: offer
    });
  } catch (error) {
    console.error('Error updating offer:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        error: Object.values(error.errors).map(e => e.message).join(', ')
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to update offer',
      error: error.message
    });
  }
};

/**
 * Delete offer
 */
const deleteOffer = async (req, res) => {
  try {
    const { id } = req.params;

    const offer = await Offer.findById(id);

    if (!offer) {
      return res.status(404).json({
        success: false,
        message: 'Offer not found'
      });
    }

    await Offer.findByIdAndDelete(id);

    res.status(200).json({
      success: true,
      message: 'Offer deleted successfully',
      data: { id }
    });
  } catch (error) {
    console.error('Error deleting offer:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete offer',
      error: error.message
    });
  }
};

/**
 * Approve offer
 */
const approveOffer = async (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.body; // From auth middleware in production

    const offer = await Offer.findById(id);

    if (!offer) {
      return res.status(404).json({
        success: false,
        message: 'Offer not found'
      });
    }

    offer.isApproved = true;
    offer.approvedBy = userId || null;
    offer.approvedAt = new Date();
    offer.status = 'Active';

    await offer.save();

    res.status(200).json({
      success: true,
      message: 'Offer approved successfully',
      data: offer
    });
  } catch (error) {
    console.error('Error approving offer:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve offer',
      error: error.message
    });
  }
};

/**
 * Reject offer
 */
const rejectOffer = async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    const offer = await Offer.findById(id);

    if (!offer) {
      return res.status(404).json({
        success: false,
        message: 'Offer not found'
      });
    }

    offer.isApproved = false;
    offer.status = 'Rejected';
    offer.rejectionReason = reason || 'No reason provided';

    await offer.save();

    res.status(200).json({
      success: true,
      message: 'Offer rejected successfully',
      data: offer
    });
  } catch (error) {
    console.error('Error rejecting offer:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject offer',
      error: error.message
    });
  }
};

/**
 * Get offer statistics
 */
const getOfferStats = async (req, res) => {
  try {
    const totalOffers = await Offer.countDocuments();
    const activeOffers = await Offer.countDocuments({ status: 'Active' });
    const pendingOffers = await Offer.countDocuments({ status: 'Pending' });
    const approvedOffers = await Offer.countDocuments({ isApproved: true });
    const rejectedOffers = await Offer.countDocuments({ status: 'Rejected' });

    // Get category breakdown
    const categoryStats = await Offer.aggregate([
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    res.status(200).json({
      success: true,
      message: 'Offer statistics retrieved successfully',
      data: {
        total: totalOffers,
        active: activeOffers,
        pending: pendingOffers,
        approved: approvedOffers,
        rejected: rejectedOffers,
        byCategory: categoryStats
      }
    });
  } catch (error) {
    console.error('Error fetching offer stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch offer statistics',
      error: error.message
    });
  }
};

/**
 * Bulk upload offers from file
 */
const bulkUploadOffers = async (req, res) => {
  try {
    const { offers } = req.body;

    if (!Array.isArray(offers) || offers.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an array of offers'
      });
    }

    const createdOffers = await Offer.insertMany(offers, { ordered: false });

    res.status(201).json({
      success: true,
      message: `Successfully uploaded ${createdOffers.length} offers`,
      data: {
        count: createdOffers.length,
        offers: createdOffers
      }
    });
  } catch (error) {
    console.error('Error bulk uploading offers:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to bulk upload offers',
      error: error.message
    });
  }
};

module.exports = {
  getAllOffers,
  getOfferById,
  createOffer,
  updateOffer,
  deleteOffer,
  approveOffer,
  rejectOffer,
  getOfferStats,
  bulkUploadOffers
};
