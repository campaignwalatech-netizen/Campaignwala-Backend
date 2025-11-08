const Offer = require('./offers.model');
const { parseExcelFile, deleteFile, validateRequiredFields } = require('../../utils/excelParser');

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
        { leadId: { $regex: search, $options: 'i' } }
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
    const approvedOffers = await Offer.countDocuments({ isApproved: true });
    const pendingOffers = await Offer.countDocuments({ isApproved: false });

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
        approved: approvedOffers,
        pending: pendingOffers,
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
/**
 * Bulk upload offers from Excel/CSV file
 */
const bulkUploadOffers = async (req, res) => {
  let filePath = null;
  
  try {
    // Check if file was uploaded
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'Please upload an Excel or CSV file'
      });
    }

    filePath = req.file.path;
    console.log('📄 Processing file:', filePath);

    // Parse Excel/CSV file
    const data = parseExcelFile(filePath);

    if (!data || data.length === 0) {
      deleteFile(filePath);
      return res.status(400).json({
        success: false,
        message: 'File is empty or contains no valid data'
      });
    }

    console.log(`📊 Found ${data.length} rows in the file`);

    // Define required fields for offers
    const requiredFields = ['leadId', 'name', 'category', 'commission1'];

    // Validate required fields
    const validation = validateRequiredFields(data, requiredFields);

    if (!validation.isValid) {
      deleteFile(filePath);
      return res.status(400).json({
        success: false,
        message: 'Validation failed: Missing required fields',
        errors: {
          missingFields: validation.missingFields,
          invalidRows: validation.invalidRows.slice(0, 10) // Show first 10 invalid rows
        }
      });
    }

    // Transform and prepare offers data
    const offersToCreate = data.map(row => ({
      leadId: row.leadId?.toString().trim(),
      name: row.name?.toString().trim(),
      category: row.category?.toString().trim(),
      commission1: parseFloat(row.commission1) || 0,
      commission2: row.commission2 ? parseFloat(row.commission2) : 0,
      customerContact: row.customerContact?.toString().trim() || '',
      description: row.description?.toString().trim() || '',
      status: row.status?.toString().toLowerCase() || 'pending',
      isApproved: row.isApproved === true || row.isApproved === 'true' || row.isApproved === 'TRUE' || false
    }));

    // Bulk insert with error handling for duplicates
    const results = {
      success: [],
      failed: []
    };

    for (let i = 0; i < offersToCreate.length; i++) {
      try {
        const offer = await Offer.create(offersToCreate[i]);
        results.success.push({
          row: i + 2, // +2 for header and 0-index
          leadId: offer.leadId,
          name: offer.name
        });
      } catch (error) {
        results.failed.push({
          row: i + 2,
          data: offersToCreate[i],
          error: error.message
        });
      }
    }

    // Delete the uploaded file
    deleteFile(filePath);

    res.status(201).json({
      success: true,
      message: `Bulk upload completed: ${results.success.length} offers created, ${results.failed.length} failed`,
      data: {
        totalRows: data.length,
        successCount: results.success.length,
        failedCount: results.failed.length,
        successItems: results.success,
        failedItems: results.failed.slice(0, 20) // Show first 20 failed items
      }
    });

  } catch (error) {
    console.error('❌ Error in bulk upload:', error);
    
    // Clean up file on error
    if (filePath) {
      deleteFile(filePath);
    }

    res.status(500).json({
      success: false,
      message: 'Failed to process bulk upload',
      error: error.message
    });
  }
};

/**
 * Get offers by category
 */
const getOffersByCategory = async (req, res) => {
  try {
    const { categoryId } = req.params;

    // First, get the category name from Category model
    const Category = require('../categories/categories.model');
    const category = await Category.findById(categoryId).select('name');
    
    if (!category) {
      return res.status(404).json({
        success: false,
        message: 'Category not found',
        data: []
      });
    }

    console.log('🔍 Searching offers for category:', category.name);

    // Find offers by category name (since offers store category as String)
    // Return ALL fields, not just limited selection
    const offers = await Offer.find({ category: category.name })
      .lean();

    console.log(`✅ Found ${offers.length} offers for category: ${category.name}`);
    console.log('📦 Sample offer fields:', offers[0]); // Debug: show what fields are returned

    res.status(200).json({
      success: true,
      message: 'Offers retrieved successfully',
      data: offers
    });
  } catch (error) {
    console.error('❌ Error fetching offers by category:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch offers',
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
  bulkUploadOffers,
  getOffersByCategory
};
