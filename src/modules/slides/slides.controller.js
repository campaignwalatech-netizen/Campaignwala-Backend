const Slide = require('./slides.models');

/**
 * Get all slides with filters and pagination
 */
const getAllSlides = async (req, res) => {
    try {
        const {
            status = 'all',
            category,
            search = '',
            page = 1,
            limit = 100,
            sortBy = 'order',
            order = 'asc'
        } = req.query;

        // Build filter query
        const filter = {};
        
        if (status !== 'all') {
            filter.status = status;
        }

        if (category) {
            filter.category = category;
        }

        if (search) {
            console.log('🔍 Searching slides with query:', search);
            filter.$or = [
                { offerTitle: { $regex: search, $options: 'i' } },
                { OffersId: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }

        // Pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sortOrder = order === 'desc' ? -1 : 1;
        const sortOptions = { [sortBy]: sortOrder };

        // Execute query
        const slides = await Slide.find(filter)
            .populate('category', 'name icon iconImage')
            .sort(sortOptions)
            .skip(skip)
            .limit(parseInt(limit));

        const total = await Slide.countDocuments(filter);

        if (search) {
            console.log(`✅ Found ${slides.length} slides matching "${search}"`);
        }

        res.status(200).json({
            success: true,
            message: 'Slides retrieved successfully',
            data: {
                slides,
                pagination: {
                    total,
                    page: parseInt(page),
                    limit: parseInt(limit),
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
    } catch (error) {
        console.error('Error in getAllSlides:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve slides',
            error: error.message
        });
    }
};

/**
 * Get slide by ID
 */
const getSlideById = async (req, res) => {
    try {
        const { id } = req.params;

        const slide = await Slide.findById(id).populate('category', 'name icon iconImage');

        if (!slide) {
            return res.status(404).json({
                success: false,
                message: 'Slide not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Slide retrieved successfully',
            data: slide
        });
    } catch (error) {
        console.error('Error in getSlideById:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve slide',
            error: error.message
        });
    }
};

/**
 * Create new slide
 */
const createSlide = async (req, res) => {
    try {
        const { offerTitle, category, OffersId, backgroundImage, order, status, description } = req.body;

        // Validate required fields
        if (!offerTitle || !category || !OffersId || !backgroundImage) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields. Please provide offerTitle, category, OffersId, and backgroundImage.'
            });
        }

        // Check if OffersId already exists
        const existingSlide = await Slide.findOne({ OffersId });
        if (existingSlide) {
            return res.status(400).json({
                success: false,
                message: 'Slide with this Offers ID already exists'
            });
        }

        // Get the highest order number and add 1 if order not provided
        let slideOrder = order;
        if (!slideOrder) {
            const lastSlide = await Slide.findOne().sort({ order: -1 });
            slideOrder = lastSlide ? lastSlide.order + 1 : 1;
        }

        const slide = new Slide({
            offerTitle,
            category,
            OffersId,
            backgroundImage,
            order: slideOrder,
            status: status || 'active',
            description: description || ''
        });

        await slide.save();
        await slide.populate('category', 'name icon iconImage');

        res.status(201).json({
            success: true,
            message: 'Slide created successfully',
            data: slide
        });
    } catch (error) {
        console.error('Error in createSlide:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create slide',
            error: error.message
        });
    }
};

/**
 * Update slide
 */
const updateSlide = async (req, res) => {
    try {
        const { id } = req.params;
        const { offerTitle, category, OffersId, backgroundImage, order, status, description } = req.body;

        const slide = await Slide.findById(id);

        if (!slide) {
            return res.status(404).json({
                success: false,
                message: 'Slide not found'
            });
        }

        // Check if OffersId is being changed and if it already exists
        if (OffersId && OffersId !== slide.OffersId) {
            const existingSlide = await Slide.findOne({ OffersId });
            if (existingSlide) {
                return res.status(400).json({
                    success: false,
                    message: 'Slide with this Offers ID already exists'
                });
            }
        }

        // Update fields
        if (offerTitle) slide.offerTitle = offerTitle;
        if (category) slide.category = category;
        if (OffersId) slide.OffersId = OffersId;
        if (backgroundImage) slide.backgroundImage = backgroundImage;
        if (order !== undefined) slide.order = order;
        if (status) slide.status = status;
        if (description !== undefined) slide.description = description;

        await slide.save();
        await slide.populate('category', 'name icon iconImage');

        res.status(200).json({
            success: true,
            message: 'Slide updated successfully',
            data: slide
        });
    } catch (error) {
        console.error('Error in updateSlide:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update slide',
            error: error.message
        });
    }
};

/**
 * Delete slide
 */
const deleteSlide = async (req, res) => {
    try {
        const { id } = req.params;

        const slide = await Slide.findByIdAndDelete(id);

        if (!slide) {
            return res.status(404).json({
                success: false,
                message: 'Slide not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Slide deleted successfully',
            data: slide
        });
    } catch (error) {
        console.error('Error in deleteSlide:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete slide',
            error: error.message
        });
    }
};

/**
 * Get slide statistics
 */
const getSlideStats = async (req, res) => {
    try {
        const total = await Slide.countDocuments();
        const active = await Slide.countDocuments({ status: 'active' });
        const inactive = await Slide.countDocuments({ status: 'inactive' });
        const totalViews = await Slide.aggregate([
            {
                $group: {
                    _id: null,
                    total: { $sum: '$views' }
                }
            }
        ]);

        res.status(200).json({
            success: true,
            message: 'Slide statistics retrieved successfully',
            data: {
                total,
                active,
                inactive,
                totalViews: totalViews.length > 0 ? totalViews[0].total : 0
            }
        });
    } catch (error) {
        console.error('Error in getSlideStats:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve slide statistics',
            error: error.message
        });
    }
};

/**
 * Update slide order
 */
const updateSlideOrder = async (req, res) => {
    try {
        const { slides } = req.body; // Array of { id, order }

        if (!Array.isArray(slides) || slides.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid slides array'
            });
        }

        // Update all slides in bulk
        const bulkOps = slides.map(slide => ({
            updateOne: {
                filter: { _id: slide.id },
                update: { $set: { order: slide.order } }
            }
        }));

        await Slide.bulkWrite(bulkOps);

        res.status(200).json({
            success: true,
            message: 'Slide order updated successfully'
        });
    } catch (error) {
        console.error('Error in updateSlideOrder:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update slide order',
            error: error.message
        });
    }
};

/**
 * Increment slide views
 */
const incrementSlideViews = async (req, res) => {
    try {
        const { id } = req.params;

        const slide = await Slide.findByIdAndUpdate(
            id,
            { $inc: { views: 1 } },
            { new: true }
        ).populate('category', 'name icon iconImage');

        if (!slide) {
            return res.status(404).json({
                success: false,
                message: 'Slide not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Slide views incremented successfully',
            data: slide
        });
    } catch (error) {
        console.error('Error in incrementSlideViews:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to increment slide views',
            error: error.message
        });
    }
};

module.exports = {
    getAllSlides,
    getSlideById,
    createSlide,
    updateSlide,
    deleteSlide,
    getSlideStats,
    updateSlideOrder,
    incrementSlideViews
};
