const mongoose = require('mongoose');

const slideSchema = new mongoose.Schema({
    offerTitle: {
        type: String,
        required: [true, 'Offer title is required'],
        trim: true,
        maxlength: [200, 'Offer title cannot exceed 200 characters']
    },
    category: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category',
        required: [true, 'Category is required']
    },
    OffersId: {
        type: String,
        required: [true, 'Offers ID is required'],
        trim: true,
        unique: true
    },
    backgroundImage: {
        type: String,
        required: [true, 'Background image is required']
    },
    order: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['active', 'inactive'],
        default: 'active'
    },
    views: {
        type: Number,
        default: 0
    },
    description: {
        type: String,
        trim: true,
        maxlength: [500, 'Description cannot exceed 500 characters']
    }
}, {
    timestamps: true
});

// Index for faster queries
slideSchema.index({ status: 1, order: 1 });
slideSchema.index({ category: 1 });
slideSchema.index({ OffersId: 1 });

module.exports = mongoose.model('Slide', slideSchema);
