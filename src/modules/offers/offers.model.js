const mongoose = require('mongoose');

const offerSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Offer name is required'],
      trim: true,
      maxlength: [200, 'Offer name cannot exceed 200 characters']
    },
    category: {
      type: String,
      required: [true, 'Category is required'],
      trim: true
    },
    description: {
      type: String,
      trim: true,
      maxlength: [1000, 'Description cannot exceed 1000 characters']
    },
    latestStage: {
      type: String,
      enum: ['Upload', 'Number', 'Pending', 'Completed'],
      default: 'Pending'
    },
    commission1: {
      type: String,
      trim: true
    },
    commission1Comment: {
      type: String,
      trim: true
    },
    commission2: {
      type: String,
      trim: true
    },
    commission2Comment: {
      type: String,
      trim: true
    },
    link: {
      type: String,
      trim: true
    },
    image: {
      type: String,
      trim: true,
      default: ''
    },
    video: {
      type: String,
      trim: true,
      default: ''
    },
    videoLink: {
      type: String,
      trim: true,
      default: ''
    },
    termsAndConditions: {
      type: String,
      trim: true,
      maxlength: [5000, 'Terms and conditions cannot exceed 5000 characters']
    },
    // Approval fields
    isApproved: {
      type: Boolean,
      default: false
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    approvedAt: {
      type: Date
    },
    rejectionReason: {
      type: String,
      trim: true
    },
    // Lead information
    leadId: {
      type: String,
      trim: true
    }
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Indexes for faster queries
offerSchema.index({ category: 1 });
offerSchema.index({ status: 1 });
offerSchema.index({ isApproved: 1 });
offerSchema.index({ createdAt: -1 });
offerSchema.index({ name: 'text', description: 'text' }); // Text search

// Virtual for formatted date
offerSchema.virtual('formattedDate').get(function() {
  return this.createdAt.toLocaleDateString('en-IN');
});

const Offer = mongoose.model('Offer', offerSchema);

module.exports = Offer;
