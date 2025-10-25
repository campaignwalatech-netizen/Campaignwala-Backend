const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Category name is required'],
      trim: true,
      unique: true,
      minlength: [2, 'Category name must be at least 2 characters long'],
      maxlength: [100, 'Category name cannot exceed 100 characters']
    },
    description: {
      type: String,
      required: [true, 'Category description is required'],
      trim: true,
      maxlength: [500, 'Description cannot exceed 500 characters']
    },
    earnUpto: {
      type: String,
    },
    icon: {
      type: String,
      trim: true,
      default: ''
    },
    iconImage: {
      type: String,
      trim: true,
      default: ''
    },
    status: {
      type: String,
      enum: ['active', 'inactive'],
      default: 'active',
      lowercase: true
    },
    count: {
      type: Number,
      default: 0,
      min: [0, 'Count cannot be negative']
    }
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Index for faster queries (name already indexed by unique: true)
categorySchema.index({ status: 1 });
categorySchema.index({ createdAt: -1 });

// Virtual for formatted creation date
categorySchema.virtual('formattedDate').get(function() {
  return this.createdAt.toLocaleDateString('en-IN');
});

const Category = mongoose.model('Category', categorySchema);

module.exports = Category;
