const mongoose = require('mongoose');

// Function to generate unique Query ID
function generateQueryId() {
  const timestamp = Date.now().toString(36).toUpperCase();
  const randomStr = Math.random().toString(36).substring(2, 5).toUpperCase();
  return `QRY-${timestamp}-${randomStr}`;
}

const replySchema = new mongoose.Schema({
  message: {
    type: String,
    required: [true, 'Reply message is required'],
    trim: true,
    maxlength: [2000, 'Reply message cannot exceed 2000 characters']
  },
  repliedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  repliedByName: {
    type: String,
    default: 'Admin'
  },
  date: {
    type: Date,
    default: Date.now
  }
}, {
  _id: true,
  timestamps: true
});

const querySchema = new mongoose.Schema({
  queryId: {
    type: String,
    unique: true,
    trim: true
  },
  user: {
    type: String,
    required: [true, 'User name is required'],
    trim: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    trim: true,
    lowercase: true
  },
  subject: {
    type: String,
    required: [true, 'Subject is required'],
    trim: true,
    maxlength: [200, 'Subject cannot exceed 200 characters']
  },
  message: {
    type: String,
    required: [true, 'Message is required'],
    trim: true,
    maxlength: [5000, 'Message cannot exceed 5000 characters']
  },
  status: {
    type: String,
    enum: ['Open', 'Replied', 'Closed'],
    default: 'Open'
  },
  hasReplied: {
    type: Boolean,
    default: false
  },
  replies: [replySchema],
  priority: {
    type: String,
    enum: ['Low', 'Medium', 'High', 'Urgent'],
    default: 'Medium'
  },
  category: {
    type: String,
    enum: ['Technical', 'Account', 'Payment', 'General', 'Feature Request', 'Other'],
    default: 'General'
  },
  attachments: [{
    filename: String,
    url: String,
    uploadedAt: Date
  }],
  isResolved: {
    type: Boolean,
    default: false
  },
  resolvedAt: {
    type: Date
  },
  resolvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Pre-save hook to generate queryId
querySchema.pre('save', async function(next) {
  if (this.isNew && !this.queryId) {
    let isUnique = false;
    while (!isUnique) {
      const newQueryId = generateQueryId();
      const existingQuery = await mongoose.model('Query').findOne({ queryId: newQueryId });
      if (!existingQuery) {
        this.queryId = newQueryId;
        isUnique = true;
      }
    }
  }
  
  // Update hasReplied based on replies
  if (this.replies && this.replies.length > 0) {
    this.hasReplied = true;
    if (this.status === 'Open') {
      this.status = 'Replied';
    }
  }
  
  next();
});

// Indexes for faster queries
querySchema.index({ email: 1 });
querySchema.index({ userId: 1 });
querySchema.index({ status: 1 });
querySchema.index({ priority: 1 });
querySchema.index({ category: 1 });
querySchema.index({ createdAt: -1 });
querySchema.index({ queryId: 1 });
querySchema.index({ user: 'text', subject: 'text', message: 'text' });

// Virtual for reply count
querySchema.virtual('replyCount').get(function() {
  return this.replies ? this.replies.length : 0;
});

// Virtual for formatted date
querySchema.virtual('formattedDate').get(function() {
  return this.createdAt ? this.createdAt.toLocaleDateString('en-IN') : 'N/A';
});

const Query = mongoose.model('Query', querySchema);

module.exports = Query;
