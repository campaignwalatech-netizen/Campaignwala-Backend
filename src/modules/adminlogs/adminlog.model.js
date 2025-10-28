const mongoose = require('mongoose');

// Function to generate unique Admin Log ID
function generateAdminLogId() {
  const timestamp = Date.now();
  const randomNum = Math.floor(Math.random() * 10000);
  return `LOG-${timestamp}-${randomNum}`;
}

const adminLogSchema = new mongoose.Schema({
  logId: {
    type: String,
    unique: true,
    trim: true
  },
  adminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  adminName: {
    type: String,
    required: [true, 'Admin name is required'],
    trim: true
  },
  adminRole: {
    type: String,
    default: 'Admin'
  },
  action: {
    type: String,
    required: [true, 'Action is required'],
    trim: true,
    maxlength: [500, 'Action cannot exceed 500 characters']
  },
  actionType: {
    type: String,
    enum: ['create', 'update', 'delete', 'approve', 'reject', 'login', 'logout', 'system', 'other'],
    default: 'other'
  },
  module: {
    type: String,
    enum: ['users', 'offers', 'categories', 'leads', 'withdrawals', 'notifications', 'queries', 'slides', 'wallet', 'system', 'authentication', 'other'],
    default: 'other'
  },
  severity: {
    type: String,
    enum: ['info', 'success', 'warning', 'error'],
    default: 'info'
  },
  ipAddress: {
    type: String,
    trim: true,
    default: 'Unknown'
  },
  userAgent: {
    type: String,
    trim: true
  },
  details: {
    type: String,
    trim: true,
    maxlength: [2000, 'Details cannot exceed 2000 characters']
  },
  // Store additional metadata as JSON
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  // Target entity (e.g., user ID, offer ID, etc.)
  targetId: {
    type: String,
    trim: true
  },
  targetType: {
    type: String,
    trim: true
  },
  // Status of the action
  status: {
    type: String,
    enum: ['success', 'failed', 'pending'],
    default: 'success'
  },
  errorMessage: {
    type: String,
    trim: true
  }
}, {
  timestamps: true
});

// Pre-save hook to generate logId
adminLogSchema.pre('save', async function(next) {
  if (!this.logId) {
    let logId;
    let isUnique = false;
    
    while (!isUnique) {
      logId = generateAdminLogId();
      const existingLog = await mongoose.model('AdminLog').findOne({ logId });
      if (!existingLog) {
        isUnique = true;
      }
    }
    
    this.logId = logId;
  }
  next();
});

// Indexes for faster queries
adminLogSchema.index({ adminId: 1 });
adminLogSchema.index({ severity: 1 });
adminLogSchema.index({ actionType: 1 });
adminLogSchema.index({ module: 1 });
adminLogSchema.index({ createdAt: -1 });
adminLogSchema.index({ status: 1 });

// Text search index
adminLogSchema.index({ 
  adminName: 'text', 
  action: 'text', 
  details: 'text',
  ipAddress: 'text'
});

const AdminLog = mongoose.model('AdminLog', adminLogSchema);

module.exports = AdminLog;
