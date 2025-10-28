const mongoose = require('mongoose');

// Function to generate unique Notification ID
function generateNotificationId() {
  const timestamp = Date.now().toString(36).toUpperCase();
  const randomStr = Math.random().toString(36).substring(2, 5).toUpperCase();
  return `NOTIF-${timestamp}-${randomStr}`;
}

const notificationSchema = new mongoose.Schema({
  notificationId: {
    type: String,
    unique: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['profile', 'offer', 'announcement', 'system'],
    required: [true, 'Notification type is required']
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    maxlength: [200, 'Title cannot exceed 200 characters']
  },
  message: {
    type: String,
    required: [true, 'Message is required'],
    trim: true,
    maxlength: [2000, 'Message cannot exceed 2000 characters']
  },
  // Recipients can be 'all' or array of user IDs
  recipients: {
    type: [String],
    default: []
  },
  recipientCount: {
    type: Number,
    default: 0
  },
  // For targeted notifications (profile completion, offers)
  targetSegments: {
    type: [String],
    default: []
  },
  // Offer specific fields
  offerDetails: {
    offerTitle: String,
    discount: String,
    expiryDate: Date,
    description: String
  },
  status: {
    type: String,
    enum: ['pending', 'sent', 'failed'],
    default: 'sent'
  },
  sentBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  sentDate: {
    type: Date,
    default: Date.now
  },
  // Track delivery status
  deliveryStats: {
    sent: { type: Number, default: 0 },
    delivered: { type: Number, default: 0 },
    failed: { type: Number, default: 0 }
  },
  // Metadata
  metadata: {
    filterBy: String,
    searchQuery: String,
    selectedUserIds: [String]
  }
}, {
  timestamps: true
});

// Pre-save hook to generate notificationId
notificationSchema.pre('save', async function(next) {
  if (this.isNew && !this.notificationId) {
    let isUnique = false;
    while (!isUnique) {
      const newNotificationId = generateNotificationId();
      const existingNotification = await mongoose.model('Notification').findOne({ notificationId: newNotificationId });
      if (!existingNotification) {
        this.notificationId = newNotificationId;
        isUnique = true;
      }
    }
  }
  next();
});

// Indexes for faster queries
notificationSchema.index({ type: 1 });
notificationSchema.index({ status: 1 });
notificationSchema.index({ sentDate: -1 });
notificationSchema.index({ notificationId: 1 });
notificationSchema.index({ sentBy: 1 });
notificationSchema.index({ title: 'text', message: 'text' });

const Notification = mongoose.model('Notification', notificationSchema);

module.exports = Notification;
