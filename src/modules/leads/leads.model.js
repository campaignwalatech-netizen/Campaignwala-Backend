const mongoose = require('mongoose');

// Function to generate unique Lead ID
function generateLeadId() {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let leadId = 'LD-';
  for (let i = 0; i < 8; i++) {
    leadId += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return leadId;
}

const leadSchema = new mongoose.Schema({
  leadId: {
    type: String,
    unique: true,
    // Don't make it required - will be auto-generated in pre-save hook
    // required: true
  },
  offerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Offer',
    required: true
  },
  offerName: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true
  },
  // HR Details (Person who shared the link)
  hrUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  hrName: {
    type: String,
    required: true
  },
  hrContact: {
    type: String,
    required: true
  },
  // Customer Details (Person who clicked the link and filled form)
  customerName: {
    type: String,
    required: true
  },
  customerContact: {
    type: String,
    required: true
  },
  // Lead Status
  status: {
    type: String,
    enum: ['pending', 'approved', 'completed', 'rejected'],
    default: 'pending'
  },
  // Commission/Offer amount
  offer: {
    type: String,
    default: ''
  },
  commission1: {
    type: Number,
    default: 0
  },
  commission2: {
    type: Number,
    default: 0
  },
  commission1Paid: {
    type: Boolean,
    default: false
  },
  commission2Paid: {
    type: Boolean,
    default: false
  },
  // Additional tracking
  sharedLink: {
    type: String,
    default: ''
  },
  remarks: {
    type: String,
    default: ''
  },
  rejectionReason: {
    type: String,
    default: ''
  }
}, {
  timestamps: true
});

// Pre-save hook to generate leadId
leadSchema.pre('save', async function(next) {
  if (!this.leadId) {
    let isUnique = false;
    while (!isUnique) {
      const newLeadId = generateLeadId();
      const existingLead = await mongoose.model('Lead').findOne({ leadId: newLeadId });
      if (!existingLead) {
        this.leadId = newLeadId;
        isUnique = true;
      }
    }
  }
  next();
});

const Lead = mongoose.model('Lead', leadSchema);

module.exports = Lead;
