const mongoose = require('mongoose');

// Function to generate unique Withdrawal ID
function generateWithdrawalId() {
  const timestamp = Date.now().toString(36).toUpperCase();
  const randomStr = Math.random().toString(36).substring(2, 5).toUpperCase();
  return `WDR-${timestamp}-${randomStr}`;
}

const withdrawalSchema = new mongoose.Schema({
  withdrawalId: {
    type: String,
    unique: true,
    trim: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: [true, 'Amount is required'],
    min: [1, 'Amount must be at least 1']
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'processing'],
    default: 'pending'
  },
  requestDate: {
    type: Date,
    default: Date.now
  },
  processedDate: {
    type: Date
  },
  processedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  reason: {
    type: String,
    trim: true,
    default: 'Awaiting admin approval'
  },
  rejectionReason: {
    type: String,
    trim: true
  },
  bankDetails: {
    accountHolderName: {
      type: String,
      trim: true
    },
    accountNumber: {
      type: String,
      trim: true
    },
    ifscCode: {
      type: String,
      trim: true
    },
    bankName: {
      type: String,
      trim: true
    },
    upiId: {
      type: String,
      trim: true
    }
  },
  transactionId: {
    type: String,
    trim: true
  },
  remarks: {
    type: String,
    trim: true
  }
}, {
  timestamps: true
});

// Pre-save hook to generate withdrawalId
withdrawalSchema.pre('save', async function(next) {
  if (this.isNew && !this.withdrawalId) {
    let isUnique = false;
    while (!isUnique) {
      const newWithdrawalId = generateWithdrawalId();
      const existingWithdrawal = await mongoose.model('Withdrawal').findOne({ withdrawalId: newWithdrawalId });
      if (!existingWithdrawal) {
        this.withdrawalId = newWithdrawalId;
        isUnique = true;
      }
    }
  }
  next();
});

// Index for faster queries
withdrawalSchema.index({ userId: 1 });
withdrawalSchema.index({ status: 1 });
withdrawalSchema.index({ requestDate: -1 });
withdrawalSchema.index({ withdrawalId: 1 });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

module.exports = Withdrawal;
