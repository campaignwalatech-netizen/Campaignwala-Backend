const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    phoneNumber: {
        type: String,
        required: [true, 'Phone number is required'],
        unique: true,
        trim: true,
        validate: {
            validator: function (v) {
                return /^[0-9]{10}$/.test(v);
            },
            message: 'Phone number must be 10 digits'
        }
    },
    name: {
        type: String,
        trim: true,
        default: ''
    },
    email: {
        type: String,
        trim: true,
        lowercase: true,
        default: ''
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long']
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    otpAttempts: {
        type: Number,
        default: 0
    },
    lastOtpSent: {
        type: Date
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        return next();
    }

    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Check if OTP attempts exceeded
userSchema.methods.canSendOtp = function () {
    const now = new Date();
    const lastOtp = this.lastOtpSent;

    // Reset attempts if more than 1 hour passed
    if (lastOtp && (now - lastOtp) > 60 * 60 * 1000) {
        this.otpAttempts = 0;
    }

    return this.otpAttempts < 5; // Max 5 attempts per hour
};

// Increment OTP attempts
userSchema.methods.incrementOtpAttempts = function () {
    this.otpAttempts += 1;
    this.lastOtpSent = new Date();
};

// Remove password from JSON output
userSchema.methods.toJSON = function () {
    const userObject = this.toObject();
    delete userObject.password;
    delete userObject.otpAttempts;
    delete userObject.lastOtpSent;
    return userObject;
};

const User = mongoose.model('User', userSchema);

module.exports = User;