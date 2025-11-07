require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./src/modules/users/user.model');

const resetOTPAttempts = async () => {
    try {
        console.log('🔌 Connecting to MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Connected to MongoDB\n');

        // Find user by email
        const userEmail = 'vermakhushbu723@gmail.com';
        const user = await User.findOne({ email: userEmail });

        if (!user) {
            console.log('❌ User not found:', userEmail);
            process.exit(1);
        }

        console.log('👤 Found user:', user.name, '(', user.email, ')');
        console.log('📊 Current OTP Attempts:', user.otpAttempts);
        console.log('📅 Last OTP Sent:', user.lastOtpSent);

        // Reset OTP attempts
        user.otpAttempts = 0;
        user.lastOtpSent = null;
        user.emailOtp = null;
        user.emailOtpExpires = null;
        await user.save();

        console.log('\n✅ OTP attempts reset successfully!');
        console.log('📊 New OTP Attempts:', user.otpAttempts);
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
};

resetOTPAttempts();
