const jwt = require('jsonwebtoken');
const axios = require('axios');
const User = require('./user.model');

// Generate JWT token
const generateToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE || '7d'
    });
};

// Send OTP via third-party SMS API
const sendSMSOTP = async (phoneNumber, otp) => {
    try {
        // Check if SMS API is configured
        if (!process.env.SMS_API_KEY || !process.env.SMS_API_URL) {
            console.log('SMS API not configured, using static OTP');
            return { success: false, useStatic: true };
        }

        const message = `Your Campaign Waala OTP is: ${otp}. Valid for 10 minutes.`;
        
        // Example SMS API call - adjust based on your SMS provider
        const response = await axios.post(process.env.SMS_API_URL, {
            apiKey: process.env.SMS_API_KEY,
            sender: process.env.SMS_SENDER_ID || 'CAMPWL',
            number: phoneNumber,
            message: message
        }, {
            timeout: 5000 // 5 second timeout
        });

        if (response.data && response.data.success) {
            console.log('OTP sent successfully via SMS API');
            return { success: true, useStatic: false };
        } else {
            console.log('SMS API failed, falling back to static OTP');
            return { success: false, useStatic: true };
        }
    } catch (error) {
        console.error('SMS API error:', error.message);
        console.log('Falling back to static OTP');
        return { success: false, useStatic: true };
    }
};

// Generate random 4-digit OTP
const generateOTP = () => {
    return Math.floor(1000 + Math.random() * 9000).toString();
};

// Send OTP (with third-party SMS API and static fallback)
const sendOTP = async (req, res) => {
    try {
        const { phoneNumber } = req.body;

        console.log('📥 sendOTP request received for:', phoneNumber);

        if (!phoneNumber) {
            console.log('❌ Phone number missing');
            return res.status(400).json({
                success: false,
                message: 'Phone number is required'
            });
        }

        // Validate phone number format
        if (!/^[0-9]{10}$/.test(phoneNumber)) {
            console.log('❌ Invalid phone format:', phoneNumber);
            return res.status(400).json({
                success: false,
                message: 'Invalid phone number format. Must be 10 digits'
            });
        }

        console.log('✅ Phone number validated');

        let user = await User.findOne({ phoneNumber });

        if (user) {
            console.log('📱 Existing user found');
            // Check OTP rate limiting
            if (!user.canSendOtp()) {
                console.log('❌ Rate limit exceeded');
                return res.status(429).json({
                    success: false,
                    message: 'Too many OTP attempts. Please try again later'
                });
            }

            user.incrementOtpAttempts();
            await user.save();
        }

        // Generate OTP
        const otp = generateOTP();
        
        // Try to send via SMS API
        const smsResult = await sendSMSOTP(phoneNumber, otp);
        
        // Determine which OTP to use and send response
        if (smsResult.useStatic) {
            // SMS API failed, use static OTP
            res.json({
                success: true,
                message: 'OTP sent successfully',
                data: {
                    phoneNumber,
                    otp: process.env.STATIC_OTP, // Return static OTP in development
                    useStatic: true
                }
            });
        } else {
            // SMS sent successfully via API
            // In production, don't send OTP in response
            res.json({
                success: true,
                message: 'OTP sent successfully to your phone',
                data: {
                    phoneNumber,
                    // Only include OTP in development for testing
                    ...(process.env.NODE_ENV === 'development' && { otp: otp }),
                    useStatic: false
                }
            });
        }

    } catch (error) {
        console.error('Send OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to send OTP'
        });
    }
};

// Register user
const register = async (req, res) => {
    try {
        const { phoneNumber, otp, name, email, password } = req.body;

        // Debug: Log what we received
        console.log('📥 Registration request received:', {
            phoneNumber: phoneNumber || 'MISSING',
            otp: otp || 'MISSING',
            name: name || 'MISSING',
            email: email || 'MISSING',
            password: password ? '***' : 'MISSING'
        });

        // Validation
        if (!phoneNumber || !otp || !name || !email || !password) {
            console.log('❌ Validation failed - missing fields');
            return res.status(400).json({
                success: false,
                message: 'Phone number, OTP, name, email, and password are required'
            });
        }

        // Verify OTP (static check for development)
        if (otp !== process.env.STATIC_OTP) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email format'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ phoneNumber });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'User with this phone number already exists'
            });
        }

        // Check if email already exists
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(409).json({
                success: false,
                message: 'Email already registered'
            });
        }

        // Create new user
        const user = new User({
            phoneNumber,
            name,
            email,
            password,
            isVerified: true // Auto-verify since OTP is validated
        });

        await user.save();

        // Generate token
        const token = generateToken(user._id);

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            data: {
                user,
                token
            }
        });

    } catch (error) {
        console.error('Registration error:', error);

        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: 'Phone number already registered'
            });
        }

        if (error.name === 'ValidationError') {
            const errorMessages = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errorMessages
            });
        }

        res.status(500).json({
            success: false,
            message: 'Registration failed'
        });
    }
};

// Login user
const login = async (req, res) => {
    try {
        const { phoneNumber, password } = req.body;

        if (!phoneNumber || !password) {
            return res.status(400).json({
                success: false,
                message: 'Phone number and password are required'
            });
        }

        // Find user
        const user = await User.findOne({ phoneNumber });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid phone number or password'
            });
        }

        // Check if account is active
        if (!user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Account is deactivated'
            });
        }

        // Check password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid phone number or password'
            });
        }

        // Generate token
        const token = generateToken(user._id);

        res.json({
            success: true,
            message: 'Login successful',
            data: {
                user,
                token
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
};

// Verify OTP and phone number
const verifyOTP = async (req, res) => {
    try {
        const { phoneNumber, otp } = req.body;

        if (!phoneNumber || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Phone number and OTP are required'
            });
        }

        // Verify OTP (static check for development)
        if (otp !== process.env.STATIC_OTP) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        // Find user
        const user = await User.findOne({ phoneNumber });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Update verification status
        user.isVerified = true;
        user.otpAttempts = 0;
        await user.save();

        res.json({
            success: true,
            message: 'Phone number verified successfully',
            data: { user }
        });

    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({
            success: false,
            message: 'OTP verification failed'
        });
    }
};

// Get current user profile
const getProfile = async (req, res) => {
    try {
        res.json({
            success: true,
            message: 'Profile retrieved successfully',
            data: { user: req.user }
        });
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get profile'
        });
    }
};

// Update user profile
const updateProfile = async (req, res) => {
    try {
        const { password } = req.body;
        const userId = req.user._id;

        const updateData = {};

        if (password) {
            if (password.length < 6) {
                return res.status(400).json({
                    success: false,
                    message: 'Password must be at least 6 characters long'
                });
            }
            updateData.password = password;
        }

        // If password is being updated, we need to trigger the pre-save hook
        if (updateData.password) {
            const user = await User.findById(userId);
            user.password = updateData.password;
            await user.save();

            // Remove password from response
            const updatedUser = user.toJSON();

            res.json({
                success: true,
                message: 'Profile updated successfully',
                data: { user: updatedUser }
            });
        } else {
            res.json({
                success: true,
                message: 'No changes to update',
                data: { user: req.user }
            });
        }

    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile'
        });
    }
};

// Change password
const changePassword = async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user._id;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current password and new password are required'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 6 characters long'
            });
        }

        // Get user with password
        const user = await User.findById(userId);

        // Verify current password
        const isCurrentPasswordValid = await user.comparePassword(currentPassword);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Update password
        user.password = newPassword;
        await user.save();

        res.json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to change password'
        });
    }
};

// Admin: Get all users
const getAllUsers = async (req, res) => {
    try {
        const { page = 1, limit = 10, role, isVerified, search } = req.query;

        const query = {};

        if (role) query.role = role;
        if (isVerified !== undefined) query.isVerified = isVerified === 'true';
        if (search) {
            query.phoneNumber = { $regex: search, $options: 'i' };
        }

        const users = await User.find(query)
            .select('-password')
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .sort({ createdAt: -1 });

        const total = await User.countDocuments(query);

        res.json({
            success: true,
            message: 'Users retrieved successfully',
            data: {
                users,
                pagination: {
                    current: parseInt(page),
                    pages: Math.ceil(total / limit),
                    total
                }
            }
        });

    } catch (error) {
        console.error('Get all users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get users'
        });
    }
};

// Admin: Get user by ID
const getUserById = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId).select('-password');
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'User retrieved successfully',
            data: { user }
        });

    } catch (error) {
        console.error('Get user by ID error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get user'
        });
    }
};

// Admin: Update user role
const updateUserRole = async (req, res) => {
    try {
        const { userId } = req.params;
        const { role } = req.body;

        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid role. Must be "user" or "admin"'
            });
        }

        const user = await User.findByIdAndUpdate(
            userId,
            { role },
            { new: true, runValidators: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'User role updated successfully',
            data: { user }
        });

    } catch (error) {
        console.error('Update user role error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user role'
        });
    }
};

// Admin: Toggle user active status
const toggleUserStatus = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        user.isActive = !user.isActive;
        await user.save();

        res.json({
            success: true,
            message: `User ${user.isActive ? 'activated' : 'deactivated'} successfully`,
            data: { user: user.toJSON() }
        });

    } catch (error) {
        console.error('Toggle user status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user status'
        });
    }
};

// Admin: Mark user as Ex
const markUserAsEx = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Mark user as Ex (inactive + isEx flag)
        user.isActive = false;
        user.isEx = true;
        await user.save();

        res.json({
            success: true,
            message: 'User marked as Ex successfully',
            data: { user: user.toJSON() }
        });

    } catch (error) {
        console.error('Mark user as Ex error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to mark user as Ex'
        });
    }
};

// Admin: Delete user
const deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findByIdAndDelete(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'User deleted successfully'
        });

    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user'
        });
    }
};

// Get dashboard stats (Admin)
const getDashboardStats = async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const verifiedUsers = await User.countDocuments({ isVerified: true });
        const adminUsers = await User.countDocuments({ role: 'admin' });
        const activeUsers = await User.countDocuments({ isActive: true });

        // Get recent registrations (last 7 days)
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        const recentRegistrations = await User.countDocuments({
            createdAt: { $gte: weekAgo }
        });

        res.json({
            success: true,
            message: 'Dashboard stats retrieved successfully',
            data: {
                totalUsers,
                verifiedUsers,
                adminUsers,
                activeUsers,
                recentRegistrations,
                unverifiedUsers: totalUsers - verifiedUsers,
                inactiveUsers: totalUsers - activeUsers
            }
        });

    } catch (error) {
        console.error('Get dashboard stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get dashboard stats'
        });
    }
};

// Forgot Password - Send OTP
const forgotPassword = async (req, res) => {
    try {
        const { phoneNumber } = req.body;

        if (!phoneNumber) {
            return res.status(400).json({
                success: false,
                message: 'Phone number is required'
            });
        }

        // Validate phone number format
        if (!/^[0-9]{10}$/.test(phoneNumber)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid phone number format. Must be 10 digits'
            });
        }

        // Check if user exists
        const user = await User.findOne({ phoneNumber });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'No account found with this phone number'
            });
        }

        // Check OTP rate limiting
        if (!user.canSendOtp()) {
            return res.status(429).json({
                success: false,
                message: 'Too many OTP attempts. Please try again later'
            });
        }

        user.incrementOtpAttempts();
        await user.save();

        // Generate OTP
        const otp = generateOTP();
        
        // Try to send via SMS API
        const smsResult = await sendSMSOTP(phoneNumber, otp);
        
        // Determine which OTP to use and send response
        if (smsResult.useStatic) {
            res.json({
                success: true,
                message: 'Password reset OTP sent successfully',
                data: {
                    phoneNumber,
                    otp: process.env.STATIC_OTP,
                    useStatic: true
                }
            });
        } else {
            res.json({
                success: true,
                message: 'Password reset OTP sent to your phone',
                data: {
                    phoneNumber,
                    ...(process.env.NODE_ENV === 'development' && { otp: otp }),
                    useStatic: false
                }
            });
        }

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to send reset OTP'
        });
    }
};

// Reset Password with OTP
const resetPassword = async (req, res) => {
    try {
        const { phoneNumber, otp, newPassword } = req.body;

        if (!phoneNumber || !otp || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Phone number, OTP, and new password are required'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long'
            });
        }

        // Verify OTP
        if (otp !== process.env.STATIC_OTP) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        // Find user
        const user = await User.findOne({ phoneNumber });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Update password
        user.password = newPassword;
        user.otpAttempts = 0; // Reset OTP attempts
        await user.save();

        res.json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset password'
        });
    }
};

// Update KYC Details (Personal + Documents + Bank)
const updateKYCDetails = async (req, res) => {
    try {
        console.log('🔵 ===== UPDATE KYC DETAILS CALLED =====');
        console.log('🔵 User object:', req.user);
        console.log('🔵 User ID from token:', req.user?._id);
        console.log('🔵 Request body:', JSON.stringify(req.body, null, 2));
        
        const userId = req.user._id;
        
        // Extract data from nested objects or direct properties
        const personalDetails = req.body.personalDetails || {};
        const kycDocuments = req.body.kycDocuments || {};
        const bankDetails = req.body.bankDetails || {};
        
        // Personal Details - can come from personalDetails object or directly
        const firstName = req.body.firstName || personalDetails.firstName;
        const lastName = req.body.lastName || personalDetails.lastName;
        const dob = req.body.dob || personalDetails.dob;
        const gender = req.body.gender || personalDetails.gender;
        const address1 = req.body.address1 || personalDetails.address1;
        const city = req.body.city || personalDetails.city;
        const state = req.body.state || personalDetails.state;
        const zip = req.body.zip || personalDetails.zip;
        const country = req.body.country || personalDetails.country;
        
        // KYC Documents - can come from kycDocuments object or directly
        const panNumber = req.body.panNumber || kycDocuments.panNumber;
        const aadhaarNumber = req.body.aadhaarNumber || kycDocuments.aadhaarNumber;
        const panImage = req.body.panImage || kycDocuments.panImage;
        const aadhaarImage = req.body.aadhaarImage || kycDocuments.aadhaarImage;
        
        // Bank Details - can come from bankDetails object or directly
        const bankName = req.body.bankName || bankDetails.bankName;
        const accountHolderName = req.body.accountHolderName || bankDetails.accountHolderName;
        const accountNumber = req.body.accountNumber || bankDetails.accountNumber;
        const ifscCode = req.body.ifscCode || bankDetails.ifscCode;
        const branchAddress = req.body.branchAddress || bankDetails.branchAddress;
        const upiId = req.body.upiId || bankDetails.upiId;
        
        console.log('🟡 Extracted Bank Details:', { bankName, accountHolderName, accountNumber, ifscCode, branchAddress, upiId });

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Update Personal Details
        if (firstName !== undefined) user.firstName = firstName;
        if (lastName !== undefined) user.lastName = lastName;
        if (dob !== undefined) user.dob = dob;
        if (gender !== undefined) user.gender = gender;
        if (address1 !== undefined) user.address1 = address1;
        if (city !== undefined) user.city = city;
        if (state !== undefined) user.state = state;
        if (zip !== undefined) user.zip = zip;
        if (country !== undefined) user.country = country;

        // Update KYC Documents
        if (panNumber !== undefined) user.kycDetails.panNumber = panNumber;
        if (aadhaarNumber !== undefined) user.kycDetails.aadhaarNumber = aadhaarNumber;
        if (panImage !== undefined) user.kycDetails.panImage = panImage;
        if (aadhaarImage !== undefined) user.kycDetails.aadhaarImage = aadhaarImage;

        // Update Bank Details
        if (bankName !== undefined) user.bankDetails.bankName = bankName;
        if (accountHolderName !== undefined) user.bankDetails.accountHolderName = accountHolderName;
        if (accountNumber !== undefined) user.bankDetails.accountNumber = accountNumber;
        if (ifscCode !== undefined) user.bankDetails.ifscCode = ifscCode;
        if (branchAddress !== undefined) user.bankDetails.branchAddress = branchAddress;
        if (upiId !== undefined) user.bankDetails.upiId = upiId;

        // Check if this is a full KYC submission (has all required fields)
        const hasAllRequiredFields = panNumber && aadhaarNumber && accountNumber && firstName && lastName;
        console.log('🔵 Has all required fields?', hasAllRequiredFields);
        console.log('🔵 Current KYC Status:', user.kycDetails.kycStatus);
        
        // If this is a full submission and status is not already approved, set to pending
        if (hasAllRequiredFields && user.kycDetails.kycStatus !== 'approved') {
            console.log('🟢 Setting KYC status to PENDING');
            user.kycDetails.kycStatus = 'pending';
            user.kycDetails.kycSubmittedAt = new Date();
            // Clear rejection reason when resubmitting
            user.kycDetails.kycRejectionReason = '';
            user.kycDetails.kycRejectedAt = null;
        }

        await user.save();
        console.log('🟢 User saved successfully. Final KYC Status:', user.kycDetails.kycStatus);

        res.json({
            success: true,
            message: 'KYC details updated successfully',
            data: user
        });

    } catch (error) {
        console.error('Update KYC details error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update KYC details',
            error: error.message
        });
    }
};

// Get KYC Details
const getKYCDetails = async (req, res) => {
    try {
        const userId = req.user._id;

        const user = await User.findById(userId).select('-password -otpAttempts -lastOtpSent');
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'KYC details retrieved successfully',
            data: {
                // Personal Details
                firstName: user.firstName || '',
                lastName: user.lastName || '',
                name: user.name || '',
                email: user.email || '',
                phoneNumber: user.phoneNumber || '',
                dob: user.dob || '',
                gender: user.gender || '',
                address1: user.address1 || '',
                city: user.city || '',
                state: user.state || '',
                zip: user.zip || '',
                country: user.country || 'India',
                // KYC Documents
                kycDetails: {
                    panNumber: user.kycDetails?.panNumber || '',
                    aadhaarNumber: user.kycDetails?.aadhaarNumber || '',
                    panImage: user.kycDetails?.panImage || '',
                    aadhaarImage: user.kycDetails?.aadhaarImage || '',
                    kycStatus: user.kycDetails?.kycStatus || 'not_submitted',
                    kycSubmittedAt: user.kycDetails?.kycSubmittedAt || null,
                    kycApprovedAt: user.kycDetails?.kycApprovedAt || null,
                    kycRejectedAt: user.kycDetails?.kycRejectedAt || null,
                    kycRejectionReason: user.kycDetails?.kycRejectionReason || ''
                },
                // Bank Details
                bankDetails: {
                    bankName: user.bankDetails?.bankName || '',
                    accountHolderName: user.bankDetails?.accountHolderName || '',
                    accountNumber: user.bankDetails?.accountNumber || '',
                    ifscCode: user.bankDetails?.ifscCode || '',
                    branchAddress: user.bankDetails?.branchAddress || '',
                    upiId: user.bankDetails?.upiId || ''
                }
            }
        });

    } catch (error) {
        console.error('Get KYC details error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get KYC details',
            error: error.message
        });
    }
};

// Admin: Get all pending KYC requests
const getPendingKYCRequests = async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 100,
            search = '',
            sortBy = 'kycDetails.kycSubmittedAt',
            order = 'desc'
        } = req.query;

        // Build filter
        const filter = {
            'kycDetails.kycStatus': 'pending'
        };

        if (search) {
            filter.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { phoneNumber: { $regex: search, $options: 'i' } },
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } }
            ];
        }

        const skip = (page - 1) * limit;
        const sortOrder = order === 'desc' ? -1 : 1;

        const users = await User.find(filter)
            .select('-password -otpAttempts -lastOtpSent')
            .sort({ [sortBy]: sortOrder })
            .skip(skip)
            .limit(parseInt(limit));

        const total = await User.countDocuments(filter);

        res.json({
            success: true,
            message: 'Pending KYC requests retrieved successfully',
            data: {
                users,
                pagination: {
                    total,
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(total / limit)
                }
            }
        });

    } catch (error) {
        console.error('Get pending KYC requests error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get pending KYC requests',
            error: error.message
        });
    }
};

// Admin: Approve KYC
const approveKYC = async (req, res) => {
    try {
        const { userId } = req.params;
        const { remarks } = req.body;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.kycDetails.kycStatus !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'KYC is not in pending status'
            });
        }

        user.kycDetails.kycStatus = 'approved';
        user.kycDetails.kycApprovedAt = new Date();
        user.kycDetails.kycRejectionReason = '';
        if (remarks) {
            user.kycDetails.remarks = remarks;
        }

        await user.save();

        res.json({
            success: true,
            message: 'KYC approved successfully',
            data: user
        });

    } catch (error) {
        console.error('Approve KYC error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve KYC',
            error: error.message
        });
    }
};

// Admin: Reject KYC
const rejectKYC = async (req, res) => {
    try {
        const { userId } = req.params;
        const { reason } = req.body;

        if (!reason || reason.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Rejection reason is required'
            });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.kycDetails.kycStatus !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'KYC is not in pending status'
            });
        }

        user.kycDetails.kycStatus = 'rejected';
        user.kycDetails.kycRejectedAt = new Date();
        user.kycDetails.kycRejectionReason = reason;

        await user.save();

        res.json({
            success: true,
            message: 'KYC rejected successfully',
            data: user
        });

    } catch (error) {
        console.error('Reject KYC error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reject KYC',
            error: error.message
        });
    }
};

// Admin: Get KYC details by user ID
const getKYCDetailsByUserId = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId).select('-password -otpAttempts -lastOtpSent');
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'KYC details retrieved successfully',
            data: user
        });

    } catch (error) {
        console.error('Get KYC details by user ID error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get KYC details',
            error: error.message
        });
    }
};

module.exports = {
    sendOTP,
    register,
    login,
    verifyOTP,
    getProfile,
    updateProfile,
    changePassword,
    getAllUsers,
    getUserById,
    updateUserRole,
    toggleUserStatus,
    markUserAsEx,
    deleteUser,
    getDashboardStats,
    forgotPassword,
    resetPassword,
    updateKYCDetails,
    getKYCDetails,
    getPendingKYCRequests,
    approveKYC,
    rejectKYC,
    getKYCDetailsByUserId
};