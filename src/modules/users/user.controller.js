const jwt = require('jsonwebtoken');
const User = require('./user.model');

// Generate JWT token
const generateToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE || '7d'
    });
};

// Send OTP (static for now)
const sendOTP = async (req, res) => {
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

        let user = await User.findOne({ phoneNumber });

        if (user) {
            // Check OTP rate limiting
            if (!user.canSendOtp()) {
                return res.status(429).json({
                    success: false,
                    message: 'Too many OTP attempts. Please try again later'
                });
            }

            user.incrementOtpAttempts();
            await user.save();
        }

        // In production, integrate with SMS service
        // For now, return static OTP for development
        res.json({
            success: true,
            message: 'OTP sent successfully',
            data: {
                phoneNumber,
                otp: process.env.STATIC_OTP // Remove this in production
            }
        });

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
        const { phoneNumber, password, otp } = req.body;

        // Validation
        if (!phoneNumber || !password || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Phone number, password, and OTP are required'
            });
        }

        // Verify OTP (static check for development)
        if (otp !== process.env.STATIC_OTP) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
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

        // Create new user
        const user = new User({
            phoneNumber,
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
    deleteUser,
    getDashboardStats
};