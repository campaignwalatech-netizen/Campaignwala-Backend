/**
 * 🔐 LOGIN WITH OTP - COMPLETE TESTING GUIDE
 * Static OTP: 1006
 * Updated: November 6, 2025
 */

// ============================================
// 🎯 LOGIN FLOW (2-Step Process)
// ============================================

/**
 * STEP 1: Send Phone Number & Password
 * Backend will:
 * - Verify credentials
 * - Generate & store OTP
 * - Send OTP to email (for users) or show static OTP (for admin)
 * - Return requireOTP: true
 */

// Example Request - Step 1
POST /api/users/login
Content-Type: application/json

{
  "phoneNumber": "9876543210",
  "password": "yourPassword123"
}

// Example Response - Step 1 (Admin)
{
  "success": true,
  "message": "OTP sent to your registered mobile number. Please verify to complete login.",
  "requireOTP": true,
  "otpType": "mobile",
  "data": {
    "phoneNumber": "9876543210",
    "role": "admin",
    "otpSent": true,
    "useStatic": true,
    "otp": "1006"  // ✅ Static OTP shown for admin
  }
}

// Example Response - Step 1 (User)
{
  "success": true,
  "message": "OTP sent to your registered email. Please verify to complete login.",
  "requireOTP": true,
  "otpType": "email",
  "data": {
    "phoneNumber": "9876543210",
    "email": "user@gmail.com",
    "role": "user",
    "otpSent": true
  }
}

/**
 * STEP 2: Send Phone Number, Password & OTP
 * Backend will:
 * - Verify OTP
 * - Generate JWT token
 * - Return user data & token
 */

// Example Request - Step 2
POST /api/users/login
Content-Type: application/json

{
  "phoneNumber": "9876543210",
  "password": "yourPassword123",
  "otp": "1006"  // Static OTP
}

// Example Response - Step 2 (Success)
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "_id": "64abc123...",
      "phoneNumber": "9876543210",
      "name": "John Doe",
      "email": "john@gmail.com",
      "role": "user",
      "isVerified": true,
      "isActive": true
      // ... other user fields
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}

// Example Response - Step 2 (Invalid OTP)
{
  "success": false,
  "message": "Invalid OTP"
}

// Example Response - Step 2 (Expired OTP)
{
  "success": false,
  "message": "OTP has expired. Please request a new one."
}


// ============================================
// 📱 POSTMAN TESTING
// ============================================

/**
 * Collection: Campaignwala - Login with OTP
 * 
 * Request 1: Login Step 1 - Get OTP
 * - Method: POST
 * - URL: {{base_url}}/api/users/login
 * - Body (raw JSON):
 *   {
 *     "phoneNumber": "9876543210",
 *     "password": "yourPassword123"
 *   }
 * - Test Script:
 *   pm.test("OTP Required", function() {
 *     pm.expect(pm.response.json().requireOTP).to.be.true;
 *   });
 * 
 * Request 2: Login Step 2 - Verify OTP
 * - Method: POST
 * - URL: {{base_url}}/api/users/login
 * - Body (raw JSON):
 *   {
 *     "phoneNumber": "9876543210",
 *     "password": "yourPassword123",
 *     "otp": "1006"
 *   }
 * - Test Script:
 *   pm.test("Login Successful", function() {
 *     var jsonData = pm.response.json();
 *     pm.expect(jsonData.success).to.be.true;
 *     pm.expect(jsonData.data.token).to.exist;
 *     pm.environment.set("token", jsonData.data.token);
 *   });
 */


// ============================================
// 🧪 CURL TESTING
// ============================================

// Step 1: Get OTP
curl -X POST http://localhost:5000/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210",
    "password": "yourPassword123"
  }'

// Step 2: Verify OTP and Complete Login
curl -X POST http://localhost:5000/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210",
    "password": "yourPassword123",
    "otp": "1006"
  }'


// ============================================
// 🎨 FRONTEND IMPLEMENTATION GUIDE
// ============================================

/**
 * React/JavaScript Example
 */

// Step 1: Initial Login Request
const handleLogin = async (phoneNumber, password) => {
  try {
    const response = await axios.post('/api/users/login', {
      phoneNumber,
      password
    });

    if (response.data.requireOTP) {
      // Show OTP input form
      setShowOtpInput(true);
      setOtpMessage(response.data.message);
      
      // If admin, show the OTP (1006)
      if (response.data.data.otp) {
        setStaticOtp(response.data.data.otp);
      }
    } else {
      // Direct login (no OTP required)
      handleLoginSuccess(response.data);
    }
  } catch (error) {
    console.error('Login error:', error);
    showError(error.response?.data?.message || 'Login failed');
  }
};

// Step 2: Verify OTP
const handleVerifyOtp = async (phoneNumber, password, otp) => {
  try {
    const response = await axios.post('/api/users/login', {
      phoneNumber,
      password,
      otp
    });

    if (response.data.success) {
      // Save token and redirect
      localStorage.setItem('token', response.data.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.data.user));
      navigate('/dashboard');
    }
  } catch (error) {
    console.error('OTP verification error:', error);
    showError(error.response?.data?.message || 'Invalid OTP');
  }
};


// ============================================
// ⚙️ BACKEND CONFIGURATION
// ============================================

/**
 * .env file settings:
 */
// Static OTP (for development & admin)
STATIC_OTP=1006

// Email Configuration (for user OTP)
EMAIL_SERVICE=gmail
EMAIL_USER=your_email@gmail.com
EMAIL_PASSWORD=your_16_digit_app_password

// JWT Configuration
JWT_SECRET=your_jwt_secret_here
JWT_EXPIRE=7d


// ============================================
// 🔍 DEBUGGING & LOGS
// ============================================

/**
 * Console logs to check:
 */

// Server logs will show:
// 🔐 Verifying OTP for login...
//    User OTP from DB: 1006
//    Provided OTP: 1006
//    Static OTP: 1006
// ✅ OTP verified successfully

// Admin login logs:
// 👑 Admin login detected - using static OTP
// 🔑 Static OTP: 1006

// User login logs:
// 📧 Sending login OTP to user email: user@gmail.com
// ✅ Login OTP email sent successfully to user


// ============================================
// 🚨 COMMON ERRORS & SOLUTIONS
// ============================================

/**
 * Error: "Invalid OTP"
 * Solution: 
 * - Check if OTP is exactly "1006"
 * - Verify user has emailOtp field in database
 * - Check OTP hasn't expired (10 minutes validity)
 * 
 * Error: "OTP has expired"
 * Solution:
 * - Request new OTP by sending Step 1 again
 * 
 * Error: "No email configured"
 * Solution:
 * - User must have email in their profile
 * - Update user email in database
 * 
 * Error: "Failed to send OTP email"
 * Solution:
 * - Check EMAIL_USER and EMAIL_PASSWORD in .env
 * - Verify Gmail App Password is correct
 * - Check internet connection
 */


// ============================================
// 📊 USER ROLES & OTP TYPES
// ============================================

/**
 * Admin Users:
 * - Role: "admin"
 * - OTP Type: Mobile (Static OTP shown in response)
 * - Static OTP: 1006
 * - OTP shown in response: Yes
 * 
 * Regular Users:
 * - Role: "user"
 * - OTP Type: Email
 * - Dynamic OTP: Generated fresh each time
 * - OTP shown in response: No (sent via email only)
 */


// ============================================
// ✅ TESTING CHECKLIST
// ============================================

/**
 * [ ] Test admin login with static OTP 1006
 * [ ] Test user login with email OTP
 * [ ] Test invalid OTP error
 * [ ] Test expired OTP error
 * [ ] Test invalid credentials
 * [ ] Test inactive account
 * [ ] Test login without OTP (should fail)
 * [ ] Test OTP resend by calling Step 1 again
 * [ ] Verify JWT token is returned
 * [ ] Verify OTP is cleared after successful login
 * [ ] Check email template formatting
 * [ ] Verify 10-minute OTP expiry works
 */


// ============================================
// 🎯 QUICK START
// ============================================

/**
 * 1. Start server:
 *    npm start
 * 
 * 2. Test admin login:
 *    - Phone: Use any admin phone number
 *    - Password: Admin password
 *    - OTP: 1006 (static)
 * 
 * 3. Test user login:
 *    - Phone: Use any user phone number
 *    - Password: User password
 *    - OTP: Check email for dynamic OTP
 * 
 * 4. Use token in subsequent requests:
 *    Authorization: Bearer <token>
 */

module.exports = {
  // Export for testing utilities
  STATIC_OTP: '1006',
  OTP_EXPIRY_MINUTES: 10,
  LOGIN_ENDPOINT: '/api/users/login'
};
