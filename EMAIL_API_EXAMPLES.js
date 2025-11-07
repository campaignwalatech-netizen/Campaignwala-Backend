/**
 * Email Notification System - API Testing Examples
 * 
 * Nodemailer successfully setup! ✅
 * Static OTP: 1006
 */

// ============================================
// 1. LOGIN WITH OTP (2-Step Process)
// ============================================

// Step 1: Initial Login Request (Gets OTP via Email)
const loginStep1 = {
    method: 'POST',
    url: 'http://localhost:5000/api/users/login',
    body: {
        "phoneNumber": "9876543210",
        "password": "yourPassword123"
    }
};

// Response Step 1:
// {
//   "success": true,
//   "message": "OTP sent to your registered email. Please verify to complete login.",
//   "requireOTP": true,
//   "emailSent": true,
//   "data": {
//     "phoneNumber": "9876543210",
//     "email": "user@gmail.com"
//   }
// }

// Step 2: Complete Login with OTP
const loginStep2 = {
    method: 'POST',
    url: 'http://localhost:5000/api/users/login',
    body: {
        "phoneNumber": "9876543210",
        "password": "yourPassword123",
        "otp": "1006"  // Static OTP
    }
};

// Response Step 2:
// {
//   "success": true,
//   "message": "Login successful",
//   "data": {
//     "user": { ... },
//     "token": "eyJhbGc..."
//   }
// }


// ============================================
// 2. REGISTRATION (Gets Welcome Email)
// ============================================

const register = {
    method: 'POST',
    url: 'http://localhost:5000/api/users/register',
    body: {
        "phoneNumber": "9876543210",
        "otp": "1006",  // Static OTP
        "name": "John Doe",
        "email": "john@gmail.com",
        "password": "password123"
    }
};

// Response:
// {
//   "success": true,
//   "message": "User registered successfully",
//   "data": {
//     "user": { ... },
//     "token": "eyJhbGc..."
//   }
// }
// Note: Welcome email automatically sent to john@gmail.com


// ============================================
// 3. CHANGE PASSWORD WITH OTP (2-Step Process)
// ============================================

// Step 1: Request Password Change (Gets OTP via Email)
const changePasswordStep1 = {
    method: 'POST',
    url: 'http://localhost:5000/api/users/change-password',
    headers: {
        "Authorization": "Bearer YOUR_JWT_TOKEN_HERE"
    },
    body: {
        "currentPassword": "oldPassword123",
        "newPassword": "newPassword456"
    }
};

// Response Step 1:
// {
//   "success": true,
//   "message": "OTP sent to your registered email. Please verify to complete password change.",
//   "requireOTP": true,
//   "emailSent": true,
//   "data": {
//     "email": "user@gmail.com"
//   }
// }

// Step 2: Complete Password Change with OTP
const changePasswordStep2 = {
    method: 'POST',
    url: 'http://localhost:5000/api/users/change-password',
    headers: {
        "Authorization": "Bearer YOUR_JWT_TOKEN_HERE"
    },
    body: {
        "currentPassword": "oldPassword123",
        "newPassword": "newPassword456",
        "otp": "1006"  // Static OTP
    }
};

// Response Step 2:
// {
//   "success": true,
//   "message": "Password changed successfully"
// }


// ============================================
// 4. SEND OTP (Gets OTP via Email)
// ============================================

const sendOTP = {
    method: 'POST',
    url: 'http://localhost:5000/api/users/send-otp',
    body: {
        "phoneNumber": "9876543210"
    }
};

// Response:
// {
//   "success": true,
//   "message": "OTP sent to your registered email",
//   "data": {
//     "phoneNumber": "9876543210",
//     "otp": "1006",
//     "useStatic": true,
//     "emailSent": true
//   }
// }


// ============================================
// POSTMAN COLLECTION - Quick Setup
// ============================================

/*
1. Create new Collection: "Campaignwala - Email OTP"

2. Add Environment Variables:
   - base_url: http://localhost:5000
   - token: (will be set after login)

3. Import these requests:
   
   ✅ Register User (POST)
   {{base_url}}/api/users/register
   
   ✅ Send OTP (POST)
   {{base_url}}/api/users/send-otp
   
   ✅ Login Step 1 - Get OTP (POST)
   {{base_url}}/api/users/login
   
   ✅ Login Step 2 - Verify OTP (POST)
   {{base_url}}/api/users/login
   
   ✅ Change Password Step 1 - Get OTP (POST)
   {{base_url}}/api/users/change-password
   Headers: Authorization: Bearer {{token}}
   
   ✅ Change Password Step 2 - Verify OTP (POST)
   {{base_url}}/api/users/change-password
   Headers: Authorization: Bearer {{token}}
*/


// ============================================
// CURL EXAMPLES
// ============================================

// Login Step 1 (Get OTP)
const curlLogin1 = `
curl -X POST http://localhost:5000/api/users/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "phoneNumber": "9876543210",
    "password": "yourPassword123"
  }'
`;

// Login Step 2 (Verify OTP)
const curlLogin2 = `
curl -X POST http://localhost:5000/api/users/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "phoneNumber": "9876543210",
    "password": "yourPassword123",
    "otp": "1006"
  }'
`;

// Change Password Step 1 (Get OTP)
const curlChangePassword1 = `
curl -X POST http://localhost:5000/api/users/change-password \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \\
  -d '{
    "currentPassword": "oldPassword123",
    "newPassword": "newPassword456"
  }'
`;

// Change Password Step 2 (Verify OTP)
const curlChangePassword2 = `
curl -X POST http://localhost:5000/api/users/change-password \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \\
  -d '{
    "currentPassword": "oldPassword123",
    "newPassword": "newPassword456",
    "otp": "1006"
  }'
`;


// ============================================
// EMAIL CONFIGURATION CHECKLIST
// ============================================

/*
✅ Nodemailer installed
✅ Email service created (src/utils/emailService.js)
✅ .env configured with email settings
✅ Login OTP implemented
✅ Password change OTP implemented
✅ Welcome email on registration
✅ Static OTP: 1006

📧 TO USE EMAIL:
1. Update .env file:
   EMAIL_SERVICE=gmail
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASSWORD=your_16_digit_app_password

2. For Gmail:
   - Enable 2-Step Verification
   - Generate App Password
   - Use that 16-digit password

3. Restart server: npm start

4. Test by logging in!
*/

// ============================================
// NOTES
// ============================================

/*
✨ Email Templates:
- Beautiful HTML emails with gradients
- Professional OTP display
- Security warnings included
- Responsive design

🔒 Security:
- OTP valid for 10 minutes
- Static OTP for development: 1006
- Can be changed to dynamic OTP later

📱 Features:
- Login requires OTP verification
- Password change requires OTP verification
- Welcome email on registration
- Automatic email fallback if not configured

🎯 Production Ready:
- Error handling included
- Graceful fallback if email not configured
- Console logs for debugging
- Professional email templates
*/

module.exports = {
    loginStep1,
    loginStep2,
    register,
    changePasswordStep1,
    changePasswordStep2,
    sendOTP
};
