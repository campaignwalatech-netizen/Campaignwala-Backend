# Email Configuration Setup Guide

## Nodemailer Setup Complete! 📧

Aapke project me Nodemailer successfully setup ho gaya hai. Ab users ko email notifications milegi.

## Features Implemented ✨

1. **Login OTP via Email** - Jab user login karta hai, usko email pe OTP milega (Static OTP: 1006)
2. **Password Change OTP** - Password change karne se pehle email pe OTP verification
3. **Welcome Email** - Registration ke baad welcome email
4. **Beautiful Email Templates** - Professional looking HTML email templates

## Configuration Steps 🔧

### 1. Gmail App Password Setup (For Gmail Users)

Agar aap Gmail use kar rahe ho, to **App Password** generate karna hoga:

1. Gmail account me jao
2. **Google Account Settings** > **Security**
3. **2-Step Verification** enable karo (agar already nahi hai)
4. **App passwords** search karo
5. App select karo: **Mail**
6. Device select karo: **Other (Custom name)** - Type: "Campaignwala Backend"
7. **Generate** button click karo
8. 16-digit password copy karo (spaces ko ignore karo)

### 2. Update .env File

`.env` file me ye values update karo:

```env
# Email Configuration
EMAIL_SERVICE=gmail
EMAIL_USER=your_email@gmail.com
EMAIL_PASSWORD=your_16_digit_app_password_here
```

**Example:**
```env
EMAIL_SERVICE=gmail
EMAIL_USER=campaignwala@gmail.com
EMAIL_PASSWORD=abcd efgh ijkl mnop  # No spaces needed
```

### 3. Other Email Services

Agar Gmail ke alawa koi aur service use karna hai:

#### Outlook/Hotmail
```env
EMAIL_SERVICE=hotmail
EMAIL_USER=your_email@outlook.com
EMAIL_PASSWORD=your_password
```

#### Yahoo
```env
EMAIL_SERVICE=yahoo
EMAIL_USER=your_email@yahoo.com
EMAIL_PASSWORD=your_password
```

#### Custom SMTP
Agar custom SMTP use karna hai, to `src/utils/emailService.js` me ye change karo:

```javascript
const createTransporter = () => {
    return nodemailer.createTransporter({
        host: 'smtp.your-domain.com',
        port: 587,
        secure: false, // true for 465, false for other ports
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        }
    });
};
```

## How It Works 🚀

### Login Flow

1. **First Request** - User phone number aur password send karta hai
```json
POST /api/users/login
{
  "phoneNumber": "9876543210",
  "password": "password123"
}
```

2. **Response** - Email pe OTP bheja jata hai
```json
{
  "success": true,
  "message": "OTP sent to your registered email. Please verify to complete login.",
  "requireOTP": true,
  "emailSent": true,
  "data": {
    "phoneNumber": "9876543210",
    "email": "user@gmail.com"
  }
}
```

3. **Second Request** - User OTP ke saath login complete karta hai
```json
POST /api/users/login
{
  "phoneNumber": "9876543210",
  "password": "password123",
  "otp": "1006"
}
```

4. **Success Response**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": { ... },
    "token": "jwt_token_here"
  }
}
```

### Password Change Flow

1. **First Request** - Current aur new password send karo
```json
POST /api/users/change-password
Headers: { "Authorization": "Bearer <token>" }
{
  "currentPassword": "oldPass123",
  "newPassword": "newPass123"
}
```

2. **Response** - Email pe OTP bheja jata hai
```json
{
  "success": true,
  "message": "OTP sent to your registered email. Please verify to complete password change.",
  "requireOTP": true,
  "emailSent": true
}
```

3. **Second Request** - OTP ke saath confirm karo
```json
POST /api/users/change-password
Headers: { "Authorization": "Bearer <token>" }
{
  "currentPassword": "oldPass123",
  "newPassword": "newPass123",
  "otp": "1006"
}
```

## Static OTP 📌

Development mode ke liye **Static OTP: 1006** set hai.

`.env` file me:
```env
STATIC_OTP=1006
```

Production me isko change kar sakte ho ya dynamic OTP system implement kar sakte ho.

## Testing 🧪

### Test Karein (Without Email Configuration)
Agar email configure nahi hai, to bhi system kaam karega:
- Emails skip ho jayengi
- Console me logs milenge
- OTP validation kaam karega

### Test Karein (With Email Configuration)
Email configure karne ke baad:
1. Registration karo - Welcome email milega
2. Login karo - OTP email milega (1006)
3. Password change karo - OTP email milega (1006)

## Troubleshooting 🔍

### Email nahi ja raha?

1. **Gmail App Password check karo**
   - 16-digit password correctly copy kiya?
   - Spaces hataye
   - 2-Step Verification enabled hai?

2. **Email credentials check karo**
   ```bash
   # Check .env file
   cat .env | grep EMAIL
   ```

3. **Console logs check karo**
   - Server console me email logs milenge
   - "✅ Email sent successfully" dikhna chahiye

4. **Gmail "Less secure app" error**
   - Use **App Password** instead of regular password
   - Never use regular password for SMTP

### Common Errors

**Error: Invalid login**
- App Password use karo, regular password nahi

**Error: Connection timeout**
- Internet connection check karo
- Firewall settings check karo

**Error: Authentication failed**
- Email aur password verify karo
- Service name check karo (gmail, yahoo, etc.)

## Security Notes 🔒

1. **Never commit .env file** to Git
2. **Use App Passwords** for Gmail
3. **Enable 2FA** on email account
4. **Keep OTP validity short** (currently 10 minutes)
5. **In production**, dynamic OTP use karo

## Files Modified 📝

- ✅ `src/utils/emailService.js` - Email service created
- ✅ `src/modules/users/user.controller.js` - Login & password change updated
- ✅ `.env` - Email configuration added
- ✅ `package.json` - Nodemailer installed

## Next Steps 🎯

1. `.env` file me apna Gmail aur App Password add karo
2. Server restart karo: `npm start`
3. Login aur password change test karo
4. Email check karo

**Ready hai! 🎉**

---

**Note:** Agar koi problem aaye ya kuch samajh na aaye, to console logs check karo. Detailed logs available hain.
