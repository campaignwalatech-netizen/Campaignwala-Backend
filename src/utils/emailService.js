const nodemailer = require('nodemailer');

// Create transporter with email configuration (singleton with connection pooling)
let transporter = null;

const createTransporter = () => {
    if (!transporter) {
        transporter = nodemailer.createTransport({
            service: process.env.EMAIL_SERVICE || 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            },
            pool: true, // Use connection pooling
            maxConnections: 5,
            maxMessages: 100,
            rateDelta: 1000,
            rateLimit: 5
        });
    }
    return transporter;
};

// HTML template for OTP email
const getOTPEmailTemplate = (userName, otp, purpose = 'verification') => {
    const purposeText = {
        'login': 'Login',
        'verification': 'Account Verification',
        'password-change': 'Password Change',
        'registration': 'Registration',
        'profile-update': 'Profile Update'
    };

    return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }
            .container {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .content {
                background: white;
                border-radius: 8px;
                padding: 30px;
                text-align: center;
            }
            .logo {
                font-size: 28px;
                font-weight: bold;
                color: #667eea;
                margin-bottom: 20px;
            }
            .otp-box {
                background: #f7f7f7;
                border: 2px dashed #667eea;
                border-radius: 8px;
                padding: 20px;
                margin: 25px 0;
                font-size: 32px;
                font-weight: bold;
                color: #667eea;
                letter-spacing: 8px;
            }
            .message {
                color: #666;
                font-size: 16px;
                margin: 20px 0;
            }
            .warning {
                background: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 12px;
                margin: 20px 0;
                font-size: 14px;
                color: #856404;
            }
            .footer {
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                font-size: 12px;
                color: #999;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="content">
                <div class="logo">🚀 Campaignwala</div>
                <h2>OTP for ${purposeText[purpose] || 'Verification'}</h2>
                <p class="message">Hello <strong>${userName}</strong>,</p>
                <p class="message">Your One-Time Password (OTP) is:</p>
                <div class="otp-box">${otp}</div>
                <p class="message">This OTP is valid for <strong>10 minutes</strong>.</p>
                <div class="warning">
                    ⚠️ <strong>Security Alert:</strong> Never share this OTP with anyone. Campaignwala will never ask for your OTP.
                </div>
                <p class="message">If you didn't request this OTP, please ignore this email.</p>
                <div class="footer">
                    <p>© ${new Date().getFullYear()} Campaignwala. All rights reserved.</p>
                    <p>This is an automated email, please do not reply.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    `;
};

// Send OTP email via SMTP
const sendOTPEmail = async (email, userName, otp, purpose = 'verification') => {
    try {
        console.log('📧 Preparing to send OTP email...');
        console.log('   FROM:', process.env.EMAIL_USER);
        console.log('   TO:', email);
        console.log('   Name:', userName);
        console.log('   OTP:', otp);
        console.log('   Purpose:', purpose);
        
        // Check if email credentials are configured
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
            console.error('❌ Email credentials not configured in .env file');
            throw new Error('Email service not configured');
        }

        // Create SMTP transporter (reuses pooled connection)
        const transporter = createTransporter();
        
        // Prepare email subject
        const purposeSubject = {
            'login': 'Login OTP',
            'verification': 'Account Verification OTP',
            'password-change': 'Password Change OTP',
            'registration': 'Registration OTP',
            'profile-update': 'Profile Update OTP'
        };

        // Email options
        const mailOptions = {
            from: {
                name: 'Campaignwala',
                address: process.env.EMAIL_USER
            },
            to: email,
            subject: `${purposeSubject[purpose] || 'Verification OTP'} - Campaignwala`,
            html: getOTPEmailTemplate(userName, otp, purpose)
        };

        console.log('📤 Sending email...');
        const info = await transporter.sendMail(mailOptions);
        
        console.log('✅ Email sent successfully!');
        console.log('   Message ID:', info.messageId);
        console.log('   Response:', info.response);
        
        return {
            success: true,
            message: 'OTP sent to email successfully',
            messageId: info.messageId
        };
        
    } catch (error) {
        console.error('❌ Failed to send email:', error.message);
        console.error('   Error details:', error);
        
        // Return error instead of fallback
        throw new Error(`Email sending failed: ${error.message}`);
    }
};

// Send welcome email
const sendWelcomeEmail = async (email, userName) => {
    try {
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
            console.log('⚠️ Email service not configured. Skipping welcome email.');
            return { success: false };
        }

        const transporter = createTransporter();
        
        const mailOptions = {
            from: {
                name: 'Campaignwala',
                address: process.env.EMAIL_USER
            },
            to: email,
            subject: 'Welcome to Campaignwala! 🎉',
            html: `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                    }
                    .container {
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        border-radius: 10px;
                        padding: 30px;
                    }
                    .content {
                        background: white;
                        border-radius: 8px;
                        padding: 30px;
                        text-align: center;
                    }
                    .logo {
                        font-size: 32px;
                        margin-bottom: 20px;
                    }
                    h1 {
                        color: #667eea;
                        margin-bottom: 20px;
                    }
                    .message {
                        color: #666;
                        font-size: 16px;
                        margin: 20px 0;
                    }
                    .footer {
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                        font-size: 12px;
                        color: #999;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="content">
                        <div class="logo">🚀</div>
                        <h1>Welcome to Campaignwala!</h1>
                        <p class="message">Hello <strong>${userName}</strong>,</p>
                        <p class="message">Thank you for registering with Campaignwala! We're excited to have you on board.</p>
                        <p class="message">You can now explore our platform and start your journey with us.</p>
                        <p class="message">If you have any questions, feel free to reach out to our support team.</p>
                        <div class="footer">
                            <p>© ${new Date().getFullYear()} Campaignwala. All rights reserved.</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log('✅ Welcome email sent successfully');
        return { success: true };
    } catch (error) {
        console.error('❌ Welcome email error:', error.message);
        return { success: false, error: error.message };
    }
};

module.exports = {
    sendOTPEmail,
    sendWelcomeEmail
};
