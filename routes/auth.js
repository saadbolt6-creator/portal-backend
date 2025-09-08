const express = require('express');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const generateToken = require('../utils/generateToken');
const sendEmail = require('../utils/sendEmail');
const { getWelcomeEmailTemplate, getPasswordResetEmailTemplate } = require('../utils/emailTemplates');
const { protect } = require('../middleware/auth');
const { requireEmailVerification } = require('../middleware/emailVerification');
const { validateCompanyDomain } = require('../middleware/domainValidation');
const { validateEmailMiddleware } = require('../middleware/emailValidation');
const seedAdmin = require('../utils/seedAdmin');
const Company = require('../models/Company');
const User = require('../models/User');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const router = express.Router();

// @desc    Validate email endpoint
// @route   POST /api/auth/validate-email
// @access  Public
router.post('/validate-email', validateEmailMiddleware, async (req, res) => {
  try {
    res.json({
      success: true,
      message: 'Email is valid and can receive messages',
      data: {
        valid: true,
        reason: req.emailValidation.reason
      }
    });
  } catch (error) {
    console.error('Email validation error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during email validation'
    });
  }
});

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
router.post('/register', validateEmailMiddleware, validateCompanyDomain, [
  body('firstName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email'),
  body('company')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Company name must be between 2 and 100 characters'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { firstName, lastName, email, company, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      company,
      password,
      isEmailVerified: false,
      emailValidated: true // Mark as validated since we checked it
    });

    // Generate email verification token
    const verificationToken = user.generateEmailVerificationToken();
    await user.save({ validateBeforeSave: false });

    // Create verification URL
    const verificationUrl = `http://localhost:5000/api/auth/verify-email/${verificationToken}`;

    try {
      // Send verification email
      await sendEmail({
        email: user.email,
        subject: 'Email Verification - Saher Flow Solutions',
        html: getWelcomeEmailTemplate(user.firstName, verificationUrl)
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully. Please check your email to verify your account.',
        data: {
          user: {
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            company: user.company,
            isEmailVerified: user.isEmailVerified
          }
        }
      });
    } catch (emailError) {
      console.error('Verification email failed:', emailError);
      
      // Delete user if email fails to send
      await User.findByIdAndDelete(user._id);
      
      res.status(500).json({
        success: false,
        message: 'Registration failed. Could not send verification email. Please try again.'
      });
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
});

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
router.post('/login', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  body('twoFactorToken')
    .optional()
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('2FA token must be exactly 6 digits')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password, twoFactorToken, backupCode } = req.body;

    // Check if user exists and get password
    const user = await User.findOne({ email }).select('+password +twoFactorSecret');
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check if account is active
    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account has been deactivated. Please contact support.'
      });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // If 2FA is enabled, verify the token
    if (user.twoFactorEnabled) {
      if (!twoFactorToken && !backupCode) {
        return res.status(200).json({
          success: false,
          message: '2FA token required',
          requiresTwoFactor: true,
          data: {
            tempUserId: user._id // Don't expose this in production, use a temporary token instead
          }
        });
      }

      let twoFactorValid = false;

      if (backupCode) {
        // Verify backup code
        twoFactorValid = user.verifyBackupCode(backupCode);
        if (twoFactorValid) {
          await user.save(); // Save the used backup code
        }
      } else if (twoFactorToken) {
        // Verify TOTP token
        const cleanToken = twoFactorToken.toString().replace(/\D/g, '');
        twoFactorValid = user.verify2FAToken(cleanToken);
      }

      if (!twoFactorValid) {
        return res.status(401).json({
          success: false,
          message: 'Invalid 2FA token or backup code. Please ensure you are using the latest code from your authenticator app.'
        });
      }
    }

    // Get user's IP address
    const getUserIP = (req) => {
      return req.headers['x-forwarded-for'] || 
             req.headers['x-real-ip'] || 
             req.connection.remoteAddress || 
             req.socket.remoteAddress ||
             (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
             req.ip;
    };

    const rawIP = getUserIP(req);
    
    // Convert IPv6 loopback to IPv4 for better readability
    let userIP = rawIP;
    if (rawIP === '::1' || rawIP === '::ffff:127.0.0.1') {
      userIP = '127.0.0.1'; // localhost
    } else if (rawIP && rawIP.startsWith('::ffff:')) {
      // Extract IPv4 from IPv6-mapped address
      userIP = rawIP.substring(7);
    }

    // Update last login and IP
    user.lastLogin = new Date();
    user.lastLoginIP = userIP;
    await user.save({ validateBeforeSave: false });

    // Generate token
    const token = generateToken(user._id);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          company: user.company,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          lastLogin: user.lastLogin,
          lastLoginIP: user.lastLoginIP,
          twoFactorEnabled: user.twoFactorEnabled
        }
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
});

// @desc    Setup 2FA
// @route   POST /api/auth/setup-2fa
// @access  Private
router.post('/setup-2fa', protect, requireEmailVerification, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+twoFactorSecret');
    
    if (user.twoFactorEnabled) {
      return res.status(400).json({
        success: false,
        message: '2FA is already enabled'
      });
    }

    // Generate 2FA secret
    const secret = user.generate2FASecret();
    await user.save();

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json({
      success: true,
      message: '2FA setup initiated',
      data: {
        secret: secret.base32,
        qrCode: qrCodeUrl,
        manualEntryKey: secret.base32,
        issuer: 'Saher Flow Solutions',
        accountName: user.email,
        instructions: 'Scan the QR code with your authenticator app or manually enter the secret key. Then enter the 6-digit code to verify and enable 2FA.'
      }
    });
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during 2FA setup'
    });
  }
});

// @desc    Verify and enable 2FA
// @route   POST /api/auth/verify-2fa
// @access  Private
router.post('/verify-2fa', protect, requireEmailVerification, [
  body('token')
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('Token must be exactly 6 digits')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { token } = req.body;
    
    // Clean the token - remove any spaces or non-numeric characters
    const cleanToken = token.toString().replace(/\D/g, '');
    
    if (cleanToken.length !== 6) {
      return res.status(400).json({
        success: false,
        message: 'Token must be exactly 6 digits'
      });
    }
    
    const user = await User.findById(req.user._id).select('+twoFactorSecret');

    if (user.twoFactorEnabled) {
      return res.status(400).json({
        success: false,
        message: '2FA is already enabled'
      });
    }

    if (!user.twoFactorSecret) {
      return res.status(400).json({
        success: false,
        message: 'Please setup 2FA first'
      });
    }

    // Verify the token
    const isValid = user.verify2FAToken(cleanToken);
    
    if (!isValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid 2FA token. Please ensure you are using the latest code from your authenticator app.'
      });
    }

    // Enable 2FA and generate backup codes
    user.twoFactorEnabled = true;
    const backupCodes = user.generateBackupCodes();
    await user.save();

    res.json({
      success: true,
      message: '2FA enabled successfully',
      data: {
        backupCodes
      }
    });
  } catch (error) {
    console.error('2FA verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during 2FA verification'
    });
  }
});

// @desc    Disable 2FA
// @route   POST /api/auth/disable-2fa
// @access  Private
router.post('/disable-2fa', protect, requireEmailVerification, [
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  body('token')
    .optional()
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('Token must be exactly 6 digits'),
  body('backupCode')
    .optional()
    .isLength({ min: 8, max: 8 })
    .withMessage('Backup code must be 8 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { password, token, backupCode } = req.body;
    const user = await User.findById(req.user._id).select('+password +twoFactorSecret');

    if (!user.twoFactorEnabled) {
      return res.status(400).json({
        success: false,
        message: '2FA is not enabled'
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid password'
      });
    }

    // Verify 2FA token or backup code
    let twoFactorValid = false;
    
    if (backupCode) {
      twoFactorValid = user.verifyBackupCode(backupCode);
    } else if (token) {
      const cleanToken = token.toString().replace(/\D/g, '');
      twoFactorValid = user.verify2FAToken(cleanToken);
    } else {
      return res.status(400).json({
        success: false,
        message: '2FA token or backup code is required'
      });
    }

    if (!twoFactorValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid 2FA token or backup code'
      });
    }

    // Disable 2FA
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    user.twoFactorBackupCodes = [];
    await user.save();

    res.json({
      success: true,
      message: '2FA disabled successfully'
    });
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during 2FA disable'
    });
  }
});

// @desc    Generate new backup codes
// @route   POST /api/auth/generate-backup-codes
// @access  Private
router.post('/generate-backup-codes', protect, requireEmailVerification, [
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  body('token')
    .optional()
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('Token must be exactly 6 digits'),
  body('backupCode')
    .optional()
    .isLength({ min: 8, max: 8 })
    .withMessage('Backup code must be 8 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { password, token, backupCode } = req.body;
    const user = await User.findById(req.user._id).select('+password +twoFactorSecret');

    if (!user.twoFactorEnabled) {
      return res.status(400).json({
        success: false,
        message: '2FA is not enabled'
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid password'
      });
    }

    // Verify 2FA token or backup code
    let twoFactorValid = false;
    
    if (backupCode) {
      twoFactorValid = user.verifyBackupCode(backupCode);
    } else if (token) {
      const cleanToken = token.toString().replace(/\D/g, '');
      twoFactorValid = user.verify2FAToken(cleanToken);
    } else {
      return res.status(400).json({
        success: false,
        message: '2FA token or backup code is required'
      });
    }

    if (!twoFactorValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid 2FA token or backup code'
      });
    }

    // Generate new backup codes
    const newBackupCodes = user.generateBackupCodes();
    await user.save();

    res.json({
      success: true,
      message: 'New backup codes generated successfully',
      data: {
        backupCodes: newBackupCodes
      }
    });
  } catch (error) {
    console.error('Generate backup codes error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error generating backup codes'
    });
  }
});

// @desc    Verify email
// @route   GET /api/auth/verify-email/:token
// @access  Public
router.get('/verify-email/:token', async (req, res) => {
  try {
    // Hash the token from URL
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    // Find user with this token
    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token'
      });
    }

    // Verify email
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save({ validateBeforeSave: false });

    // Send HTML response for better user experience
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verified - Saher Flow Solutions</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #1a3a5c 0%, #153149 100%); padding: 30px; text-align: center; }
          .header h1 { color: #ffd500; margin: 0; font-size: 28px; }
          .content { padding: 30px; text-align: center; }
          .success-icon { font-size: 48px; color: #28a745; margin-bottom: 20px; }
          .btn { background: #ffd500; color: #1a3a5c; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; margin-top: 20px; }
          .btn:hover { background: #e6c200; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Saher Flow Solutions</h1>
          </div>
          <div class="content">
            <div class="success-icon">✅</div>
            <h2 style="color: #1a3a5c;">Email Verified Successfully!</h2>
            <p>Your email address has been verified. You can now access all features of your account.</p>
            <a href="${process.env.CLIENT_URL || 'http://localhost:5173'}" class="btn">Go to Dashboard</a>
            <p style="margin-top: 30px; color: #666; font-size: 14px;">
              You can now close this window and return to the application.
            </p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during email verification'
    });
  }
});

// @desc    Forgot password
// @route   POST /api/auth/forgot-password
// @access  Public
router.post('/forgot-password', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'No user found with this email address'
      });
    }

    // Generate reset token
    const resetToken = user.generatePasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // Create reset URL
    const resetUrl = `http://localhost:5000/api/auth/reset-password/${resetToken}`;

    try {
      // Send password reset email
      await sendEmail({
        email: user.email,
        subject: 'Password Reset Request - Saher Flow Solutions',
        html: getPasswordResetEmailTemplate(user.firstName, resetUrl)
      });

      res.json({
        success: true,
        message: 'Password reset email sent successfully'
      });
    } catch (emailError) {
      console.error('Password reset email failed:', emailError);
      
      // Clear reset token if email fails
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
      
      res.status(500).json({
        success: false,
        message: 'Could not send password reset email'
      });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during password reset request'
    });
  }
});

// @desc    Reset password
// @route   PUT /api/auth/reset-password/:token
// @access  Public
router.get('/reset-password/:token', async (req, res) => {
  try {
    // Hash the token from URL
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    // Find user with this token
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Invalid Reset Link - Saher Flow Solutions</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #1a3a5c 0%, #153149 100%); padding: 30px; text-align: center; }
            .header h1 { color: #ffd500; margin: 0; font-size: 28px; }
            .content { padding: 30px; text-align: center; }
            .error-icon { font-size: 48px; color: #dc3545; margin-bottom: 20px; }
            .btn { background: #ffd500; color: #1a3a5c; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Saher Flow Solutions</h1>
            </div>
            <div class="content">
              <div class="error-icon">❌</div>
              <h2 style="color: #dc3545;">Invalid or Expired Reset Link</h2>
                This window will automatically redirect you to the login page in 5 seconds.
              <a href="${process.env.CLIENT_URL || 'http://localhost:5173'}/forgot-password" class="btn">Request New Reset</a>
            </div>
          </div>
          <script>
            setTimeout(() => {
              window.location.href = '${process.env.CLIENT_URL || 'http://localhost:5173'}/login';
            }, 5000);
          </script>
        </body>
        </html>
      `);
    }

    // Show password reset form
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Password - Saher Flow Solutions</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #1a3a5c 0%, #153149 100%); padding: 30px; text-align: center; }
          .header h1 { color: #ffd500; margin: 0; font-size: 28px; }
          .content { padding: 30px; }
          .form-group { margin-bottom: 20px; }
          .form-group label { display: block; margin-bottom: 5px; font-weight: bold; color: #1a3a5c; }
          .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; box-sizing: border-box; }
          .btn { background: #ffd500; color: #1a3a5c; padding: 12px 30px; border: none; border-radius: 5px; font-weight: bold; cursor: pointer; width: 100%; font-size: 16px; }
          .btn:hover { background: #e6c200; }
          .btn:disabled { background: #ccc; cursor: not-allowed; }
          .message { padding: 10px; border-radius: 5px; margin-bottom: 20px; }
          .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
          .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Reset Your Password</h1>
          </div>
          <div class="content">
            <div id="message"></div>
            <form id="resetForm">
              <div class="form-group">
                <label for="password">New Password:</label>
                <input type="password" id="password" name="password" required minlength="6">
                <small style="color: #666;">Must be at least 6 characters with uppercase, lowercase, and number</small>
              </div>
              <div class="form-group">
                <label for="confirmPassword">Confirm Password:</label>
                <input type="password" id="confirmPassword" name="confirmPassword" required>
              </div>
              <button type="submit" class="btn" id="submitBtn">Reset Password</button>
            </form>
          </div>
        </div>
        
        <script>
          document.getElementById('resetForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const messageDiv = document.getElementById('message');
            const submitBtn = document.getElementById('submitBtn');
            
            // Clear previous messages
            messageDiv.innerHTML = '';
            
            // Validate passwords match
            if (password !== confirmPassword) {
              messageDiv.innerHTML = '<div class="message error">Passwords do not match</div>';
              return;
            }
            
            // Validate password strength
            if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)/.test(password)) {
              messageDiv.innerHTML = '<div class="message error">Password must contain at least one uppercase letter, one lowercase letter, and one number</div>';
              return;
            }
            
            submitBtn.disabled = true;
            submitBtn.textContent = 'Resetting...';
            
            try {
              const response = await fetch('/api/auth/reset-password/${req.params.token}', {
                method: 'PUT',
                headers: {
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
              });
              
              const data = await response.json();
              
              if (data.success) {
                messageDiv.innerHTML = '<div class="message success">Password reset successful! You can now login with your new password.</div>';
                document.getElementById('resetForm').style.display = 'none';
                messageDiv.innerHTML += '<div class="message success">Redirecting to login page...</div>';
                setTimeout(() => {
                  window.location.href = '${process.env.CLIENT_URL || 'http://localhost:5173'}/login';
                }, 3000);
              } else {
                messageDiv.innerHTML = '<div class="message error">' + data.message + '</div>';
              }
            } catch (error) {
              messageDiv.innerHTML = '<div class="message error">Network error. Please try again.</div>';
            }
            
            submitBtn.disabled = false;
            submitBtn.textContent = 'Reset Password';
          });
        </script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Password reset page error:', error);
    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Error - Saher Flow Solutions</title>
      </head>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1>Server Error</h1>
        <p>Something went wrong. Please try again later.</p>
      </body>
      </html>
    `);
  }
});

// @desc    Reset password (API endpoint)
// @route   PUT /api/auth/reset-password/:token
// @access  Public
router.put('/reset-password/:token', [
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    // Hash the token from URL
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    // Find user with this token
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token'
      });
    }

    // Set new password
    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Generate new token
    const token = generateToken(user._id);

    res.json({
      success: true,
      message: 'Password reset successful',
      data: {
        token,
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          company: user.company,
          role: user.role,
          isEmailVerified: user.isEmailVerified
        }
      }
    });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during password reset'
    });
  }
});

// @desc    Resend verification email
// @route   POST /api/auth/resend-verification
// @access  Public
router.post('/resend-verification', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'No user found with this email address'
      });
    }

    // Check if already verified
    if (user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        message: 'Email is already verified'
      });
    }

    // Generate new verification token
    const verificationToken = user.generateEmailVerificationToken();
    await user.save({ validateBeforeSave: false });

    // Create verification URL
    const verificationUrl = `${process.env.API_URL || 'http://localhost:5000'}/api/auth/verify-email/${verificationToken}`;

    try {
      // Send verification email
      await sendEmail({
        email: user.email,
        subject: 'Email Verification - Saher Flow Solutions',
        html: getWelcomeEmailTemplate(user.firstName, verificationUrl)
      });

      res.json({
        success: true,
        message: 'Verification email sent successfully'
      });
    } catch (emailError) {
      console.error('Verification email failed:', emailError);
      res.status(500).json({
        success: false,
        message: 'Could not send verification email'
      });
    }
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during verification email resend'
    });
  }
});

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
router.get('/me', protect, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: req.user
      }
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error getting user data'
    });
  }
});

// @desc    Logout user
// @route   POST /api/auth/logout
// @access  Private
router.post('/logout', protect, async (req, res) => {
  try {
    // In a stateless JWT system, logout is handled client-side
    // But we can track logout time if needed
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during logout'
    });
  }
});

module.exports = router;