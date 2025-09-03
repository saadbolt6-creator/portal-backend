const express = require('express');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const sendEmail = require('../utils/sendEmail');
const { getWelcomeEmailTemplate, getPasswordResetEmailTemplate } = require('../utils/emailTemplates');
const { protect, generateTokenWithVersion, generateToken, getClientIP } = require('../middleware/auth');
const { validateCompanyDomain } = require('../middleware/domainValidation');
const User = require('../models/User');
const Company = require('../models/Company');
const LoginHistory = require('../models/LoginHistory');

const router = express.Router();

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
router.post('/register', validateCompanyDomain, [
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
      company: req.companyInfo.name, // Use company name from database
      password,
      isEmailVerified: false
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
    .withMessage('Password is required')
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
    const clientIP = getClientIP(req);
    const userAgent = req.headers['user-agent'] || 'Unknown';

    // Check if user exists and get password
    const user = await User.findOne({ email }).select('+password +twoFactorSecret');
    if (!user) {
      // Log failed login attempt
      await LoginHistory.create({
        userId: null,
        ipAddress: clientIP,
        userAgent,
        loginStatus: 'failed',
        failureReason: 'User not found'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check if account is active
    if (!user.isActive) {
      await LoginHistory.create({
        userId: user._id,
        ipAddress: clientIP,
        userAgent,
        loginStatus: 'blocked',
        failureReason: 'Account deactivated'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Account has been deactivated. Please contact support.'
      });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      await LoginHistory.create({
        userId: user._id,
        ipAddress: clientIP,
        userAgent,
        loginStatus: 'failed',
        failureReason: 'Invalid password'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check 2FA if enabled
    if (user.isTwoFactorEnabled) {
      let twoFactorValid = false;
      
      if (twoFactorToken) {
        // Simple 2FA check - you can implement this later if needed
        twoFactorValid = false;
      } else if (backupCode) {
        // Simple backup code check - you can implement this later if needed
        twoFactorValid = false;
      }
      
      if (!twoFactorValid) {
        await LoginHistory.create({
          userId: user._id,
          ipAddress: clientIP,
          userAgent,
          loginStatus: 'failed',
          failureReason: '2FA verification failed'
        });
        
        return res.status(401).json({
          success: false,
          message: 'Two-factor authentication required',
          requiresTwoFactor: true
        });
      }
    }

    // Update last login
    user.lastLogin = new Date();
    user.lastIpAddress = clientIP;
    user.currentIpAddress = clientIP;
    await user.save({ validateBeforeSave: false });

    // Log successful login
    const loginRecord = await LoginHistory.create({
      userId: user._id,
      ipAddress: clientIP,
      userAgent,
      loginStatus: 'success'
    });

    // Add to user's login history
    user.loginHistory.push(loginRecord._id);
    await user.save({ validateBeforeSave: false });

    // Generate token with version
    const token = generateTokenWithVersion(user._id, user.tokenVersion);

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
          ipAddress: clientIP
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

// @desc    Renew token
// @route   POST /api/auth/renew-token
// @access  Private
router.post('/renew-token', protect, async (req, res) => {
  try {
    // Generate new token with current version
    const newToken = generateTokenWithVersion(req.user._id, req.user.tokenVersion);

    res.json({
      success: true,
      message: 'Token renewed successfully',
      data: {
        token: newToken
      }
    });
  } catch (error) {
    console.error('Token renewal error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error renewing token'
    });
  }
});

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
router.get('/me', protect, async (req, res) => {
  try {
    // Renew token on every request
    const newToken = generateTokenWithVersion(req.user._id, req.user.tokenVersion);
    
    res.json({
      success: true,
      data: {
        user: req.user,
        token: newToken // Send renewed token
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
    // Optionally invalidate all tokens for this user
    if (req.body.logoutAllDevices) {
      await req.user.invalidateAllTokens();
    }
    
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