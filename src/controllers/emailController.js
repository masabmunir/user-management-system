const crypto = require('crypto');
const { User, AuditLog } = require('../models');
const logger = require('../utils/logger');
const emailService = require('../services/emailService');
const { validationResult } = require('express-validator');

class EmailController {
  // Send verification email
  async sendVerificationEmail(req, res) {
    try {
      // Check for validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { email } = req.body;
      
      console.log('=== SEND VERIFICATION EMAIL STARTED ===');
      console.log('Email:', email);
      
      // Find user
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      console.log('User found, status:', user.status);
      console.log('Email verified:', user.emailVerified);

      if (user.emailVerified) {
        return res.status(400).json({
          success: false,
          error: 'Email already verified',
          code: 'ALREADY_VERIFIED'
        });
      }

      if (user.status === 'active') {
        return res.status(400).json({
          success: false,
          error: 'Account already active',
          code: 'ALREADY_ACTIVE'
        });
      }

      // Generate verification token
      console.log('Generating verification token...');
      const verificationToken = user.createEmailVerificationToken();
      await user.save();

      console.log('Verification token generated and saved');

      // In production, you would send an actual email here
      // For development/testing, we'll return the token
      // TODO: Replace with actual email service
      /*
      const emailService = require('../services/emailService');
      await emailService.sendVerificationEmail(user.email, verificationToken);
      */

      // Log the action
      await AuditLog.createEntry({
        action: 'email_verification_sent',
        actorType: 'user',
        userId: user._id,
        actorDetails: {
          email: user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: user._id,
        resource: 'email_verification',
        status: 'success',
        category: 'authentication'
      });

      logger.info(`Email verification token sent to: ${email}`);
      console.log('=== SEND VERIFICATION EMAIL COMPLETED ===');

      res.status(200).json({
        success: true,
        message: 'Verification email sent successfully',
        data: {
          message: 'Please check your email for verification instructions',
          // Remove this in production - only for development/testing
          ...(process.env.NODE_ENV === 'development' && { 
            verificationToken,
            verificationUrl: `http://localhost:${process.env.PORT || 3000}/api/email/verify/${verificationToken}`
          })
        }
      });

    } catch (error) {
      console.log('=== SEND VERIFICATION EMAIL ERROR ===');
      console.log('Error:', error.message);
      logger.error('Send verification email error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to send verification email',
        code: 'EMAIL_SEND_ERROR'
      });
    }
  }

  // Verify email and activate user
  async verifyEmail(req, res) {
    try {
      const { token } = req.params;

      console.log('=== EMAIL VERIFICATION STARTED ===');
      console.log('Token received:', !!token);
      console.log('Token length:', token?.length);

      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Verification token required',
          code: 'TOKEN_REQUIRED'
        });
      }

      // Hash the token to match database
      console.log('Hashing token for database lookup...');
      const hashedToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

      console.log('Looking for user with hashed token...');
      
      // Find user with valid token
      const user = await User.findOne({
        emailVerificationToken: hashedToken,
        emailVerificationExpires: { $gt: Date.now() }
      });

      console.log('User found:', !!user);

      if (!user) {
        console.log('Invalid or expired token');
        return res.status(400).json({
          success: false,
          error: 'Invalid or expired verification token',
          code: 'INVALID_TOKEN'
        });
      }

      console.log('Token valid, activating user...');
      console.log('User current status:', user.status);

      // Activate user
      user.emailVerified = true;
      user.status = 'active';
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      
      await user.save();

      console.log('User activated successfully');
      console.log('New status:', user.status);
      console.log('Email verified:', user.emailVerified);

      // Log the verification
      await AuditLog.createEntry({
        action: 'email_verification',
        actorType: 'user',
        userId: user._id,
        actorDetails: {
          email: user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: user._id,
        resource: 'authentication',
        status: 'success',
        category: 'security'
      });

      logger.info(`User email verified and activated: ${user.email}`);
      console.log('=== EMAIL VERIFICATION COMPLETED ===');

      res.status(200).json({
        success: true,
        message: 'Email verified successfully! Your account is now active and you can log in.',
        data: {
          user: {
            id: user._id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            status: user.status,
            emailVerified: user.emailVerified
          }
        }
      });

    } catch (error) {
      console.log('=== EMAIL VERIFICATION ERROR ===');
      console.log('Error:', error.message);
      console.log('Stack:', error.stack);
      
      logger.error('Email verification error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Email verification failed',
        code: 'VERIFICATION_ERROR'
      });
    }
  }

  // Resend verification email
  async resendVerificationEmail(req, res) {
    try {
      // Check for validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { email } = req.body;
      
      console.log('=== RESEND VERIFICATION EMAIL STARTED ===');
      console.log('Email:', email);
      
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      if (user.emailVerified) {
        return res.status(400).json({
          success: false,
          error: 'Email already verified',
          code: 'ALREADY_VERIFIED'
        });
      }

      if (user.status === 'active') {
        return res.status(400).json({
          success: false,
          error: 'Account already active',
          code: 'ALREADY_ACTIVE'
        });
      }

      // Generate new verification token
      const verificationToken = user.createEmailVerificationToken();
      await user.save();

      // Log the action
      await AuditLog.createEntry({
        action: 'email_verification_resent',
        actorType: 'user',
        userId: user._id,
        actorDetails: {
          email: user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: user._id,
        resource: 'email_verification',
        status: 'success',
        category: 'authentication'
      });

      logger.info(`Email verification resent to: ${email}`);
      console.log('=== RESEND VERIFICATION EMAIL COMPLETED ===');

      res.status(200).json({
        success: true,
        message: 'Verification email resent successfully',
        data: {
          message: 'Please check your email for new verification instructions',
          // Remove this in production
          ...(process.env.NODE_ENV === 'development' && { 
            verificationToken,
            verificationUrl: `http://localhost:${process.env.PORT || 3000}/api/email/verify/${verificationToken}`
          })
        }
      });

    } catch (error) {
      console.log('=== RESEND VERIFICATION EMAIL ERROR ===');
      console.log('Error:', error.message);
      logger.error('Resend verification email error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to resend verification email',
        code: 'EMAIL_RESEND_ERROR'
      });
    }
  }
}

module.exports = new EmailController();