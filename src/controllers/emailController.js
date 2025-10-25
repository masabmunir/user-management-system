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
      
      logger.info(`=== SEND VERIFICATION EMAIL STARTED ===`);
      logger.info(`Email: ${email}`);
      
      // Find user
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      logger.info(`User found - Status: ${user.status}, Email verified: ${user.emailVerified}`);

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
      logger.info('Generating verification token...');
      const verificationToken = user.createEmailVerificationToken();
      await user.save();
      logger.info('Verification token generated and saved');

      // Send verification email using email service
      try {
        await emailService.sendVerificationEmail(
          user.email,
          verificationToken,
          user.firstName || user.username
        );
        logger.info(`✓ Verification email sent successfully to: ${email}`);
      } catch (emailError) {
        logger.error(`✗ Failed to send email: ${emailError.message}`);
        // Continue anyway - token is saved, user can request resend
      }

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

      logger.info(`=== SEND VERIFICATION EMAIL COMPLETED ===`);

      res.status(200).json({
        success: true,
        message: 'Verification email sent successfully',
        data: {
          message: 'Please check your email for verification instructions',
          email: user.email,
          expiresIn: '24 hours',
          // Only show in development mode
          ...(process.env.NODE_ENV === 'development' && { 
            verificationToken,
            verificationUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email/${verificationToken}`,
            note: 'Token shown only in development mode'
          })
        }
      });

    } catch (error) {
      logger.error('=== SEND VERIFICATION EMAIL ERROR ===');
      logger.error(`Error: ${error.message}`);
      
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

      logger.info('=== EMAIL VERIFICATION STARTED ===');
      logger.info(`Token received: ${!!token}`);

      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Verification token required',
          code: 'TOKEN_REQUIRED'
        });
      }

      // Hash the token to match database
      logger.info('Hashing token for database lookup...');
      const hashedToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

      logger.info('Looking for user with valid token...');
      
      // Find user with valid token
      const user = await User.findOne({
        emailVerificationToken: hashedToken,
        emailVerificationExpires: { $gt: Date.now() }
      });

      logger.info(`User found: ${!!user}`);

      if (!user) {
        logger.warn('Invalid or expired token');
        return res.status(400).json({
          success: false,
          error: 'Invalid or expired verification token',
          code: 'INVALID_TOKEN',
          message: 'The verification link has expired or is invalid. Please request a new verification email.'
        });
      }

      logger.info(`Token valid, activating user: ${user.email}`);
      logger.info(`Current status: ${user.status}`);

      // Activate user
      user.emailVerified = true;
      user.status = 'active';
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      
      await user.save();

      logger.info(`✓ User activated successfully`);
      logger.info(`New status: ${user.status}, Email verified: ${user.emailVerified}`);

      // Send welcome email
      try {
        await emailService.sendWelcomeEmail(
          user.email,
          user.firstName || user.username
        );
        logger.info(`✓ Welcome email sent to: ${user.email}`);
      } catch (emailError) {
        logger.error(`✗ Failed to send welcome email: ${emailError.message}`);
        // Don't fail the verification if welcome email fails
      }

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

      logger.info(`=== EMAIL VERIFICATION COMPLETED ===`);

      res.status(200).json({
        success: true,
        message: 'Email verified successfully! Your account is now active and you can log in.',
        data: {
          user: {
            id: user._id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            username: user.username,
            status: user.status,
            emailVerified: user.emailVerified
          },
          nextSteps: {
            message: 'You can now log in to your account',
            loginUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login`
          }
        }
      });

    } catch (error) {
      logger.error('=== EMAIL VERIFICATION ERROR ===');
      logger.error(`Error: ${error.message}`);
      logger.error(`Stack: ${error.stack}`);
      
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
      
      logger.info('=== RESEND VERIFICATION EMAIL STARTED ===');
      logger.info(`Email: ${email}`);
      
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
      logger.info('Generating new verification token...');
      const verificationToken = user.createEmailVerificationToken();
      await user.save();
      logger.info('New verification token generated');

      // Send verification email using email service
      try {
        await emailService.sendVerificationEmail(
          user.email,
          verificationToken,
          user.firstName || user.username
        );
        logger.info(`✓ Verification email resent successfully to: ${email}`);
      } catch (emailError) {
        logger.error(`✗ Failed to send email: ${emailError.message}`);
        // Continue anyway - token is saved
      }

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

      logger.info('=== RESEND VERIFICATION EMAIL COMPLETED ===');

      res.status(200).json({
        success: true,
        message: 'Verification email resent successfully',
        data: {
          message: 'Please check your email for new verification instructions',
          email: user.email,
          expiresIn: '24 hours',
          // Only show in development mode
          ...(process.env.NODE_ENV === 'development' && { 
            verificationToken,
            verificationUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email/${verificationToken}`,
            note: 'Token shown only in development mode'
          })
        }
      });

    } catch (error) {
      logger.error('=== RESEND VERIFICATION EMAIL ERROR ===');
      logger.error(`Error: ${error.message}`);
      
      res.status(500).json({
        success: false,
        error: 'Failed to resend verification email',
        code: 'EMAIL_RESEND_ERROR'
      });
    }
  }
}

module.exports = new EmailController();