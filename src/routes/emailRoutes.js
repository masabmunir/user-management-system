const express = require('express');
const { body, param } = require('express-validator');
const emailController = require('../controllers/emailController');
const { rateLimitByIP } = require('../middleware/rateLimiter');

const router = express.Router();

// Rate limiting for email endpoints (prevent spam)
const emailRateLimit = rateLimitByIP({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 emails per 15 minutes per IP
  message: {
    success: false,
    error: 'Too many email requests. Please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// Send verification email
router.post('/send-verification',
  emailRateLimit,
  [
    body('email')
      .isEmail()
      .withMessage('Valid email address is required')
      .normalizeEmail()
      .isLength({ min: 5, max: 254 })
      .withMessage('Email must be between 5 and 254 characters')
  ],
  emailController.sendVerificationEmail
);

// Verify email with token
router.get('/verify/:token',
  [
    param('token')
      .isLength({ min: 64, max: 64 })
      .withMessage('Invalid verification token format')
      .matches(/^[a-f0-9]{64}$/)
      .withMessage('Token must be a valid hexadecimal string')
  ],
  emailController.verifyEmail
);

// Resend verification email
router.post('/resend-verification',
  emailRateLimit,
  [
    body('email')
      .isEmail()
      .withMessage('Valid email address is required')
      .normalizeEmail()
      .isLength({ min: 5, max: 254 })
      .withMessage('Email must be between 5 and 254 characters')
  ],
  emailController.resendVerificationEmail
);

module.exports = router;
