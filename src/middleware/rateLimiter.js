const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

// Create rate limiter by IP
const rateLimitByIP = (options = {}) => {
  const defaultOptions = {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
      success: false,
      error: 'Too many requests from this IP. Please try again later.',
      code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Custom handler to log rate limit hits
    handler: (req, res) => {
      logger.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
      res.status(429).json(options.message || defaultOptions.message);
    }
  };

  return rateLimit({ ...defaultOptions, ...options });
};

// Specific rate limiters for different endpoints
const authRateLimit = rateLimitByIP({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 login attempts per 15 minutes
  message: {
    success: false,
    error: 'Too many authentication attempts. Please try again later.',
    code: 'AUTH_RATE_LIMIT_EXCEEDED'
  }
});

const emailRateLimit = rateLimitByIP({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 email requests per 15 minutes
  message: {
    success: false,
    error: 'Too many email requests. Please try again later.',
    code: 'EMAIL_RATE_LIMIT_EXCEEDED'
  }
});

const generalAPIRateLimit = rateLimitByIP({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // 1000 requests per 15 minutes
  message: {
    success: false,
    error: 'Too many API requests. Please try again later.',
    code: 'API_RATE_LIMIT_EXCEEDED'
  }
});

module.exports = {
  rateLimitByIP,
  authRateLimit,
  emailRateLimit,
  generalAPIRateLimit
};