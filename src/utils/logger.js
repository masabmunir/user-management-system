const winston = require('winston');
const { time } = require('console');
const path = require('path');
const { level } = require('winston');

// Define log format

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Define console format for development
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, stack }) => {
      return `${timestamp} [${level}]: ${stack || message}`;
    })
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
  format: logFormat,
  defaultMeta: { service: 'user-management-system' },
  transports: [
    // Write all logs with importance level of `error` or less to error.log
    new winston.transports.File({
      filename: path.join('logs', 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    
    // Write all logs with importance level of `info` or less to combined.log
    new winston.transports.File({
      filename: path.join('logs', 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
  ],
});

// If we're not in production, also log to the console
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat
  }));
}

// Create logs directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// Create function to log user activities
logger.logUserActivity = (userId, action, details = {}) => {
  logger.info('User Activity', {
    userId,
    action,
    details,
    timestamp: new Date().toISOString(),
    type: 'USER_ACTIVITY'
  });
};

// Create function to log security events
logger.logSecurityEvent = (event, details = {}) => {
  logger.warn('Security Event', {
    event,
    details,
    timestamp: new Date().toISOString(),
    type: 'SECURITY_EVENT'
  });
};

module.exports = logger;