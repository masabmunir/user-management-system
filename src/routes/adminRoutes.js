const express = require('express');
const adminController = require('../controllers/adminController');
const { authenticate, authorize } = require('../middleware/auth');
const { query, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'src/uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `import-${Date.now()}${path.extname(file.originalname)}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'text/csv' || file.originalname.endsWith('.csv')) {
      cb(null, true);
    } else {
      cb(new Error('Only CSV files are allowed'));
    }
  }
});

// Validation middleware
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      code: 'VALIDATION_ERROR',
      details: errors.array()
    });
  }
  next();
};

// Validation rules
const activityLogsValidation = [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 200 }).withMessage('Limit must be between 1 and 200'),
  query('startDate').optional().isISO8601().withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate').optional().isISO8601().withMessage('End date must be a valid ISO 8601 date'),
  query('sortBy').optional().isIn(['createdAt', 'action', 'status']).withMessage('Invalid sort field'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc')
];

const exportUsersValidation = [
  query('status').optional().isIn(['active', 'inactive', 'pending', 'suspended', 'blocked']).withMessage('Invalid status'),
  query('role').optional().trim().isLength({ min: 1 }).withMessage('Role cannot be empty'),
  query('includeDeleted').optional().isBoolean().withMessage('Include deleted must be boolean')
];

// All routes require authentication and admin permissions
router.use(authenticate);

/**
 * @route   GET /api/admin/dashboard
 * @desc    Get system dashboard with overview statistics
 * @access  Private (requires system:audit permission)
 */
router.get(
  '/dashboard',
  authorize('system:audit'),
  adminController.getSystemDashboard
);

/**
 * @route   GET /api/admin/activity-logs
 * @desc    Get system activity logs with filtering
 * @access  Private (requires system:audit permission)
 */
router.get(
  '/activity-logs',
  authorize('system:audit'),
  activityLogsValidation,
  validateRequest,
  adminController.getActivityLogs
);

/**
 * @route   POST /api/admin/bulk-import-users
 * @desc    Bulk import users from CSV file
 * @access  Private (requires data:import permission)
 */
router.post(
  '/bulk-import-users',
  authorize('data:import'),
  upload.single('file'),
  adminController.bulkImportUsers
);

/**
 * @route   GET /api/admin/bulk-export-users
 * @desc    Bulk export users to CSV file
 * @access  Private (requires data:export permission)
 */
router.get(
  '/bulk-export-users',
  authorize('data:export'),
  exportUsersValidation,
  validateRequest,
  adminController.bulkExportUsers
);

/**
 * @route   GET /api/admin/health
 * @desc    Get system health status
 * @access  Private (requires system:audit permission)
 */
router.get(
  '/health',
  authorize('system:audit'),
  adminController.getSystemHealth
);

module.exports = router;