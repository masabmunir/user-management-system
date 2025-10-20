const { User, Role, Permission, AuditLog } = require('../models');
const logger = require('../utils/logger');
const csv = require('csv-parser');
const { createObjectCsvStringifier } = require('csv-writer');
const fs = require('fs').promises;
const streamFs = require('fs');
const path = require('path');

class AdminController {
  // System Dashboard - Overview of entire system
  async getSystemDashboard(req, res) {
    try {
      console.log('=== SYSTEM DASHBOARD STARTED ===');

      // Get current date ranges
      const now = new Date();
      const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const last7Days = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const last30Days = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

      // User Statistics
      const totalUsers = await User.countDocuments({ isDeleted: { $ne: true } });
      const activeUsers = await User.countDocuments({ status: 'active', isDeleted: { $ne: true } });
      const newUsersLast24h = await User.countDocuments({ 
        createdAt: { $gte: last24Hours },
        isDeleted: { $ne: true }
      });
      const newUsersLast7Days = await User.countDocuments({ 
        createdAt: { $gte: last7Days },
        isDeleted: { $ne: true }
      });

      // Role & Permission Statistics
      const totalRoles = await Role.countDocuments({ isDeleted: { $ne: true } });
      const totalPermissions = await Permission.countDocuments({ isDeleted: { $ne: true } });

      // Activity Statistics
      const totalLogins24h = await AuditLog.countDocuments({
        action: 'login',
        createdAt: { $gte: last24Hours }
      });

      const failedLogins24h = await AuditLog.countDocuments({
        action: 'login',
        status: 'failure',
        createdAt: { $gte: last24Hours }
      });

      // Recent Activity
      const recentActivity = await AuditLog.find()
        .sort({ createdAt: -1 })
        .limit(10)
        .populate('userId', 'username email firstName lastName')
        .lean();

      // Active Sessions
      const usersWithActiveSessions = await User.countDocuments({
        'activeSessions.0': { $exists: true },
        isDeleted: { $ne: true }
      });

      // Security Alerts (suspicious activities)
      const suspiciousActivities = await AuditLog.countDocuments({
        riskScore: { $gte: 7 },
        createdAt: { $gte: last7Days }
      });

      // User Growth Trend (last 7 days)
      const userGrowthTrend = await User.aggregate([
        {
          $match: {
            createdAt: { $gte: last7Days },
            isDeleted: { $ne: true }
          }
        },
        {
          $group: {
            _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ]);

      // Log activity
      await AuditLog.createEntry({
        action: 'read',
        actorType: 'user',
        userId: req.user.id,
        actorDetails: {
          username: req.user.username,
          email: req.user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'system',
        targetId: req.user.id,
        resource: 'system_dashboard',
        status: 'success',
        category: 'admin'
      });

      res.status(200).json({
        success: true,
        message: 'System dashboard data retrieved successfully',
        data: {
          overview: {
            totalUsers,
            activeUsers,
            totalRoles,
            totalPermissions,
            usersWithActiveSessions
          },
          userActivity: {
            newUsersLast24h,
            newUsersLast7Days,
            totalLogins24h,
            failedLogins24h
          },
          security: {
            suspiciousActivities,
            failedLoginRate: totalLogins24h > 0 ? 
              ((failedLogins24h / totalLogins24h) * 100).toFixed(2) + '%' : '0%'
          },
          trends: {
            userGrowth: userGrowthTrend
          },
          recentActivity: recentActivity.map(activity => ({
            id: activity._id,
            action: activity.action,
            user: activity.userId ? {
              username: activity.userId.username,
              email: activity.userId.email
            } : { username: 'System' },
            resource: activity.resource,
            status: activity.status,
            timestamp: activity.createdAt
          })),
          lastUpdated: new Date()
        }
      });

    } catch (error) {
      console.log('System dashboard error:', error.message);
      logger.error('Get system dashboard error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve system dashboard',
        code: 'DASHBOARD_ERROR'
      });
    }
  }

  // Get System Activity Logs with filtering
  async getActivityLogs(req, res) {
    try {
      const {
        page = 1,
        limit = 50,
        action,
        status,
        userId,
        startDate,
        endDate,
        category,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Build query
      const query = {};
      
      if (action) query.action = action;
      if (status) query.status = status;
      if (userId) query.userId = userId;
      if (category) query.category = category;
      
      if (startDate || endDate) {
        query.createdAt = {};
        if (startDate) query.createdAt.$gte = new Date(startDate);
        if (endDate) query.createdAt.$lte = new Date(endDate);
      }

      // Pagination
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      const skip = (pageNum - 1) * limitNum;

      // Sort
      const sortObj = {};
      sortObj[sortBy] = sortOrder === 'asc' ? 1 : -1;

      // Execute query
      const logs = await AuditLog.find(query)
        .populate('userId', 'username email firstName lastName')
        .sort(sortObj)
        .skip(skip)
        .limit(limitNum)
        .lean();

      const totalLogs = await AuditLog.countDocuments(query);
      const totalPages = Math.ceil(totalLogs / limitNum);

      res.status(200).json({
        success: true,
        message: 'Activity logs retrieved successfully',
        data: {
          logs,
          pagination: {
            currentPage: pageNum,
            totalPages,
            totalLogs,
            hasNextPage: pageNum < totalPages,
            hasPrevPage: pageNum > 1,
            limit: limitNum
          },
          filters: { action, status, userId, startDate, endDate, category }
        }
      });

    } catch (error) {
      logger.error('Get activity logs error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve activity logs',
        code: 'ACTIVITY_LOGS_ERROR'
      });
    }
  }

  // Bulk User Import (CSV)
async bulkImportUsers(req, res) {
  try {
    console.log('=== BULK IMPORT STARTED ===');
    
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'CSV file is required',
        code: 'FILE_REQUIRED'
      });
    }

    const results = [];
    const errors = [];
    let successCount = 0;
    let errorCount = 0;
    let rowNumber = 1;

    // Use csv-parser for proper CSV parsing
    const csvParser = require('csv-parser');
    const streamFs = require('fs');
    
    const users = [];
    
    // Parse CSV with proper library
    await new Promise((resolve, reject) => {
      streamFs.createReadStream(req.file.path)
        .pipe(csvParser())
        .on('data', (row) => {
          users.push({ row: ++rowNumber, data: row });
        })
        .on('end', resolve)
        .on('error', reject);
    });

    console.log('Parsed users:', users.length);

    // Validate required fields from first row
    if (users.length > 0) {
      const firstRow = users[0].data;
      const requiredFields = ['firstName', 'lastName', 'email', 'username'];
      const missingFields = requiredFields.filter(field => !(field in firstRow));
      
      if (missingFields.length > 0) {
        await fs.unlink(req.file.path);
        return res.status(400).json({
          success: false,
          error: `Missing required columns: ${missingFields.join(', ')}`,
          code: 'INVALID_CSV_FORMAT'
        });
      }
    }

    // Process each row
    for (const { row, data } of users) {
      try {
        // Skip rows with empty required fields
        if (!data.firstName || !data.lastName || !data.email || !data.username) {
          errors.push({
            row,
            data,
            error: 'Missing required fields'
          });
          errorCount++;
          continue;
        }

        // Check if user already exists
        const existingUser = await User.findOne({
          $or: [
            { email: data.email.trim() },
            { username: data.username.trim() }
          ]
        });

        if (existingUser) {
          errors.push({
            row,
            data,
            error: 'User with this email or username already exists'
          });
          errorCount++;
          continue;
        }

        // Create user with default password
        const defaultPassword = 'ChangeMe123!';
        const user = new User({
          firstName: data.firstName.trim(),
          lastName: data.lastName.trim(),
          email: data.email.trim(),
          username: data.username.trim(),
          password: defaultPassword,
          status: 'pending',
          emailVerified: false,
          createdBy: req.user.id
        });

        await user.save();
        
        results.push({
          row,
          username: user.username,
          email: user.email,
          status: 'success'
        });
        successCount++;

      } catch (error) {
        console.log('Error creating user:', error.message);
        errors.push({
          row,
          data,
          error: error.message
        });
        errorCount++;
      }
    }

    // Clean up uploaded file
    await fs.unlink(req.file.path);

    // Log activity
    await AuditLog.createEntry({
      action: 'import_data',
      actorType: 'user',
      userId: req.user.id,
      actorDetails: {
        username: req.user.username,
        email: req.user.email,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      },
      targetType: 'system',
      targetId: req.user.id,
      resource: 'bulk_user_import',
      status: errorCount === 0 ? 'success' : 'partial',
      category: 'admin'
    });

    logger.info(`Bulk user import completed: ${successCount} success, ${errorCount} errors`);

    res.status(200).json({
      success: true,
      message: 'Bulk user import completed',
      data: {
        summary: {
          totalProcessed: successCount + errorCount,
          successCount,
          errorCount
        },
        results,
        errors: errors.length > 0 ? errors : undefined
      }
    });

  } catch (error) {
    console.log('=== BULK IMPORT ERROR ===');
    console.log('Error:', error.message);
    
    logger.error('Bulk import users error:', error.message);
    
    // Clean up file if exists
    if (req.file && req.file.path) {
      await fs.unlink(req.file.path).catch(() => {});
    }
    
    res.status(500).json({
      success: false,
      error: 'Failed to import users',
      code: 'BULK_IMPORT_ERROR'
    });
  }
}


  // Bulk User Export (CSV)
  async bulkExportUsers(req, res) {
    try {
      const { status, role, includeDeleted = false } = req.query;

      // Build query
      const query = {};
      if (status) query.status = status;
      if (!includeDeleted || includeDeleted === 'false') {
        query.isDeleted = { $ne: true };
      }

      // Get users
      const users = await User.find(query)
        .populate('roles', 'name displayName')
        .select('-password -twoFactorSecret')
        .lean();

      // Filter by role if specified
      let filteredUsers = users;
      if (role) {
        filteredUsers = users.filter(user => 
          user.roles.some(r => r.name === role)
        );
      }

      // Prepare CSV data
      const csvData = filteredUsers.map(user => ({
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        status: user.status,
        emailVerified: user.emailVerified,
        roles: user.roles.map(r => r.displayName).join('; '),
        createdAt: user.createdAt,
        lastLogin: user.lastLogin || 'Never'
      }));

      // Create CSV
      const csvStringifier = createObjectCsvStringifier({
        header: [
          { id: 'username', title: 'Username' },
          { id: 'email', title: 'Email' },
          { id: 'firstName', title: 'First Name' },
          { id: 'lastName', title: 'Last Name' },
          { id: 'status', title: 'Status' },
          { id: 'emailVerified', title: 'Email Verified' },
          { id: 'roles', title: 'Roles' },
          { id: 'createdAt', title: 'Created At' },
          { id: 'lastLogin', title: 'Last Login' }
        ]
      });

      const csvContent = csvStringifier.getHeaderString() + csvStringifier.stringifyRecords(csvData);

      // Log activity
      await AuditLog.createEntry({
        action: 'export_data',
        actorType: 'user',
        userId: req.user.id,
        actorDetails: {
          username: req.user.username,
          email: req.user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'system',
        targetId: req.user.id,
        resource: 'bulk_user_export',
        status: 'success',
        category: 'admin',
        details: {
          userCount: filteredUsers.length,
          filters: { status, role, includeDeleted }
        }
      });

      logger.info(`Bulk user export: ${filteredUsers.length} users by ${req.user.username}`);

      // Send CSV file
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=users-export-${Date.now()}.csv`);
      res.status(200).send(csvContent);

    } catch (error) {
      logger.error('Bulk export users error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to export users',
        code: 'BULK_EXPORT_ERROR'
      });
    }
  }

  // System Health Check
  async getSystemHealth(req, res) {
    try {
      const health = {
        status: 'healthy',
        timestamp: new Date(),
        services: {}
      };

      // Check database connection
      try {
        await User.findOne().limit(1);
        health.services.database = { status: 'healthy', responseTime: 'fast' };
      } catch (error) {
        health.services.database = { status: 'unhealthy', error: error.message };
        health.status = 'degraded';
      }

      // Check memory usage
      const memUsage = process.memoryUsage();
      health.services.memory = {
        status: memUsage.heapUsed < memUsage.heapTotal * 0.9 ? 'healthy' : 'warning',
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`
      };

      // System uptime
      health.uptime = process.uptime();
      health.environment = process.env.NODE_ENV;

      res.status(200).json({
        success: true,
        data: health
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Health check failed',
        code: 'HEALTH_CHECK_ERROR'
      });
    }
  }
}

module.exports = new AdminController();