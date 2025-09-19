const { User, Role, Permission, AuditLog } = require('../models');
const logger = require('../utils/logger');

class userController {
    /**
   * Get all users with pagination, filtering, and sorting
   */
    async getAllUsers(req, res) {
    try {
      const {
        page = 1,
        limit = 10,
        status,
        role,
        search,
        sortBy = 'createdAt',
        sortOrder = 'desc',
        includeDeleted = false
      } = req.query;

      // Build query
      const query = {};
      
      // Filter by status
      if (status) {
        query.status = status;
      }
      
      // Filter by role
      if (role) {
        const roleDoc = await Role.findOne({ name: role });
        if (roleDoc) {
          query.roles = roleDoc._id;
        }
      }
      
      // Search by name or email
      if (search) {
        query.$or = [
          { firstName: { $regex: search, $options: 'i' } },
          { lastName: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
          { username: { $regex: search, $options: 'i' } }
        ];
      }
      
      // Handle soft deleted users
      if (!includeDeleted || includeDeleted === 'false') {
        query.isDeleted = { $ne: true };
      }

      // Calculate pagination
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      const skip = (pageNum - 1) * limitNum;

      // Build sort object
      const sortObj = {};
      sortObj[sortBy] = sortOrder === 'asc' ? 1 : -1;

      // Execute query
      const users = await User.find(query)
        .select('-password -twoFactorSecret')
        .populate({
          path: 'roles',
          select: 'name displayName level color icon'
        })
        .sort(sortObj)
        .skip(skip)
        .limit(limitNum)
        .lean();

      // Get total count for pagination
      const totalUsers = await User.countDocuments(query);
      const totalPages = Math.ceil(totalUsers / limitNum);

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
        targetType: 'user',
        resource: 'user_list',
        status: 'success',
        category: 'user_management',
        endpoint: {
          method: req.method,
          path: req.path,
          query: req.query
        }
      });

      res.status(200).json({
        success: true,
        message: 'Users retrieved successfully',
        data: {
          users,
          pagination: {
            currentPage: pageNum,
            totalPages,
            totalUsers,
            hasNextPage: pageNum < totalPages,
            hasPrevPage: pageNum > 1,
            limit: limitNum
          },
          filters: {
            status,
            role,
            search,
            includeDeleted
          }
        }
      });

    } catch (error) {
      logger.error('Get all users error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve users',
        code: 'GET_USERS_ERROR'
      });
    }
  }
}