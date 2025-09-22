const { User, Role, AuditLog } = require('../models');
const logger = require('../utils/logger');

class UserController {
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

  /**
   * Get single user by ID
   */
  async getUserById(req, res) {
    try {
      const { userId } = req.params;

      const user = await User.findById(userId)
        .select('-password -twoFactorSecret')
        .populate({
          path: 'roles',
          populate: {
            path: 'permissions',
            select: 'name displayName description category'
          }
        })
        .lean();

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Collect all permissions from roles
      const allPermissions = new Set();
      if (user.roles) {
        user.roles.forEach(role => {
          if (role.permissions) {
            role.permissions.forEach(permission => {
              allPermissions.add(permission);
            });
          }
        });
      }

      user.allPermissions = Array.from(allPermissions);

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
        targetId: userId,
        resource: 'user_profile',
        status: 'success',
        category: 'user_management'
      });

      res.status(200).json({
        success: true,
        message: 'User retrieved successfully',
        data: { user }
      });

    } catch (error) {
      logger.error('Get user by ID error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve user',
        code: 'GET_USER_ERROR'
      });
    }
  }

  /**
   * Update user information
   */
  async updateUser(req, res) {
    try {
      const { userId } = req.params;
      const updateData = req.body;

      // Remove sensitive fields from update
      delete updateData.password;
      delete updateData.roles;
      delete updateData._id;
      delete updateData.createdAt;
      delete updateData.updatedAt;

      const user = await User.findById(userId);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Store original values for audit
      const originalValues = {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        username: user.username,
        status: user.status,
        profile: user.profile
      };

      // Update user
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        {
          ...updateData,
          updatedBy: req.user.id
        },
        { 
          new: true,
          runValidators: true
        }
      ).select('-password -twoFactorSecret');

      // Log activity
      await AuditLog.createEntry({
        action: 'update',
        actorType: 'user',
        userId: req.user.id,
        actorDetails: {
          username: req.user.username,
          email: req.user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: userId,
        targetDetails: {
          name: updatedUser.fullName,
          previousValues: originalValues,
          newValues: updateData
        },
        resource: 'user_profile',
        status: 'success',
        category: 'user_management'
      });

      logger.info(`User updated: ${updatedUser.email} by ${req.user.email}`);

      res.status(200).json({
        success: true,
        message: 'User updated successfully',
        data: { user: updatedUser }
      });

    } catch (error) {
      logger.error('Update user error:', error.message);

      // Handle validation errors
      if (error.name === 'ValidationError') {
        return res.status(400).json({
          success: false,
          error: 'Validation failed',
          code: 'VALIDATION_ERROR',
          details: Object.values(error.errors).map(e => e.message)
        });
      }

      res.status(500).json({
        success: false,
        error: 'Failed to update user',
        code: 'UPDATE_USER_ERROR'
      });
    }
  }

  /**
   * Delete user (soft delete)
   */
  async deleteUser(req, res) {
    try {
      const { userId } = req.params;

      const user = await User.findById(userId);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Prevent self-deletion
      if (userId === req.user.id) {
        return res.status(400).json({
          success: false,
          error: 'Cannot delete your own account',
          code: 'SELF_DELETE_ERROR'
        });
      }

      // Soft delete
      await User.findByIdAndUpdate(userId, {
        isDeleted: true,
        deletedAt: new Date(),
        deletedBy: req.user.id,
        status: 'inactive'
      });

      // Log activity
      await AuditLog.createEntry({
        action: 'delete',
        actorType: 'user',
        userId: req.user.id,
        actorDetails: {
          username: req.user.username,
          email: req.user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: userId,
        targetDetails: {
          name: user.fullName,
          identifier: user.email
        },
        resource: 'user_profile',
        status: 'success',
        category: 'user_management'
      });

      logger.info(`User deleted: ${user.email} by ${req.user.email}`);

      res.status(200).json({
        success: true,
        message: 'User deleted successfully'
      });

    } catch (error) {
      logger.error('Delete user error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to delete user',
        code: 'DELETE_USER_ERROR'
      });
    }
  }

  /**
   * Activate/Deactivate user account
   */
  async toggleUserStatus(req, res) {
    try {
      const { userId } = req.params;
      const { status } = req.body;

      // Validate status
      const validStatuses = ['active', 'inactive', 'suspended', 'blocked'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid status',
          code: 'INVALID_STATUS',
          validStatuses
        });
      }

      const user = await User.findById(userId);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Prevent changing own status
      if (userId === req.user.id) {
        return res.status(400).json({
          success: false,
          error: 'Cannot change your own account status',
          code: 'SELF_STATUS_CHANGE_ERROR'
        });
      }

      const oldStatus = user.status;
      
      // Update user status
      await User.findByIdAndUpdate(userId, {
        status,
        updatedBy: req.user.id
      });

      // Log activity
      await AuditLog.createEntry({
        action: 'update',
        actorType: 'user',
        userId: req.user.id,
        actorDetails: {
          username: req.user.username,
          email: req.user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: userId,
        targetDetails: {
          name: user.fullName,
          previousValues: { status: oldStatus },
          newValues: { status }
        },
        resource: 'user_status',
        status: 'success',
        category: 'user_management'
      });

      logger.info(`User status changed: ${user.email} from ${oldStatus} to ${status} by ${req.user.email}`);

      res.status(200).json({
        success: true,
        message: `User ${status === 'active' ? 'activated' : status} successfully`,
        data: {
          userId,
          oldStatus,
          newStatus: status
        }
      });

    } catch (error) {
      logger.error('Toggle user status error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to update user status',
        code: 'UPDATE_STATUS_ERROR'
      });
    }
  }

  /**
   * Assign roles to user
   */
  async assignRoles(req, res) {
    try {
      const { userId } = req.params;
      const { roleIds } = req.body;

      if (!Array.isArray(roleIds) || roleIds.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'Role IDs array is required',
          code: 'MISSING_ROLE_IDS'
        });
      }

      const user = await User.findById(userId).populate('roles');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Validate all roles exist
      const roles = await Role.find({ _id: { $in: roleIds }, status: 'active' });
      
      if (roles.length !== roleIds.length) {
        return res.status(400).json({
          success: false,
          error: 'One or more roles not found or inactive',
          code: 'INVALID_ROLES'
        });
      }

      const oldRoles = user.roles.map(role => ({
        id: role._id,
        name: role.name,
        displayName: role.displayName
      }));

      // Update user roles
      await User.findByIdAndUpdate(userId, {
        roles: roleIds,
        updatedBy: req.user.id
      });

      // Log activity
      await AuditLog.createEntry({
        action: 'role_assigned',
        actorType: 'user',
        userId: req.user.id,
        actorDetails: {
          username: req.user.username,
          email: req.user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: userId,
        targetDetails: {
          name: user.fullName,
          previousValues: { roles: oldRoles },
          newValues: { roles: roles.map(r => ({ id: r._id, name: r.name, displayName: r.displayName })) }
        },
        resource: 'user_roles',
        status: 'success',
        category: 'user_management'
      });

      logger.info(`Roles assigned to user: ${user.email} by ${req.user.email}`);

      res.status(200).json({
        success: true,
        message: 'Roles assigned successfully',
        data: {
          userId,
          assignedRoles: roles.map(role => ({
            id: role._id,
            name: role.name,
            displayName: role.displayName,
            level: role.level
          }))
        }
      });

    } catch (error) {
      logger.error('Assign roles error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to assign roles',
        code: 'ASSIGN_ROLES_ERROR'
      });
    }
  }

  /**
   * Get user statistics
   */
  async getUserStats(req, res) {
    try {
      // Get various user statistics
      const totalUsers = await User.countDocuments({ isDeleted: { $ne: true } });
      const activeUsers = await User.countDocuments({ status: 'active', isDeleted: { $ne: true } });
      const pendingUsers = await User.countDocuments({ status: 'pending', isDeleted: { $ne: true } });
      const suspendedUsers = await User.countDocuments({ status: 'suspended', isDeleted: { $ne: true } });
      const deletedUsers = await User.countDocuments({ isDeleted: true });

      // Get users by role
      const roleStats = await User.aggregate([
        { $match: { isDeleted: { $ne: true } } },
        { $unwind: '$roles' },
        { $lookup: { from: 'roles', localField: 'roles', foreignField: '_id', as: 'roleInfo' } },
        { $unwind: '$roleInfo' },
        { $group: { _id: '$roleInfo.name', count: { $sum: 1 }, displayName: { $first: '$roleInfo.displayName' } } },
        { $sort: { count: -1 } }
      ]);

      // Recent registrations (last 30 days)
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      
      const recentRegistrations = await User.countDocuments({
        createdAt: { $gte: thirtyDaysAgo },
        isDeleted: { $ne: true }
      });

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
        resource: 'user_statistics',
        status: 'success',
        category: 'user_management'
      });

      res.status(200).json({
        success: true,
        message: 'User statistics retrieved successfully',
        data: {
          overview: {
            totalUsers,
            activeUsers,
            pendingUsers,
            suspendedUsers,
            deletedUsers,
            recentRegistrations
          },
          roleDistribution: roleStats,
          lastUpdated: new Date()
        }
      });

    } catch (error) {
      logger.error('Get user stats error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve user statistics',
        code: 'GET_STATS_ERROR'
      });
    }
  }
}

module.exports = new UserController();