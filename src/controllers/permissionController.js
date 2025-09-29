const { Permission, Role, User, AuditLog } = require('../models');
const logger = require('../utils/logger');

class PermissionController {
  // Get all permissions with filtering and sorting
  async getAllPermissions(req, res) {
    try {
      console.log('=== GET ALL PERMISSIONS STARTED ===');
      
      const {
        page = 1,
        limit = 50,
        category,
        riskLevel,
        search,
        sortBy = 'category',
        sortOrder = 'asc',
        includeDeleted = false
      } = req.query;

      // Build query
      const query = {};
      
      if (category) {
        query.category = category;
      }
      
      if (riskLevel) {
        query.riskLevel = riskLevel;
      }
      
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { displayName: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }
      
      if (!includeDeleted || includeDeleted === 'false') {
        query.isDeleted = { $ne: true };
      }

      // Pagination
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      const skip = (pageNum - 1) * limitNum;

      // Sort object
      const sortObj = {};
      sortObj[sortBy] = sortOrder === 'asc' ? 1 : -1;

      // Execute query
      const permissions = await Permission.find(query)
        .sort(sortObj)
        .skip(skip)
        .limit(limitNum)
        .lean();

      const totalPermissions = await Permission.countDocuments(query);
      const totalPages = Math.ceil(totalPermissions / limitNum);

      // Get usage stats for each permission
      const permissionsWithStats = await Promise.all(
        permissions.map(async (permission) => {
          const rolesUsingPermission = await Role.countDocuments({
            permissions: permission._id,
            isDeleted: { $ne: true }
          });

          return {
            ...permission,
            usedByRolesCount: rolesUsingPermission
          };
        })
      );

      // Group by category
      const permissionsByCategory = permissionsWithStats.reduce((acc, perm) => {
        const cat = perm.category || 'uncategorized';
        if (!acc[cat]) acc[cat] = [];
        acc[cat].push(perm);
        return acc;
      }, {});

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
        resource: 'permission_list',
        status: 'success',
        category: 'permission_management'
      });

      res.status(200).json({
        success: true,
        message: 'Permissions retrieved successfully',
        data: {
          permissions: permissionsWithStats,
          permissionsByCategory,
          pagination: {
            currentPage: pageNum,
            totalPages,
            totalPermissions,
            hasNextPage: pageNum < totalPages,
            hasPrevPage: pageNum > 1,
            limit: limitNum
          },
          filters: { category, riskLevel, search, includeDeleted }
        }
      });

    } catch (error) {
      console.log('Get permissions error:', error.message);
      logger.error('Get all permissions error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve permissions',
        code: 'GET_PERMISSIONS_ERROR'
      });
    }
  }

  // Get permission statistics
  async getPermissionStats(req, res) {
    try {
      const totalPermissions = await Permission.countDocuments({ isDeleted: { $ne: true } });
      
      // Count by category
      const categoryStats = await Permission.aggregate([
        { $match: { isDeleted: { $ne: true } } },
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]);

      // Count by risk level
      const riskLevelStats = await Permission.aggregate([
        { $match: { isDeleted: { $ne: true } } },
        { $group: { _id: '$riskLevel', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]);

      // Most used permissions
      const rolesWithPermissions = await Role.find({ isDeleted: { $ne: true } })
        .select('permissions')
        .lean();

      const permissionUsage = {};
      rolesWithPermissions.forEach(role => {
        role.permissions.forEach(permId => {
          const id = permId.toString();
          permissionUsage[id] = (permissionUsage[id] || 0) + 1;
        });
      });

      const topPermissions = await Promise.all(
        Object.entries(permissionUsage)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(async ([permId, count]) => {
            const perm = await Permission.findById(permId).select('name displayName category').lean();
            return { ...perm, usageCount: count };
          })
      );

      // Unused permissions
      const unusedCount = await Permission.countDocuments({
        _id: { $nin: rolesWithPermissions.flatMap(r => r.permissions) },
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
        targetId: req.user.id,
        resource: 'permission_statistics',
        status: 'success',
        category: 'permission_management'
      });

      res.status(200).json({
        success: true,
        message: 'Permission statistics retrieved successfully',
        data: {
          overview: {
            totalPermissions,
            unusedPermissions: unusedCount,
            categoriesCount: categoryStats.length
          },
          categoryDistribution: categoryStats,
          riskLevelDistribution: riskLevelStats,
          topUsedPermissions: topPermissions,
          lastUpdated: new Date()
        }
      });

    } catch (error) {
      logger.error('Get permission stats error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve permission statistics',
        code: 'GET_PERMISSION_STATS_ERROR'
      });
    }
  }

  // Get single permission by ID
  async getPermissionById(req, res) {
    try {
      const { permissionId } = req.params;

      const permission = await Permission.findById(permissionId).lean();

      if (!permission) {
        return res.status(404).json({
          success: false,
          error: 'Permission not found',
          code: 'PERMISSION_NOT_FOUND'
        });
      }

      // Get roles using this permission
      const rolesWithPermission = await Role.find({
        permissions: permissionId,
        isDeleted: { $ne: true }
      })
      .select('name displayName level currentUserCount')
      .lean();

      // Get total users affected
      const usersAffected = await User.countDocuments({
        roles: { $in: rolesWithPermission.map(r => r._id) },
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
        targetType: 'permission',
        targetId: permissionId,
        resource: 'permission_details',
        status: 'success',
        category: 'permission_management'
      });

      res.status(200).json({
        success: true,
        message: 'Permission retrieved successfully',
        data: {
          permission,
          usage: {
            rolesCount: rolesWithPermission.length,
            usersAffected,
            roles: rolesWithPermission
          }
        }
      });

    } catch (error) {
      logger.error('Get permission by ID error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve permission',
        code: 'GET_PERMISSION_ERROR'
      });
    }
  }

  // Create new permission
  async createPermission(req, res) {
    try {
      const {
        name,
        displayName,
        description,
        category,
        resource,
        action,
        riskLevel = 'medium',
        conditions = {},
        metadata = {}
      } = req.body;

      // Check if permission name already exists
      const existingPermission = await Permission.findOne({
        name: name.toLowerCase(),
        isDeleted: { $ne: true }
      });

      if (existingPermission) {
        return res.status(400).json({
          success: false,
          error: 'Permission name already exists',
          code: 'PERMISSION_NAME_EXISTS'
        });
      }

      // Create permission
      const permission = new Permission({
        name: name.toLowerCase(),
        displayName,
        description,
        category,
        resource,
        action,
        riskLevel,
        conditions,
        metadata,
        createdBy: req.user.id,
        isSystemPermission: false
      });

      await permission.save();

      // Log activity
      await AuditLog.createEntry({
        action: 'create',
        actorType: 'user',
        userId: req.user.id,
        actorDetails: {
          username: req.user.username,
          email: req.user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'permission',
        targetId: permission._id,
        targetDetails: {
          permissionName: permission.displayName,
          category: permission.category
        },
        resource: 'permission_creation',
        status: 'success',
        category: 'permission_management'
      });

      logger.info(`Permission created: ${permission.displayName} by ${req.user.username}`);

      res.status(201).json({
        success: true,
        message: 'Permission created successfully',
        data: { permission }
      });

    } catch (error) {
      logger.error('Create permission error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to create permission',
        code: 'CREATE_PERMISSION_ERROR'
      });
    }
  }

  // Update existing permission
  async updatePermission(req, res) {
    try {
      const { permissionId } = req.params;
      const updates = req.body;

      const permission = await Permission.findById(permissionId);
      
      if (!permission) {
        return res.status(404).json({
          success: false,
          error: 'Permission not found',
          code: 'PERMISSION_NOT_FOUND'
        });
      }

      // Prevent updating system permissions (except by super admin)
      if (permission.isSystemPermission && 
          !req.user.roles.some(r => r.name === 'super_admin')) {
        return res.status(403).json({
          success: false,
          error: 'Cannot modify system permissions',
          code: 'SYSTEM_PERMISSION_PROTECTED'
        });
      }

      // Store original values for audit
      const originalValues = {
        displayName: permission.displayName,
        description: permission.description,
        riskLevel: permission.riskLevel,
        category: permission.category
      };

      // Update permission
      Object.assign(permission, updates);
      permission.updatedBy = req.user.id;
      await permission.save();

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
        targetType: 'permission',
        targetId: permissionId,
        targetDetails: {
          permissionName: permission.displayName,
          changes: updates,
          originalValues
        },
        resource: 'permission_update',
        status: 'success',
        category: 'permission_management'
      });

      logger.info(`Permission updated: ${permission.displayName} by ${req.user.username}`);

      res.status(200).json({
        success: true,
        message: 'Permission updated successfully',
        data: { permission }
      });

    } catch (error) {
      logger.error('Update permission error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to update permission',
        code: 'UPDATE_PERMISSION_ERROR'
      });
    }
  }

  // Delete permission (soft delete)
  async deletePermission(req, res) {
    try {
      const { permissionId } = req.params;

      const permission = await Permission.findById(permissionId);
      
      if (!permission) {
        return res.status(404).json({
          success: false,
          error: 'Permission not found',
          code: 'PERMISSION_NOT_FOUND'
        });
      }

      // Prevent deleting system permissions
      if (permission.isSystemPermission) {
        return res.status(403).json({
          success: false,
          error: 'Cannot delete system permissions',
          code: 'SYSTEM_PERMISSION_PROTECTED'
        });
      }

      // Check if permission is in use
      const rolesUsingPermission = await Role.countDocuments({
        permissions: permissionId,
        isDeleted: { $ne: true }
      });

      if (rolesUsingPermission > 0) {
        return res.status(400).json({
          success: false,
          error: `Cannot delete permission. ${rolesUsingPermission} roles are using this permission`,
          code: 'PERMISSION_IN_USE'
        });
      }

      // Soft delete
      permission.isDeleted = true;
      permission.deletedAt = new Date();
      permission.deletedBy = req.user.id;
      await permission.save();

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
        targetType: 'permission',
        targetId: permissionId,
        targetDetails: {
          permissionName: permission.displayName
        },
        resource: 'permission_deletion',
        status: 'success',
        category: 'permission_management'
      });

      logger.info(`Permission deleted: ${permission.displayName} by ${req.user.username}`);

      res.status(200).json({
        success: true,
        message: 'Permission deleted successfully',
        data: { permissionId }
      });

    } catch (error) {
      logger.error('Delete permission error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to delete permission',
        code: 'DELETE_PERMISSION_ERROR'
      });
    }
  }

  // Get permission categories
  async getPermissionCategories(req, res) {
    try {
      const categories = await Permission.distinct('category', { 
        isDeleted: { $ne: true } 
      });

      const categoriesWithCount = await Promise.all(
        categories.map(async (category) => {
          const count = await Permission.countDocuments({
            category,
            isDeleted: { $ne: true }
          });
          return { category, count };
        })
      );

      res.status(200).json({
        success: true,
        message: 'Permission categories retrieved successfully',
        data: {
          categories: categoriesWithCount,
          totalCategories: categories.length
        }
      });

    } catch (error) {
      logger.error('Get permission categories error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve permission categories',
        code: 'GET_CATEGORIES_ERROR'
      });
    }
  }
}

module.exports = new PermissionController();