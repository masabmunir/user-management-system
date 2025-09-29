const { Role, Permission, User, AuditLog } = require('../models');
const logger = require('../utils/logger');

class RoleController {
  // Get all roles with optional filtering and sorting
  async getAllRoles(req, res) {
  try {
    
    const {
      page = 1,
      limit = 10,
      status,
      level,
      search,
      sortBy = 'level',
      sortOrder = 'asc',
      includeDeleted = false
    } = req.query;

    // Build query
    const query = {};
    if (status) query.status = status;
    if (level) query.level = parseInt(level);
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

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;

    const sortObj = {};
    sortObj[sortBy] = sortOrder === 'asc' ? 1 : -1;
    console.log('Sort Object:', sortObj);

    // Execute query
    const roles = await Role.find(query)
      .populate('permissions', 'name displayName description category')
      .populate('parentRole', 'name displayName level')
      .populate('childRoles', 'name displayName level')
      .sort(sortObj)
      .skip(skip)
      .limit(limitNum)
      .lean();

    const totalRoles = await Role.countDocuments(query);
    const totalPages = Math.ceil(totalRoles / limitNum);

    const rolesWithStats = await Promise.all(
      roles.map(async (role) => {
        const userCount = await User.countDocuments({
          roles: role._id,
          isDeleted: { $ne: true }
        });
        return {
          ...role,
          currentUserCount: userCount,
          permissionCount: role.permissions.length
        };
      })
    );

    await AuditLog.createEntry({
      action: 'read',
      actorType: 'user',
      userId: req.user?.id,
      actorDetails: {
        username: req.user?.username,
        email: req.user?.email,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      },
      targetType: 'system',
      targetId: req.user?.id,
      resource: 'role_list',
      status: 'success',
      category: 'role_management'
    });

    res.status(200).json({
      success: true,
      message: 'Roles retrieved successfully',
      data: {
        roles: rolesWithStats,
        pagination: {
          currentPage: pageNum,
          totalPages,
          totalRoles,
          hasNextPage: pageNum < totalPages,
          hasPrevPage: pageNum > 1,
          limit: limitNum
        },
        filters: { status, level, search, includeDeleted }
      }
    });

  } catch (error) {
    logger.error('Get all roles error:', error.message);
    
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve roles',
      code: 'GET_ROLES_ERROR'
    });
  }
}


  // Get role statistics
  async getRoleStats(req, res) {
    try {
      const totalRoles = await Role.countDocuments({ isDeleted: { $ne: true } });
      const activeRoles = await Role.countDocuments({ status: 'active', isDeleted: { $ne: true } });
      const systemRoles = await Role.countDocuments({ isSystemRole: true, isDeleted: { $ne: true } });
      const customRoles = await Role.countDocuments({ isSystemRole: false, isDeleted: { $ne: true } });

      // Role distribution by level
      const levelDistribution = await Role.aggregate([
        { $match: { isDeleted: { $ne: true } } },
        { $group: { _id: '$level', count: { $sum: 1 } } },
        { $sort: { _id: 1 } }
      ]);

      // Roles with most users
      const roleUsage = await User.aggregate([
        { $match: { isDeleted: { $ne: true } } },
        { $unwind: '$roles' },
        { $group: { _id: '$roles', userCount: { $sum: 1 } } },
        { $lookup: { from: 'roles', localField: '_id', foreignField: '_id', as: 'roleInfo' } },
        { $unwind: '$roleInfo' },
        { $project: { 
          roleName: '$roleInfo.name',
          displayName: '$roleInfo.displayName',
          level: '$roleInfo.level',
          userCount: 1
        }},
        { $sort: { userCount: -1 } },
        { $limit: 5 }
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
        resource: 'role_statistics',
        status: 'success',
        category: 'role_management'
      });

      res.status(200).json({
        success: true,
        message: 'Role statistics retrieved successfully',
        data: {
          overview: {
            totalRoles,
            activeRoles,
            systemRoles,
            customRoles
          },
          levelDistribution,
          roleUsage,
          lastUpdated: new Date()
        }
      });

    } catch (error) {
      logger.error('Get role stats error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve role statistics',
        code: 'GET_ROLE_STATS_ERROR'
      });
    }
  }

  // Get single role by ID
  async getRoleById(req, res) {
    try {
      const { roleId } = req.params;

      const role = await Role.findById(roleId)
        .populate('permissions', 'name displayName description category riskLevel')
        .populate('parentRole', 'name displayName level')
        .populate('childRoles', 'name displayName level')
        .lean();

      if (!role) {
        return res.status(404).json({
          success: false,
          error: 'Role not found',
          code: 'ROLE_NOT_FOUND'
        });
      }

      // Get users with this role
      const usersWithRole = await User.find({ 
        roles: roleId,
        isDeleted: { $ne: true }
      })
      .select('firstName lastName email username status')
      .limit(10)
      .lean();

      const totalUsersWithRole = await User.countDocuments({ 
        roles: roleId,
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
        targetType: 'role',
        targetId: roleId,
        resource: 'role_details',
        status: 'success',
        category: 'role_management'
      });

      res.status(200).json({
        success: true,
        message: 'Role retrieved successfully',
        data: {
          role: {
            ...role,
            currentUserCount: totalUsersWithRole,
            permissionCount: role.permissions.length
          },
          usersWithRole: {
            users: usersWithRole,
            totalCount: totalUsersWithRole,
            showing: Math.min(10, usersWithRole.length)
          }
        }
      });

    } catch (error) {
      logger.error('Get role by ID error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve role',
        code: 'GET_ROLE_ERROR'
      });
    }
  }

  // Create new role
  async createRole(req, res) {
    try {
      const {
        name,
        displayName,
        description,
        level,
        permissions = [],
        parentRole,
        color = '#007bff',
        icon = 'user',
        maxUsers,
        restrictions = {}
      } = req.body;

      // Check if role name already exists
      const existingRole = await Role.findOne({ 
        name: name.toLowerCase(),
        isDeleted: { $ne: true }
      });
      
      if (existingRole) {
        return res.status(400).json({
          success: false,
          error: 'Role name already exists',
          code: 'ROLE_NAME_EXISTS'
        });
      }

      // Validate level is unique (if specified)
      if (level) {
        const roleAtLevel = await Role.findOne({ 
          level,
          isDeleted: { $ne: true }
        });
        
        if (roleAtLevel) {
          return res.status(400).json({
            success: false,
            error: `A role already exists at level ${level}`,
            code: 'LEVEL_EXISTS'
          });
        }
      }

      // Validate permissions exist
      if (permissions.length > 0) {
        const validPermissions = await Permission.countDocuments({
          _id: { $in: permissions }
        });
        
        if (validPermissions !== permissions.length) {
          return res.status(400).json({
            success: false,
            error: 'One or more permissions are invalid',
            code: 'INVALID_PERMISSIONS'
          });
        }
      }

      // Create role
      const role = new Role({
        name: name.toLowerCase(),
        displayName,
        description,
        level,
        permissions,
        parentRole,
        color,
        icon,
        maxUsers,
        restrictions,
        createdBy: req.user.id,
        isSystemRole: false,
        status: 'active'
      });

      await role.save();

      // Populate for response
      await role.populate('permissions', 'name displayName description');
      await role.populate('parentRole', 'name displayName level');

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
        targetType: 'role',
        targetId: role._id,
        targetDetails: {
          roleName: role.displayName,
          permissionCount: permissions.length
        },
        resource: 'role_creation',
        status: 'success',
        category: 'role_management'
      });

      logger.info(`Role created: ${role.displayName} by ${req.user.username}`);

      res.status(201).json({
        success: true,
        message: 'Role created successfully',
        data: { role }
      });

    } catch (error) {
      logger.error('Create role error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to create role',
        code: 'CREATE_ROLE_ERROR'
      });
    }
  }

  // Update existing role
  async updateRole(req, res) {
    try {
      const { roleId } = req.params;
      const updates = req.body;

      const role = await Role.findById(roleId);
      if (!role) {
        return res.status(404).json({
          success: false,
          error: 'Role not found',
          code: 'ROLE_NOT_FOUND'
        });
      }

      // Prevent updating system roles (except by super admin)
      if (role.isSystemRole && req.user.roles.some(r => r.name !== 'super_admin')) {
        return res.status(403).json({
          success: false,
          error: 'Cannot modify system roles',
          code: 'SYSTEM_ROLE_PROTECTED'
        });
      }

      // If updating permissions, validate them
      if (updates.permissions) {
        const validPermissions = await Permission.countDocuments({
          _id: { $in: updates.permissions }
        });
        
        if (validPermissions !== updates.permissions.length) {
          return res.status(400).json({
            success: false,
            error: 'One or more permissions are invalid',
            code: 'INVALID_PERMISSIONS'
          });
        }
      }

      // Store original values for audit
      const originalValues = {
        name: role.name,
        displayName: role.displayName,
        permissions: role.permissions,
        level: role.level
      };

      // Update role
      Object.assign(role, updates);
      role.updatedBy = req.user.id;
      await role.save();

      // Populate for response
      await role.populate('permissions', 'name displayName description');
      await role.populate('parentRole', 'name displayName level');

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
        targetType: 'role',
        targetId: roleId,
        targetDetails: {
          roleName: role.displayName,
          changes: updates,
          originalValues
        },
        resource: 'role_update',
        status: 'success',
        category: 'role_management'
      });

      logger.info(`Role updated: ${role.displayName} by ${req.user.username}`);

      res.status(200).json({
        success: true,
        message: 'Role updated successfully',
        data: { role }
      });

    } catch (error) {
      logger.error('Update role error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to update role',
        code: 'UPDATE_ROLE_ERROR'
      });
    }
  }

  // Delete role (soft delete)
  async deleteRole(req, res) {
    try {
      const { roleId } = req.params;

      const role = await Role.findById(roleId);
      if (!role) {
        return res.status(404).json({
          success: false,
          error: 'Role not found',
          code: 'ROLE_NOT_FOUND'
        });
      }

      // Prevent deleting system roles
      if (role.isSystemRole) {
        return res.status(403).json({
          success: false,
          error: 'Cannot delete system roles',
          code: 'SYSTEM_ROLE_PROTECTED'
        });
      }

      // Check if role is in use
      const usersWithRole = await User.countDocuments({ 
        roles: roleId,
        isDeleted: { $ne: true }
      });

      if (usersWithRole > 0) {
        return res.status(400).json({
          success: false,
          error: `Cannot delete role. ${usersWithRole} users are assigned to this role`,
          code: 'ROLE_IN_USE'
        });
      }

      // Soft delete
      role.isDeleted = true;
      role.deletedAt = new Date();
      role.deletedBy = req.user.id;
      await role.save();

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
        targetType: 'role',
        targetId: roleId,
        targetDetails: {
          roleName: role.displayName
        },
        resource: 'role_deletion',
        status: 'success',
        category: 'role_management'
      });

      logger.info(`Role deleted: ${role.displayName} by ${req.user.username}`);

      res.status(200).json({
        success: true,
        message: 'Role deleted successfully',
        data: { roleId }
      });

    } catch (error) {
      logger.error('Delete role error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to delete role',
        code: 'DELETE_ROLE_ERROR'
      });
    }
  }

  // Get role hierarchy tree
  async getRoleHierarchy(req, res) {
    try {
      const roles = await Role.find({ 
        isDeleted: { $ne: true },
        status: 'active'
      })
      .populate('permissions', 'name displayName category')
      .sort({ level: 1 })
      .lean();

      // Build hierarchy tree
      const hierarchyTree = RoleController.buildRoleHierarchy(roles);

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
        resource: 'role_hierarchy',
        status: 'success',
        category: 'role_management'
      });

      res.status(200).json({
        success: true,
        message: 'Role hierarchy retrieved successfully',
        data: {
          hierarchy: hierarchyTree,
          totalRoles: roles.length
        }
      });

    } catch (error) {
      logger.error('Get role hierarchy error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve role hierarchy',
        code: 'GET_HIERARCHY_ERROR'
      });
    }
  }

  // Helper method to build role hierarchy
 static buildRoleHierarchy(roles) {
    const roleMap = new Map();
    const rootRoles = [];

    // Create role map
    roles.forEach(role => {
      roleMap.set(role._id.toString(), {
        ...role,
        children: []
      });
    });

    // Build hierarchy
    roles.forEach(role => {
      if (role.parentRole) {
        const parent = roleMap.get(role.parentRole.toString());
        if (parent) {
          parent.children.push(roleMap.get(role._id.toString()));
        }
      } else {
        rootRoles.push(roleMap.get(role._id.toString()));
      }
    });

    return rootRoles;
  }
}

module.exports = new RoleController();