const mongoose = require('mongoose');
const { User, Role, Permisson } = require('../models');
const logger = require('../utils/logger');

// Default system permissions
const systemPermissions = [
    // User Management
    {
        name: 'user:create',
        displayName: 'Create User',
        description: 'Create new user accounts',
        resource: 'user',
        action: 'create',
        category: 'user_management',
        isSystemPermission: true,
        riskLevel: 'medium'
    },
    {
        name: 'user:read',
        displayName: 'Read User',
        description: 'View user information',
        resource: 'user',
        action: 'read',
        category: 'user_management',
        isSystemPermission: true,
        riskLevel: 'low'
    },
    {
        name: 'user:update',
        displayName: 'Update User',
        description: 'Modify user information',
        resource: 'user',
        action: 'update',
        category: 'user_management',
        isSystemPermission: true,
        riskLevel: 'medium'
    },
    {
        name: 'user:delete',
        displayName: 'Delete User',
        description: 'Delete user accounts',
        resource: 'user',
        action: 'delete',
        category: 'user_management',
        isSystemPermission: true,
        riskLevel: 'high'
    },
    {
        name: 'user:manage',
        displayName: 'Manage Users',
        description: 'Full user management access',
        resource: 'user',
        action: 'manage',
        scope: 'global',
        category: 'user_management',
        isSystemPermission: true,
        riskLevel: 'high'
    },
    // Role Management
    {
        name: 'role:create',
        displayName: 'Create Role',
        description: 'Create new roles',
        resource: 'role',
        action: 'create',
        category: 'role_management',
        isSystemPermission: true,
        riskLevel: 'high'
    },
    {
        name: 'role:read',
        displayName: 'Read Role',
        description: 'View role information',
        resource: 'role',
        action: 'read',
        category: 'role_management',
        isSystemPermission: true,
        riskLevel: 'low'
    },
    {
        name: 'role:update',
        displayName: 'Update Role',
        description: 'Modify roles',
        resource: 'role',
        action: 'update',
        category: 'role_management',
        isSystemPermission: true,
        riskLevel: 'high'
    },
    {
        name: 'role:delete',
        displayName: 'Delete Role',
        description: 'Delete roles',
        resource: 'role',
        action: 'delete',
        category: 'role_management',
        isSystemPermission: true,
        riskLevel: 'critical'
    },
    {
        name: 'role:assign',
        displayName: 'Assign Role',
        description: 'Assign roles to users',
        resource: 'role',
        action: 'execute',
        category: 'role_management',
        isSystemPermission: true,
        riskLevel: 'high'
    },
    // Permission Management
    {
        name: 'permission:create',
        displayName: 'Create Permission',
        description: 'Create new permissions',
        resource: 'permission',
        action: 'create',
        category: 'role_management',
        isSystemPermission: true,
        riskLevel: 'critical'
    },
    {
        name: 'permission:read',
        displayName: 'Read Permission',
        description: 'View permissions',
        resource: 'permission',
        action: 'read',
        category: 'role_management',
        isSystemPermission: true,
        riskLevel: 'low'
    },
    {
        name: 'permission:update',
        displayName: 'Update Permission',
        description: 'Modify permissions',
        resource: 'permission',
        action: 'update',
        category: 'role_management',
        isSystemPermission: true,
        riskLevel: 'critical'
    },
    {
        name: 'permission:delete',
        displayName: 'Delete Permission',
        description: 'Delete permissions',
        resource: 'permission',
        action: 'delete',
        category: 'role_management',
        isSystemPermission: true,
        riskLevel: 'critical'
    },
    // System Administration
    {
        name: 'system:configure',
        displayName: 'System Configuration',
        description: 'Configure system settings',
        resource: 'system',
        action: 'update',
        category: 'system_administration',
        isSystemPermission: true,
        riskLevel: 'critical'
    },
    {
        name: 'system:backup',
        displayName: 'System Backup',
        description: 'Create system backups',
        resource: 'system',
        action: 'execute',
        category: 'system_administration',
        isSystemPermission: true,
        riskLevel: 'medium'
    },
    {
        name: 'system:audit',
        displayName: 'System Audit',
        description: 'View audit logs',
        resource: 'audit',
        action: 'read',
        category: 'security',
        isSystemPermission: true,
        riskLevel: 'medium'
    },
    // Data Management
    {
        name: 'data:export',
        displayName: 'Export Data',
        description: 'Export system data',
        resource: 'data',
        action: 'export',
        category: 'data_management',
        isSystemPermission: true,
        riskLevel: 'high'
    },
    {
        name: 'data:import',
        displayName: 'Import Data',
        description: 'Import data into system',
        resource: 'data',
        action: 'import',
        category: 'data_management',
        isSystemPermission: true,
        riskLevel: 'high'
    },

    // API Access
    {
        name: 'api:access',
        displayName: 'API Access',
        description: 'Access system APIs',
        resource: 'api',
        action: 'read',
        category: 'api_access',
        isSystemPermission: true,
        riskLevel: 'low'
    },
    {
        name: 'api:admin',
        displayName: 'API Administration',
        description: 'Administer API settings',
        resource: 'api',
        action: 'manage',
        category: 'api_access',
        isSystemPermission: true,
        riskLevel: 'high'
    }

];

// Default system roles
const systemRoles = [
    {
        name: 'super_admin',
        displayName: 'Super Administrator',
        description: 'Full system access with all permissions',
        level: 1,
        isSystemRole: true,
        color: '#dc3545',
        icon: 'crown',
        permissions: [] // Will be populated with all permissions
    },
    {
        name: 'admin',
        displayName: 'Administrator',
        description: 'Administrative access to user and role management',
        level: 2,
        isSystemRole: true,
        color: '#fd7e14',
        icon: 'user-cog',
        permissions: [
            'user:create', 'user:read', 'user:update', 'user:delete',
            'role:read', 'role:assign',
            'permission:read',
            'system:audit'
        ]
    },
    {
        name: 'manager',
        displayName: 'Manager',
        description: 'Can manage users within their department',
        level: 3,
        isSystemRole: true,
        color: '#20c997',
        icon: 'users',
        permissions: [
            'user:read', 'user:update',
            'role:read',
            'permission:read'
        ]
    },
    {
        name: 'user',
        displayName: 'Standard User',
        description: 'Basic user with limited permissions',
        level: 4,
        isSystemRole: true,
        isDefault: true,
        color: '#007bff',
        icon: 'user',
        permissions: [
            'user:read', // Can read own profile
            'api:access'
        ]
    },
    {
        name: 'viewer',
        displayName: 'Viewer',
        description: 'Read-only access to permitted resources',
        level: 5,
        isSystemRole: true,
        color: '#6c757d',
        icon: 'eye',
        permissions: [
            'user:read'
        ]
    }
];

// Seeder functions
const seedPermissions = async (createdBy) => {
  logger.info('Seeding permissions...');
  
  const createdPermissions = [];
  
  for (const permData of systemPermissions) {
    try {
      // Check if permission already exists
      const existingPermission = await Permission.findOne({ name: permData.name });
      
      if (!existingPermission) {
        const permission = new Permission({
          ...permData,
          createdBy
        });
        
        await permission.save();
        createdPermissions.push(permission);
        logger.info(`Created permission: ${permission.name}`);
      } else {
        createdPermissions.push(existingPermission);
        logger.info(`Permission already exists: ${existingPermission.name}`);
      }
    } catch (error) {
      logger.error(`Error creating permission ${permData.name}:`, error.message);
    }
  }
  
  return createdPermissions;
};

const seedRoles = async (permissions, createdBy) => {
  logger.info('Seeding roles...');
  
  const createdRoles = [];
  
  for (const roleData of systemRoles) {
    try {
      // Check if role already exists
      const existingRole = await Role.findOne({ name: roleData.name });
      
      if (!existingRole) {
        // Get permission IDs for this role
        const rolePermissions = permissions.filter(perm => 
          roleData.permissions.includes(perm.name)
        ).map(perm => perm._id);
        
        // Super admin gets all permissions
        if (roleData.name === 'super_admin') {
          roleData.permissions = permissions.map(perm => perm._id);
        } else {
          roleData.permissions = rolePermissions;
        }
        
        const role = new Role({
          ...roleData,
          createdBy
        });
        
        await role.save();
        createdRoles.push(role);
        logger.info(`Created role: ${role.name}`);
      } else {
        createdRoles.push(existingRole);
        logger.info(`Role already exists: ${existingRole.name}`);
      }
    } catch (error) {
      logger.error(`Error creating role ${roleData.name}:`, error.message);
    }
  }
  
  return createdRoles;
};

const createSystemAdmin = async (defaultRole) => {
  logger.info('Creating system administrator...');
  
  try {
    // Check if admin user already exists
    const existingAdmin = await User.findOne({ 
      email: 'admin@system.com' 
    });
    
    if (!existingAdmin) {
      // Find super admin role
      const superAdminRole = await Role.findOne({ name: 'super_admin' });
      
      const adminUser = new User({
        firstName: 'System',
        lastName: 'Administrator',
        email: 'admin@system.com',
        username: 'admin',
        password: 'Admin@123456', // This will be hashed automatically
        status: 'active',
        emailVerified: true,
        roles: [superAdminRole._id],
        profile: {
          jobTitle: 'System Administrator',
          department: 'IT'
        }
      });
      
      await adminUser.save();
      logger.info('System administrator created successfully');
      logger.info('Login credentials:');
      logger.info('Email: admin@system.com');
      logger.info('Password: Admin@123456');
      logger.info('⚠️  IMPORTANT: Please change the default password immediately!');
      
      return adminUser;
    } else {
      logger.info('System administrator already exists');
      return existingAdmin;
    }
  } catch (error) {
    logger.error('Error creating system administrator:', error.message);
    throw error;
  }
};

const seedDatabase = async () => {
  try {
    logger.info('🌱 Starting database seeding process...');
    
    // Create a temporary system user for audit trail
    const systemUser = new User({
      firstName: 'System',
      lastName: 'Seeder',
      email: 'system@seeder.internal',
      username: 'system_seeder',
      password: 'temp_password',
      status: 'active',
      roles: []
    });
    
    // Save without validation for seeding purposes
    await systemUser.save({ validateBeforeSave: false });
    
    // 1. Seed permissions
    const permissions = await seedPermissions(systemUser._id);
    
    // 2. Seed roles
    const roles = await seedRoles(permissions, systemUser._id);
    
    // 3. Create system administrator
    const defaultRole = roles.find(role => role.isDefault);
    const adminUser = await createSystemAdmin(defaultRole);
    
    // 4. Clean up temporary system user
    await User.findByIdAndDelete(systemUser._id);
    
    logger.info('✅ Database seeding completed successfully!');
    logger.info(`Created ${permissions.length} permissions`);
    logger.info(`Created ${roles.length} roles`);
    logger.info('System ready for use!');
    
    return {
      permissions,
      roles,
      adminUser
    };
    
  } catch (error) {
    logger.error('❌ Database seeding failed:', error.message);
    throw error;
  }
};


// Function to reset database (useful for development)
const resetDatabase = async () => {
  try {
    logger.warn('🗑️  Resetting database...');
    
    await User.deleteMany({});
    await Role.deleteMany({});
    await Permission.deleteMany({});
    
    logger.info('Database reset completed');
    
    // Re-seed after reset
    return await seedDatabase();
    
  } catch (error) {
    logger.error('Database reset failed:', error.message);
    throw error;
  }
};

// Function to update existing permissions
const updatePermissions = async () => {
  try {
    logger.info('Updating existing permissions...');
    
    for (const permData of systemPermissions) {
      await Permission.findOneAndUpdate(
        { name: permData.name },
        { $set: permData },
        { upsert: true }
      );
    }
    
    logger.info('Permissions updated successfully');
  } catch (error) {
    logger.error('Permission update failed:', error.message);
    throw error;
  }
};

module.exports = {
  seedDatabase,
  resetDatabase,
  updatePermissions,
  seedPermissions,
  seedRoles,
  createSystemAdmin
};