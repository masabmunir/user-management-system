const mongoose = require('mongoose');
const { User, Role, Permisson} = require('../models');
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
]