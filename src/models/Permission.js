const mongoose = require('mongoose');

const permissionsSchema = new mongoose.Schema({
    // Basic Information
  name: {
    type: String,
    required: [true, 'Permission name is required'],
    unique: true,
    trim: true,
    lowercase: true,
    maxlength: [100, 'Permission name cannot exceed 100 characters'],
    match: [/^[a-z0-9_:.-]+$/, 'Permission name can only contain lowercase letters, numbers, underscores, colons, dots, and hyphens']
  },
  
  displayName: {
    type: String,
    required: [true, 'Display name is required'],
    trim: true,
    maxlength: [100, 'Display name cannot exceed 100 characters']
  },
  
  description: {
    type: String,
    required: [true, 'Permission description is required'],
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  // Permission Structure
  resource: {
    type: String,
    required: [true, 'Resource is required'],
    trim: true,
    lowercase: true,
    maxlength: [50, 'Resource name cannot exceed 50 characters']
  },
  
  action: {
    type: String,
    required: [true, 'Action is required'],
    enum: ['create', 'read', 'update', 'delete', 'execute', 'manage', 'approve', 'reject', 'export', 'import'],
    lowercase: true
  },
  
  scope: {
    type: String,
    enum: ['global', 'department', 'organization', 'own', 'assigned'],
    default: 'own'
  },

  // Permisson Categories
  category: {
    type: String,
    required: [true, 'Category is required'],
    trim: true,
    enum: [
      'user_management',
      'role_management',
      'system_administration',
      'data_management',
      'reporting',
      'security',
      'api_access',
      'content_management',
      'financial',
      'custom'
    ]
  },
  
  subcategory: {
    type: String,
    trim: true,
    maxlength: [50, 'Subcategory cannot exceed 50 characters']
  },

  // Permission Properties
  isSystemPermission: {
    type: Boolean,
    default: false // System permissions cannot be deleted
  },
  
  isApiPermission: {
    type: Boolean,
    default: true // Whether this permission applies to API access
  },
  
  isUIPermission: {
    type: Boolean,
    default: true // Whether this permission applies to UI access
  },
  
  status: {
    type: String,
    enum: ['active', 'inactive', 'deprecated'],
    default: 'active'
  },
  
  // Permission Hierarchy
  parentPermission: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission',
    default: null
  },
  
  childPermissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }],

  // Conditions and Constraints
  conditions: {
    // Time-based conditions
    timeRestrictions: {
      allowedHours: {
        start: String, // HH:MM format
        end: String    // HH:MM format
      },
      allowedDays: [String], // Array of day names
      timezone: String
    },
    
    // IP-based restrictions
    ipRestrictions: {
      allowedRanges: [String],
      blockedRanges: [String]
    },
    
    // Device-based restrictions
    deviceRestrictions: {
      allowedDeviceTypes: [String],
      blockedDeviceTypes: [String]
    },
    
    // Data-based conditions
    dataFilters: {
      maxRecords: Number,
      allowedFields: [String],
      restrictedFields: [String]
    },
    
    // Custom conditions (JavaScript expressions)
    customConditions: [String]
  },
  
  // Dependencies
  requiredPermissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }], // Permissions that must be present for this permission to be effective
  
  conflictingPermissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }], // Permissions that cannot coexist with this permission
  
  // Risk and Security
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  
  requiresApproval: {
    type: Boolean,
    default: false
  },
  
  approvalWorkflow: {
    approvers: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }],
    approvalLevels: Number,
    autoApprovalConditions: mongoose.Schema.Types.Mixed
  },
  
  // Audit and Compliance
  auditRequired: {
    type: Boolean,
    default: false
  },
  
  complianceFrameworks: [{
    type: String,
    enum: ['gdpr', 'hipaa', 'sox', 'pci-dss', 'iso27001', 'custom']
  }],
  
  // Usage Tracking
  usageStats: {
    assignedToRoles: {
      type: Number,
      default: 0
    },
    assignedToUsers: {
      type: Number,
      default: 0
    },
    lastUsed: Date,
    usageCount: {
      type: Number,
      default: 0
    }
  },
  
  // Documentation and Examples
  documentation: {
    examples: [String],
    useCases: [String],
    warnings: [String],
    relatedPermissions: [String]
  },
  
  // API Endpoints (for API permissions)
  apiEndpoints: [{
    method: {
      type: String,
      enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      uppercase: true
    },
    path: String,
    description: String
  }],
  
  // UI Elements (for UI permissions)
  uiElements: [{
    type: {
      type: String,
      enum: ['page', 'section', 'button', 'field', 'menu', 'tab']
    },
    identifier: String,
    description: String
  }],
  
  // Metadata
  tags: [{
    type: String,
    trim: true,
    lowercase: true
  }],
  
  color: {
    type: String,
    match: [/^#[0-9A-F]{6}$/i, 'Color must be a valid hex color code'],
    default: '#28a745'
  },
  
  icon: {
    type: String,
    default: 'shield'
  },
  
  // Audit Trail
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  // Change History
  changeHistory: [{
    action: {
      type: String,
      enum: ['created', 'updated', 'activated', 'deactivated', 'deprecated'],
      required: true
    },
    changedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    changedAt: {
      type: Date,
      default: Date.now
    },
    details: mongoose.Schema.Types.Mixed,
    reason: String
  }],
  
  // Soft Delete
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedAt: Date,
  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
  
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }

});