const { func } = require('joi');
const mongoose = require('mongoose');

const permissionsSchema = new mongoose.Schema({
    // Basic Information
  name: {
    type: String,
    required: [true, 'Permission name is required'],
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
    enum: ['create', 'read', 'update', 'delete', 'execute', 'manage', 'approve', 'reject', 'export', 'import','generate'],
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

// Indexes for performance
permissionsSchema.index({ name: 1 });
permissionsSchema.index({ resource: 1, action: 1 });
permissionsSchema.index({ category: 1 });
permissionsSchema.index({ status: 1 });
permissionsSchema.index({ isDeleted: 1 });
permissionsSchema.index({ riskLevel: 1 });
permissionsSchema.index({ tags: 1 });

// Virtual for full permission identifier
permissionsSchema.virtual('fullName').get(function(){
    return `${this.resource}:${this.action}`;
})

// Virtual for checking if permission is high risk
permissionsSchema.virtual('isHighRisk').get(function(){
    return ['high', 'critical'].includes(this.riskLevel);
})

// Pre-save middleware to generate name if not provided
permissionsSchema.pre('save', function(next){
    if (!this.name && this.resource && this.action) {
    this.name = `${this.resource}:${this.action}`;
    if (this.scope && this.scope !== 'own') {
      this.name += `:${this.scope}`;
    }
  }
    next();
});

// Pre-save middleware to handle permission hierarchy
permissionsSchema.pre('save', async function(next) {
  // If parent permission is set, add this permission to parent's children
  if (this.parentPermission && this.isModified('parentPermission')) {
    await this.constructor.findByIdAndUpdate(
      this.parentPermission,
      { $addToSet: { childPermissions: this._id } }
    );
  }
  next();
});

// Instance method to check if user meets conditions
permissionsSchema.methods.checkConditions = function(user, context = {}) {
  const conditions = this.conditions || {};
  
  // Check time restrictions
  if (conditions.timeRestrictions) {
    const now = new Date();
    const currentTime = now.toTimeString().slice(0, 5); // HH:MM format
    const currentDay = now.toLocaleDateString('en-US', { weekday: 'lowercase' });
    
    const { allowedHours, allowedDays } = conditions.timeRestrictions;
    
    if (allowedHours && allowedHours.start && allowedHours.end) {
      if (currentTime < allowedHours.start || currentTime > allowedHours.end) {
        return false;
      }
    }
    
    if (allowedDays && allowedDays.length > 0) {
      if (!allowedDays.includes(currentDay)) {
        return false;
      }
    }
  }
  
  // Check IP restrictions
  if (conditions.ipRestrictions && context.userIP) {
    const { allowedRanges, blockedRanges } = conditions.ipRestrictions;
    
    if (allowedRanges && allowedRanges.length > 0) {
      // Check if IP is in allowed ranges
      const isAllowed = allowedRanges.some(range => {
        return this.isIPInRange(context.userIP, range);
      });
      if (!isAllowed) return false;
    }
    
    if (blockedRanges && blockedRanges.length > 0) {
      // Check if IP is in blocked ranges
      const isBlocked = blockedRanges.some(range => {
        return this.isIPInRange(context.userIP, range);
      });
      if (isBlocked) return false;
    }
  }
  
  // Check data filters
  if (conditions.dataFilters && context.requestedData) {
    const { maxRecords, allowedFields, restrictedFields } = conditions.dataFilters;
    
    if (maxRecords && context.requestedData.count > maxRecords) {
      return false;
    }
    
    if (allowedFields && context.requestedData.fields) {
      const hasDisallowedField = context.requestedData.fields.some(
        field => !allowedFields.includes(field)
      );
      if (hasDisallowedField) return false;
    }
    
    if (restrictedFields && context.requestedData.fields) {
      const hasRestrictedField = context.requestedData.fields.some(
        field => restrictedFields.includes(field)
      );
      if (hasRestrictedField) return false;
    }
  }
  
  return true;
};

// Helper method to check if IP is in range
permissionsSchema.methods.isIPInRange = function(ip, range) {
  // Simple IP range check - in production, use a proper IP library
  if (range.includes('/')) {
    // CIDR notation
    const [rangeIP, mask] = range.split('/');
    // Implement CIDR checking logic here
    return ip.startsWith(rangeIP.split('.').slice(0, parseInt(mask) / 8).join('.'));
  } else {
    // Single IP
    return ip === range;
  }
};

// Instance method to check dependencies
permissionsSchema.methods.checkDependencies = async function(userPermissions) {
  if (!this.requiredPermissions || this.requiredPermissions.length === 0) {
    return true;
  }
  
  const userPermissionIds = userPermissions.map(p => p.toString());
  
  // Check if all required permissions are present
  const hasAllRequired = this.requiredPermissions.every(reqPerm => 
    userPermissionIds.includes(reqPerm.toString())
  );
  
  return hasAllRequired;
};

// Instance method to check conflicts
permissionsSchema.methods.checkConflicts = async function(userPermissions){methods.checkConflicts = async function(userPermissions) {
  if (!this.conflictingPermissions || this.conflictingPermissions.length === 0) {
    return false; // No conflicts
  }
}
  const userPermissionIds = userPermissions.map(p => p.toString());
  
  // Check if any conflicting permissions are present
  const hasConflict = this.conflictingPermissions.some(conflictPerm => 
    userPermissionIds.includes(conflictPerm.toString())
  );
  
  return hasConflict;
};

// Instance method to increment usage stats
permissionsSchema.methods.incrementUsage = function() {
  this.usageStats.usageCount += 1;
  this.usageStats.lastUsed = new Date();
  return this.save();
};

// Instance method to add change to history
permissionsSchema.methods.addToChangeHistory = function(action, changedBy, details, reason) {
  this.changeHistory.push({
    action,
    changedBy,
    changedAt: new Date(),
    details,
    reason
  });
};

// Static method to find by resource and action
permissionsSchema.statics.findByResourceAction = function(resource, action, scope = null) {
  const query = { resource, action, isDeleted: false };
  if (scope) query.scope = scope;
  return this.findOne(query);
};

// Static method to find by category
permissionsSchema.statics.findByCategory = function(category) {
  return this.find({ 
    category, 
    status: 'active', 
    isDeleted: false 
  });
};

// Static method to find system permissions
permissionsSchema.statics.findSystemPermissions = function() {
  return this.find({ 
    isSystemPermission: true, 
    isDeleted: false 
  });
};

// Static method to find high-risk permissions
permissionsSchema.statics.findHighRisk = function() {
  return this.find({ 
    riskLevel: { $in: ['high', 'critical'] }, 
    status: 'active', 
    isDeleted: false 
  });
};

// Static method to build permission tree by category
permissionsSchema.statics.buildCategoryTree = async function() {
  const permissions = await this.find({ isDeleted: false })
    .populate('parentPermission')
    .populate('childPermissions')
    .sort({ category: 1, subcategory: 1, name: 1 });
  
  const categoryTree = {};
  
  permissions.forEach(permission => {
    const category = permission.category;
    const subcategory = permission.subcategory || 'general';
    
    if (!categoryTree[category]) {
      categoryTree[category] = {};
    }
    
    if (!categoryTree[category][subcategory]) {
      categoryTree[category][subcategory] = [];
    }
    
    categoryTree[category][subcategory].push(permission);
  });
  
  return categoryTree;
};

// Static method to validate permission set
permissionsSchema.statics.validatePermissionSet = async function(permissionIds) {
  const permissions = await this.find({ 
    _id: { $in: permissionIds }, 
    isDeleted: false 
  });
  
  const errors = [];
  
  // Check for conflicts
  for (const permission of permissions) {
    if (permission.conflictingPermissions && permission.conflictingPermissions.length > 0) {
      const conflicts = permission.conflictingPermissions.filter(conflictId =>
        permissionIds.includes(conflictId.toString())
      );
      
      if (conflicts.length > 0) {
        errors.push({
          type: 'conflict',
          permission: permission.name,
          conflicts: conflicts
        });
      }
    }
  }
  
  // Check for missing dependencies
  for (const permission of permissions) {
    if (permission.requiredPermissions && permission.requiredPermissions.length > 0) {
      const missingDeps = permission.requiredPermissions.filter(reqId =>
        !permissionIds.includes(reqId.toString())
      );
      
      if (missingDeps.length > 0) {
        errors.push({
          type: 'missing_dependency',
          permission: permission.name,
          missingDependencies: missingDeps
        });
      }
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

// Query middleware to exclude soft deleted documents
permissionsSchema.pre(/^find/, function(next) {
  if (!this.getQuery().isDeleted) {
    this.find({ isDeleted: { $ne: true } });
  }
  next();
});

const Permission = mongoose.model('Permission', permissionsSchema);
module.exports = Permission;