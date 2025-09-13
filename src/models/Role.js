const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Role name is required'],
    trim: true,
    maxlength: [50, 'Role name cannot exceed 50 characters'],
    match: [/^[a-zA-Z0-9_\s-]+$/, 'Role name can only contain letters, numbers, spaces, underscores, and hyphens']
  },
  
  displayName: {
    type: String,
    required: [true, 'Display name is required'],
    trim: true,
    maxlength: [100, 'Display name cannot exceed 100 characters']
  },
  
  description: {
    type: String,
    required: [true, 'Role description is required'],
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  // Role Hierarchy & Inheritance
  level: {
    type: Number,
    required: true,
    min: [1, 'Role level must be at least 1'],
    max: [10, 'Role level cannot exceed 10']
  },
  
  parentRole: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
    default: null
  },
  
  childRoles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],
  
  // Permissions
  permissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission',
    required: true
  }],
  
  // Inherited permissions from parent roles
  inheritedPermissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }],
  
  // Role Properties
  isSystemRole: {
    type: Boolean,
    default: false // System roles cannot be deleted or modified
  },
  
  isDefault: {
    type: Boolean,
    default: false // Default role assigned to new users
  },
  
  status: {
    type: String,
    enum: ['active', 'inactive', 'deprecated'],
    default: 'active'
  },
  
  // Access Control
  maxUsers: {
    type: Number,
    default: null // null means unlimited
  },
  
  currentUserCount: {
    type: Number,
    default: 0
  },
  
  // Role Restrictions
  restrictions: {
    canCreateUsers: {
      type: Boolean,
      default: false
    },
    canModifyUsers: {
      type: Boolean,
      default: false
    },
    canDeleteUsers: {
      type: Boolean,
      default: false
    },
    canAssignRoles: {
      type: Boolean,
      default: false
    },
    canModifyRoles: {
      type: Boolean,
      default: false
    },
    maxSessionDuration: {
      type: Number, // in minutes
      default: null // null means no limit
    },
    allowedIPRanges: [{
      type: String,
      match: [/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/, 'Invalid IP range format']
    }],
    timeRestrictions: {
      allowedHours: {
        start: {
          type: String,
          match: [/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Invalid time format (HH:MM)']
        },
        end: {
          type: String,
          match: [/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Invalid time format (HH:MM)']
        }
      },
      allowedDays: [{
        type: String,
        enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
      }]
    }
  },
  
  // Department/Organization Context
  department: {
    type: String,
    trim: true
  },
  
  organization: {
    type: String,
    trim: true
  },
  
  // Role Metadata
  color: {
    type: String,
    match: [/^#[0-9A-F]{6}$/i, 'Color must be a valid hex color code'],
    default: '#007bff'
  },
  
  icon: {
    type: String,
    default: 'user'
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
      enum: ['created', 'updated', 'permissions_added', 'permissions_removed', 'activated', 'deactivated'],
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
    details: mongoose.Schema.Types.Mixed, // Store specific change details
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

// Indexes 
roleSchema.index({ name: 1 });
roleSchema.index({ level: 1 });
roleSchema.index({ status: 1 });    
roleSchema.index({ isDeleted: 1 });
roleSchema.index({ department: 1 });
roleSchema.index({ organization: 1 });

// Virtual for all permissions (direct + inherited)

roleSchema.virtual('allPermissions').get(function (){
    const directPermissions = this.permissions || [];
    const inheritedPermissions = this.inheritedPermissions || [];

    // Combine and deduplicate permissions
    const allPerms = [...directPermissions, ...inheritedPermissions];
    return [...new Set(allPerms.map(p => p.toString()))];
})

// Pre-save middleware to handle role hierarchy
roleSchema.pre('save', async function(next) {
  // If parent role is set, add this role to parent's children
  if (this.parentRole && this.isModified('parentRole')) {
    await this.constructor.findByIdAndUpdate(
      this.parentRole,
      { $addToSet: { childRoles: this._id } }
    );
  }
  
  next();
});

// Pre-save middleware to calculate inherited permissions
roleSchema.pre('save', async function(next) {
  if (this.parentRole && (this.isModified('parentRole') || this.isModified('permissions'))) {
    await this.calculateInheritedPermissions();
  }
  next();
});

// Instance method to calculate inherited permissions
roleSchema.methods.calculateInheritedPermissions = async function() {
  if (!this.parentRole) {
    this.inheritedPermissions = [];
    return;
  }
  
  const parentRole = await this.constructor.findById(this.parentRole)
    .populate('permissions')
    .populate('inheritedPermissions');
  
  if (parentRole) {
    // Inherit all permissions from parent (direct + inherited)
    const parentAllPermissions = [
      ...(parentRole.permissions || []),
      ...(parentRole.inheritedPermissions || [])
    ];
    
    // Remove duplicates
    const uniquePermissions = [...new Set(parentAllPermissions.map(p => p._id.toString()))];
    this.inheritedPermissions = uniquePermissions;
  }
};

// Instance method to get all child roles recursively
roleSchema.methods.getAllChildRoles = async function() {
  const childRoles = [];
  const queue = [this._id];
  
  while (queue.length > 0) {
    const currentRoleId = queue.shift();
    const currentRole = await this.constructor.findById(currentRoleId);
    
    if (currentRole && currentRole.childRoles) {
      for (const childRoleId of currentRole.childRoles) {
        if (!childRoles.includes(childRoleId.toString())) {
          childRoles.push(childRoleId.toString());
          queue.push(childRoleId);
        }
      }
    }
  }
  
  return childRoles;
};

// Instance method to check if role can be assigned to user
roleSchema.methods.canAssignToUser = function() {
  if (this.status !== 'active') return false;
  if (this.maxUsers && this.currentUserCount >= this.maxUsers) return false;
  return true;
};

// Instance method to add change to history
roleSchema.methods.addToChangeHistory = function(action, changedBy, details, reason) {
  this.changeHistory.push({
    action,
    changedBy,
    changedAt: new Date(),
    details,
    reason
  });
};

// Static method to find active roles
roleSchema.statics.findActiveRoles = function() {
    return this.find({
        status: 'active',
        isDeleted: false
    });
}   

// Static method to find default role
roleSchema.static.defaultRole = function (){
    return this.findOne({
        isDefault : 'true',
        status: 'active',
        isDeleted: false
    })
}

// Static method to find roles by level
roleSchema.static.defaultRole = function (level){
    return this.find({
        level,
        status: 'active',
        isDeleted: false
    })
}

// Static method to build role hierarchy tree
roleSchema.statics.buildHierarchyTree = async function() {
  const roles = await this.find({ isDeleted: false })
    .populate('permissions')
    .populate('parentRole')
    .populate('childRoles')
    .sort({ level: 1 });
  
  const roleMap = new Map();
  const rootRoles = [];
  
  // Create role map
  roles.forEach(role => {
    roleMap.set(role._id.toString(), {
      ...role.toObject(),
      children: []
    });
  });
  
  // Build hierarchy
  roles.forEach(role => {
    if (role.parentRole) {
      const parent = roleMap.get(role.parentRole._id.toString());
      if (parent) {
        parent.children.push(roleMap.get(role._id.toString()));
      }
    } else {
      rootRoles.push(roleMap.get(role._id.toString()));
    }
  });
  
  return rootRoles;
};

// Query middleware to exclude soft deleted documents
roleSchema.pre(/^find/, function(next) {
  if (!this.getQuery().isDeleted) {
    this.find({ isDeleted: { $ne: true } });
  }
  next();
});

// Post middleware to update user count
roleSchema.post('save', async function() {
  if (this.isModified('permissions') || this.isNew) {
    // Update user count for this role
    const User = mongoose.model('User');
    const userCount = await User.countDocuments({ 
      roles: this._id, 
      isDeleted: false 
    });
    
    await this.constructor.findByIdAndUpdate(this._id, { 
      currentUserCount: userCount 
    });
  }
});

const Role = mongoose.model('Role', roleSchema);
module.exports = Role;