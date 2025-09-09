const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Role name is required'],
    unique: true,
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
