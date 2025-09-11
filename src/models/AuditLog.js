const { required } = require('joi');
const mongoose = require('mongoose');
const { ref } = require('process');

const auditLogSchema = new mongoose.Schema({
    // Basic Information
    action: {
        type: String,
        required: [true, 'Action is required'],
        enum: [
            'create', 'read', 'update', 'delete', 'login', 'logout',
            'password_change', 'password_reset', 'email_verification',
            'role_assigned', 'role_removed', 'permission_granted', 'permission_revoked',
            'account_locked', 'account_unlocked', 'account_suspended', 'account_activated',
            'export_data', 'import_data', 'backup_created', 'system_config_changed',
            'api_access', 'file_upload', 'file_download', 'report_generated',
            'custom'
        ]

    },
    // Actor Information
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: function () {
            return this.actorType === 'user';
        }
    },
    
    actorType: {
        required: true,
        enum: ['user', 'system', 'api', 'cron', 'admin'],
        default: 'user'
    },

    actorDetails: {
        username: String,
        email: String,
        roles: [String],
        ipAddress: String,
        userAgent: String
    },

    // Target Information
    targetType: {
    type: String,
    required: [true, 'Target type is required'],
    enum: ['user', 'role', 'permission', 'system', 'file', 'report', 'api', 'custom']
  },

 targetId: {
    type: mongoose.Schema.Types.ObjectId,
    required: function() {
      return ['user', 'role', 'permission'].includes(this.targetType);
    }
  },
  
  targetDetails: {
    name: String,
    identifier: String,
    previousValues: mongoose.Schema.Types.Mixed,
    newValues: mongoose.Schema.Types.Mixed
  },

  // Request Information
  resource: {
    type: String,
    required: [true, 'Resource is required'],
    trim: true
  },
  
  endpoint: {
    method: {
      type: String,
      enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
    },
    path: String,
    query: mongoose.Schema.Types.Mixed,
    body: mongoose.Schema.Types.Mixed // Sensitive data should be filtered out
  },

  // Result Information
  status: {
    type: String,
    enum: ['success', 'failure', 'partial', 'error'],
    required: [true, 'Status is required']
  },
  
  statusCode: {
    type: Number,
    min: 100,
    max: 599
  },
  
  errorMessage: String,
  errorCode: String,

  // Context Information
  sessionId: String,
  
  requestId: {
    type: String,
    required: true,
    unique: true
  },
  
  correlationId: String, // For tracking related actions

   // Location and Device
  location: {
    country: String,
    region: String,
    city: String,
    latitude: Number,
    longitude: Number,
    timezone: String
  },
  
  device: {
    type: String,
    browser: String,
    os: String,
    isMobile: Boolean,
    deviceId: String
  },

  // Security Context
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  
  riskFactors: [{
    factor: String,
    score: Number,
    description: String
  }],
  
  anomalyFlags: [{
    type: String,
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical']
    },
    description: String
  }],
})