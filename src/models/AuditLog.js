const { required, custom } = require('joi');
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
        required: function () {
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

    // Data Classification
    dataClassification: {
        type: String,
        enum: ['public', 'internal', 'confidential', 'restricted'],
        default: 'internal'
    },

    sensitiveDataInvolved: {
        type: Boolean,
        default: false
    },

    piiInvolved: {
        type: Boolean,
        default: false
    },

    // Compliance and Regulatory
    complianceFrameworks: [{
        type: String,
        enum: ['gdpr', 'hipaa', 'sox', 'pci-dss', 'iso27001', 'custom']
    }],

    retentionPeriod: {
        type: Number, // Days
        default: 2555 // 7 years default
    },

    // Performance Metrics
    duration: {
        type: Number, // Milliseconds
        min: 0
    },

    responseSize: {
        type: Number, // Bytes
        min: 0
    },

    // Additional Metadata
    tags: [{
        type: String,
        trim: true,
        lowercase: true
    }],

    category: {
        type: String,
        enum: [
            'authentication', 'authorization', 'user_management', 'data_access',
            'system_administration', 'security', 'compliance', 'api_usage',
            'file_operations', 'reporting', 'configuration', 'custom'
        ],
        default: 'custom'
    },

    severity: {
        type: String,
        enum: ['info', 'warning', 'error', 'critical'],
        default: 'info'
    },
    // Custom Fields for Extension
    customFields: mongoose.Schema.Types.Mixed,

    // Workflow and Approval Context
    workflowId: String,
    approvalStatus: {
        type: String,
        enum: ['pending', 'approved', 'rejected', 'auto_approved']
    },
    approvedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },

    // Source Information
    source: {
        application: String,
        module: String,
        version: String,
        environment: {
            type: String,
            enum: ['development', 'staging', 'production', 'testing']
        }
    }

}, {
    timestamps: true,
    // Optimize for time-series queries
    timeseries: {
        timeField: 'createdAt',
        metaField: 'userId',
        granularity: 'hours'
    }
});

// Indexes for performance
// Indexes for performance
auditLogSchema.index({ userId: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ targetType: 1, targetId: 1, createdAt: -1 });
auditLogSchema.index({ resource: 1, createdAt: -1 });
auditLogSchema.index({ status: 1, createdAt: -1 });
auditLogSchema.index({ category: 1, createdAt: -1 });
auditLogSchema.index({ severity: 1, createdAt: -1 });
auditLogSchema.index({ requestId: 1 }, { unique: true });
auditLogSchema.index({ correlationId: 1 });
auditLogSchema.index({ sessionId: 1 });
auditLogSchema.index({ 'actorDetails.ipAddress': 1, createdAt: -1 });
auditLogSchema.index({ riskScore: -1, createdAt: -1 });
auditLogSchema.index({ complianceFrameworks: 1, createdAt: -1 });
auditLogSchema.index({ tags: 1 });

// TTL index for automatic cleanup (7 years default)
auditLogSchema.index({ createdAt: 1 }, { 
  expireAfterSeconds: 60 * 60 * 24 * 2555 // 7 years in seconds
});

// Virtual for formatted duration
auditLogSchema.virtual('formattedDuration').get(function() {
  if (!this.duration) return null;
  
  if (this.duration < 1000) {
    return `${this.duration}ms`;
  } else if (this.duration < 60000) {
    return `${(this.duration / 1000).toFixed(2)}s`;
  } else {
    return `${(this.duration / 60000).toFixed(2)}m`;
  }
});

// Virtual for risk level
auditLogSchema.virtual('riskLevel').get(function() {
  if (this.riskScore >= 80) return 'critical';
  if (this.riskScore >= 60) return 'high';
  if (this.riskScore >= 40) return 'medium';
  return 'low';
});

// Static method to create audit log entry
auditLogSchema.statics.createEntry = async function(data) {
  const entry = new this({
    requestId: data.requestId || this.generateRequestId(),
    ...data
  });
  
  return await entry.save();
};

// Static method to generate unique request ID
auditLogSchema.statics.generateRequestId = function() {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 8);
  return `${timestamp}-${random}`;
};

// Static method to find by user
auditLogSchema.statics.findByUser = function(userId, options = {}) {
  const {
    startDate,
    endDate,
    actions,
    limit = 100,
    skip = 0
  } = options;
  
  const query = { userId };
  
  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }
  
  if (actions && actions.length > 0) {
    query.action = { $in: actions };
  }
  
  return this.find(query)
    .sort({ createdAt: -1 })
    .limit(limit)
    .skip(skip)
    .populate('userId', 'username email firstName lastName')
    .populate('approvedBy', 'username email firstName lastName');
};

// Static method to find security events
auditLogSchema.statics.findSecurityEvents = function(options = {}) {
  const {
    startDate,
    endDate,
    severity = ['error', 'critical'],
    limit = 100
  } = options;
  
  const query = {
    $or: [
      { severity: { $in: severity } },
      { riskScore: { $gte: 60 } },
      { anomalyFlags: { $exists: true, $ne: [] } }
    ]
  };
  
  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }
  
  return this.find(query)
    .sort({ riskScore: -1, createdAt: -1 })
    .limit(limit)
    .populate('userId', 'username email firstName lastName');
};

// Static method to get activity statistics
auditLogSchema.statics.getActivityStats = async function(options = {}) {
  const {
    startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
    endDate = new Date(),
    groupBy = 'day'
  } = options;
  
  let groupFormat;
  switch (groupBy) {
    case 'hour':
      groupFormat = '%Y-%m-%d-%H';
      break;
    case 'day':
      groupFormat = '%Y-%m-%d';
      break;
    case 'month':
      groupFormat = '%Y-%m';
      break;
    default:
      groupFormat = '%Y-%m-%d';
  }
  
  const pipeline = [
    {
      $match: {
        createdAt: {
          $gte: startDate,
          $lte: endDate
        }
      }
    },
    {
      $group: {
        _id: {
          date: { $dateToString: { format: groupFormat, date: '$createdAt' } },
          action: '$action',
          status: '$status'
        },
        count: { $sum: 1 },
        avgDuration: { $avg: '$duration' },
        avgRiskScore: { $avg: '$riskScore' }
      }
    },
    {
      $sort: { '_id.date': 1 }
    }
  ];
  
  return await this.aggregate(pipeline);
};

// Static method to detect anomalies
auditLogSchema.statics.detectAnomalies = async function(userId, timeWindow = 24) {
  const startTime = new Date(Date.now() - timeWindow * 60 * 60 * 1000);
  
  const pipeline = [
    {
      $match: {
        userId: mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startTime }
      }
    },
    {
      $group: {
        _id: {
          hour: { $hour: '$createdAt' },
          action: '$action'
        },
        count: { $sum: 1 },
        uniqueIPs: { $addToSet: '$actorDetails.ipAddress' },
        locations: { $addToSet: '$location.country' }
      }
    },
    {
      $project: {
        count: 1,
        ipCount: { $size: '$uniqueIPs' },
        locationCount: { $size: '$locations' },
        anomalyScore: {
          $add: [
            { $multiply: [{ $max: [0, { $subtract: ['$count', 10] }] }, 2] }, // High activity
            { $multiply: [{ $max: [0, { $subtract: [{ $size: '$uniqueIPs' }, 3] }] }, 5] }, // Multiple IPs
            { $multiply: [{ $max: [0, { $subtract: [{ $size: '$locations' }, 2] }] }, 10] } // Multiple locations
          ]
        }
      }
    },
    {
      $match: {
        anomalyScore: { $gt: 0 }
      }
    },
    {
      $sort: { anomalyScore: -1 }
    }
  ];
  
  return await this.aggregate(pipeline);
};

// Instance method to calculate risk score
auditLogSchema.methods.calculateRiskScore = function() {
  let score = 0;
  
  // Base score by action type
  const actionRiskScores = {
    'delete': 30,
    'role_assigned': 25,
    'permission_granted': 25,
    'password_change': 20,
    'account_unlocked': 20,
    'system_config_changed': 40,
    'export_data': 15,
    'login': 5,
    'read': 1
  };
  
  score += actionRiskScores[this.action] || 10;
  
  // Add risk for failure status
  if (this.status === 'failure' || this.status === 'error') {
    score += 20;
  }
  
  // Add risk for sensitive data
  if (this.sensitiveDataInvolved) score += 15;
  if (this.piiInvolved) score += 20;
  
  // Add risk for off-hours access
  const hour = new Date(this.createdAt).getHours();
  if (hour < 6 || hour > 22) {
    score += 10;
  }
  
  // Add risk factors
  if (this.riskFactors && this.riskFactors.length > 0) {
    score += this.riskFactors.reduce((sum, factor) => sum + factor.score, 0);
  }
  
  this.riskScore = Math.min(100, Math.max(0, score));
  return this.riskScore;
};

// Pre-save middleware to calculate risk score
auditLogSchema.pre('save', function(next){
    if(this.isNew || this.isModified('action') || this.isModified('status')){
        this.calculateRiskScore();
    }
    next();
})

const auditLog = mongoose.model('AuditLog', auditLogSchema);
module.exports = auditLog;