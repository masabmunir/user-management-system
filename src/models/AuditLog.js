const mongoose = require('mongoose');

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
            'custom', 'email_verification_sent', 'email_verification_resent', 
        ]
    },

    // Actor Information
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: function() {
            return this.actorType === 'user';
        }
    },

    actorType: {
        type: String,
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
        body: mongoose.Schema.Types.Mixed
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
    },

    correlationId: String,

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
        type: Number,
        default: 2555
    },

    // Performance Metrics
    duration: {
        type: Number,
        min: 0
    },

    responseSize: {
        type: Number,
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
    timestamps: true
});

// Indexes
auditLogSchema.index({ userId: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ targetType: 1, targetId: 1, createdAt: -1 });
auditLogSchema.index({ resource: 1, createdAt: -1 });
auditLogSchema.index({ status: 1, createdAt: -1 });
auditLogSchema.index({ category: 1, createdAt: -1 });
auditLogSchema.index({ severity: 1, createdAt: -1 });
auditLogSchema.index({ requestId: 1 }, { unique: true });

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

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog;