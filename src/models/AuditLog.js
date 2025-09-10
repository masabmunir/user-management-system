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
})