// Central export file for all models
const User = require('./User');
const Role = require('./Role');
const Permission = require('./Permission');
const AuditLog = require('./AuditLog');

module.exports= {
    User,
    Role,
    Permission,
    AuditLog
}