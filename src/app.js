const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

// Import utilities and middleware
const logger = require('./utils/logger');
const connectDB = require('./config/database');
const errorHandler = require('./middleware/errorHandler');
const notFound = require('./middleware/notFound');

// Import routes
const authRoutes = require('./routes/authRoutes');
const emailRoute = require('./routes/emailRoutes');
const userRoutes = require('./routes/userRoutes');
const roleRoutes = require('./routes/roleRoutes')
const permissionRoutes = require('./routes/permissionRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();

// Trust proxy for accurate IP addresses
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',')
      : ['http://localhost:3000', 'http://localhost:3001'];

    // Allow requests with no origin (like mobile apps or Postman)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-requested-with']
};

app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Request logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined', {
    stream: { write: message => logger.info(message.trim()) }
  }));
}

// Request ID and timestamp
app.use((req, res, next) => {
  req.requestId = Math.random().toString(36).substring(2, 15);
  req.requestTime = new Date();
  res.set('X-Request-ID', req.requestId);
  next();
});

// Connect to database
connectDB();

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    version: process.env.npm_package_version || '1.0.0'
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/email', emailRoute);
app.use('/api/users', userRoutes)
app.use('/api/roles', roleRoutes)
app.use('/api/permissions', permissionRoutes);
app.use('/api/admin', adminRoutes);

// API documentation endpoint
app.get('/api', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'User Management System API',
    version: '1.0.0',
    endpoints: {
      authentication: {
        'POST /api/auth/register': 'Register a new user',
        'POST /api/auth/login': 'Login user',
        'POST /api/auth/refresh': 'Refresh access token',
        'POST /api/auth/logout': 'Logout user',
        'POST /api/auth/logout-all': 'Logout from all sessions',
        'GET /api/auth/profile': 'Get user profile',
        'POST /api/auth/forgot-password': 'Request password reset',
        'POST /api/auth/reset-password': 'Reset password with token',
        'POST /api/auth/change-password': 'Change password',
        'GET /api/auth/verify-token': 'Verify token validity'
      },
      email: {  // Add this section
        'POST /api/email/send-verification': 'Send email verification',
        'GET /api/email/verify/:token': 'Verify email with token',
        'POST /api/email/resend-verification': 'Resend verification email'
      },
      user_management: {
        'GET /api/users': 'Get all users (with pagination, filtering)',
        'GET /api/users/stats': 'Get user statistics',
        'GET /api/users/:userId': 'Get single user by ID',
        'PUT /api/users/:userId': 'Update user information',
        'DELETE /api/users/:userId': 'Delete user (soft delete)',
        'PATCH /api/users/:userId/status': 'Update user status',
        'POST /api/users/:userId/roles': 'Assign roles to user',
        'DELETE /api/users/:userId/roles/:roleId': 'Remove role from user',
        'GET /api/users/:userId/permissions': 'Get user permissions'
      },
      role_management: {
        'GET /api/roles': 'Get all roles (with pagination, filtering)',
        'GET /api/roles/stats': 'Get role statistics and analytics',
        'GET /api/roles/hierarchy': 'Get role hierarchy tree',
        'GET /api/roles/:roleId': 'Get single role by ID',
        'POST /api/roles': 'Create a new role',
        'PUT /api/roles/:roleId': 'Update existing role',
        'DELETE /api/roles/:roleId': 'Delete role (soft delete)'
      },
      permission_management: {
        'GET /api/permissions': 'Get all permissions (with filtering)',
        'GET /api/permissions/stats': 'Get permission statistics',
        'GET /api/permissions/categories': 'Get permission categories',
        'GET /api/permissions/:permissionId': 'Get single permission by ID',
        'POST /api/permissions': 'Create a new permission',
        'PUT /api/permissions/:permissionId': 'Update existing permission',
        'DELETE /api/permissions/:permissionId': 'Delete permission (soft delete)'
      },
      admin_features: {
        'GET /api/admin/dashboard': 'System dashboard with statistics',
        'GET /api/admin/activity-logs': 'Activity logs with filtering',
        'POST /api/admin/bulk-import-users': 'Bulk import users from CSV',
        'GET /api/admin/bulk-export-users': 'Bulk export users to CSV',
        'GET /api/admin/health': 'System health check'
      }
    },
    documentation: 'https://your-app-docs.com'
  });
});

// Handle 404 for API routes
app.use('/api', notFound);

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Welcome to User Management System',
    version: '1.0.0',
    api: '/api',
    health: '/health'
  });
});

// Global error handler (must be last)
app.use(errorHandler);

module.exports = app;