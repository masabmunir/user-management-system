const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const cors = require('cors');   
const compression = require('compression');
const rateLimit = require('express-rate-limit');

// Import middleware and routes
const errorHandler = require('./middleware/errorHandler');
const notFound = require('./middleware/notFound');
const logger = require('./utils/logger');
const { error } = require('console');

// Load environment variables
require('dotenv').config();

const app = express();

// Trust proxy (important for rate limiting behind reverse proxy)
app,set('trust proxy', 1);

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
  crossOriginEmbedderPolicy: false,
}));

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3001',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-refresh-token']
}));

// Request logging
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim())
  }
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression middleware
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '15') * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'), // limit each IP to 100 requests per windowMs
  message:{
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: Math.ceil(parseInt(process.env.RATE_LIMIT_WINDOW) || 15)
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: Math.ceil(parseInt(process.env.RATE_LIMIT_WINDOW) || 15)
    });
  }
});

app.use('/api/',limiter);

// Health check endpoint
app.get('/health',(req,res)=>{
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV
    })
})

// API Routes

app.use('/api/auth',  require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/roles', require('./routes/roles'));
app.use('/api/admin'),  require('./routes/admin')

// Serve static files (uploaded files)
app.use('/uploads', express.static('uploads'));

// API documentation endpoint
app.use('/api',(req,res)=>{
    res.json({
        name: 'User Management System API',
    version: '1.0.0',
    description: 'Enterprise User Management System with Role-Based Access Control',
    endpoints: {
      auth: '/api/auth',
      users: '/api/users',
      roles: '/api/roles',
      admin: '/api/admin'
    },
    documentation: '/api/docs' // Future implementation
  });
});


// 404 handler
app.use(notFound);

// Global error handler
app.use(errorHandler);

module.exports = app;