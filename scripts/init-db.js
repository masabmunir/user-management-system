#!/usr/bin/env node

/**
 * Database Initialization Script
 * 
 * This script initializes the database with default data including:
 * - System permissions
 * - Default roles (super_admin, admin, manager, user, viewer)
 * - System administrator account
 * 
 * Usage:
 * npm run init-db                    # Initialize database
 * npm run init-db -- --reset         # Reset and re-initialize
 * npm run init-db -- --update-perms  # Update permissions only
 */

require('dotenv').config();
const mongoose = require('mongoose');
const { seedDatabase, resetDatabase, updatePermissions } = require('../src/seeders');
const logger = require('../src/utils/logger');

// Parse command line arguments
const args = process.argv.slice(2);
const shouldReset = args.includes('--reset');
const shouldUpdatePerms = args.includes('--update-perms');
const shouldHelp = args.includes('--help') || args.includes('-h');

function showHelp() {
  console.log(`
Database Initialization Script

Usage: node scripts/init-db.js [options]

Options:
  --reset         Reset database and reinitialize with fresh data
  --update-perms  Update system permissions only
  --help, -h      Show this help message

Examples:
  node scripts/init-db.js                    # Initialize database
  node scripts/init-db.js --reset            # Reset and reinitialize
  node scripts/init-db.js --update-perms     # Update permissions
  `);
}

async function connectToDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/user_management';
    
    logger.info('Connecting to MongoDB...');
    await mongoose.connect(mongoUri);
    logger.info(`✅ Connected to MongoDB: ${mongoUri}`);
    
  } catch (error) {
    logger.error('❌ MongoDB connection failed:', error.message);
    process.exit(1);
  }
}

async function disconnectFromDatabase() {
  try {
    await mongoose.disconnect();
    logger.info('📤 Disconnected from MongoDB');
  } catch (error) {
    logger.error('Error disconnecting from MongoDB:', error.message);
  }
}

async function main() {
  try {
    // Show help if requested
    if (shouldHelp) {
      showHelp();
      return;
    }
    
    logger.info('🚀 Starting database initialization...');
    
    // Connect to database
    await connectToDatabase();
    
    // Execute based on options
    if (shouldReset) {
      logger.warn('⚠️  RESET MODE: This will delete all existing data!');
      
      // Add confirmation in production
      if (process.env.NODE_ENV === 'production') {
        logger.error('❌ Reset is not allowed in production environment');
        process.exit(1);
      }
      
      await resetDatabase();
      
    } else if (shouldUpdatePerms) {
      logger.info('🔄 Updating permissions...');
      await updatePermissions();
      
    } else {
      // Normal initialization
      await seedDatabase();
    }
    
    logger.info('🎉 Database initialization completed successfully!');
    
  } catch (error) {
    logger.error('❌ Database initialization failed:', error.message);
    
    if (error.code === 11000) {
      logger.error('Duplicate key error - some data may already exist');
    } else if (error.name === 'ValidationError') {
      logger.error('Validation error:', error.message);
    } else {
      logger.error('Full error:', error);
    }
    
    process.exit(1);
    
  } finally {
    // Always disconnect
    await disconnectFromDatabase();
  }
}

// Handle process termination
process.on('SIGINT', async () => {
  logger.info('🛑 Process interrupted, closing database connection...');
  await disconnectFromDatabase();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('🛑 Process terminated, closing database connection...');
  await disconnectFromDatabase();
  process.exit(0);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  logger.error('💥 Unhandled Promise Rejection:', err.message);
  process.exit(1);
});

// Run the main function
main();