const express = require('express');
const adminController = require('../controllers/adminController');
const { authenticate, authorize } = require('../middleware/auth');
const { query, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');

const router = express.Router();