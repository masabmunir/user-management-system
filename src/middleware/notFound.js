const notFound = (req, res, next) => {
  res.status(404).json({
    success: false,
    error: `Route ${req.method} ${req.originalUrl} not found`,
    timestamp: new Date().toISOString(),
    availableEndpoints: {
      auth: '/api/auth',
      users: '/api/users',
      roles: '/api/roles',
      admin: '/api/admin',
      health: '/health'
    }
  });
};

module.exports = notFound;