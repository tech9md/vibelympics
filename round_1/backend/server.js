import express from 'express';
import { readFileSync, writeFileSync, existsSync, renameSync, unlinkSync, statSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomUUID } from 'crypto';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import pino from 'pino';

// Structured logger configuration
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = join(__dirname, 'data.json');

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || true, // Allow all in dev, configure in prod
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

// Rate limiting - general
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: { error: '⏳ Too many requests, please try again later' }
});

// Rate limiting - stricter for writes
const writeLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 writes per minute
  message: { error: '⏳ Too many save requests, please slow down' }
});

app.use(generalLimiter);

// Body parser with size limit
app.use(express.json({ limit: '1mb' }));

// Request ID middleware - adds correlation ID to all requests
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || randomUUID();
  res.setHeader('x-request-id', req.id);
  next();
});

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    logger.info({
      type: 'request',
      requestId: req.id,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: Date.now() - start,
      userAgent: req.headers['user-agent'],
      ip: req.ip
    });
  });

  next();
});

// Serve static files from the frontend build
const staticPath = join(__dirname, '../frontend/dist');
if (existsSync(staticPath)) {
  app.use(express.static(staticPath));
}

// Initialize data file if it doesn't exist
if (!existsSync(DATA_FILE)) {
  writeFileSync(DATA_FILE, JSON.stringify([]));
}

// Validation helper
const isValidRoom = (room) => {
  return room &&
    typeof room === 'object' &&
    (typeof room.id === 'string' || typeof room.id === 'number') &&
    typeof room.type === 'string' &&
    typeof room.tasks === 'object' &&
    typeof room.priority === 'string';
};

const isValidRoomsArray = (data) => {
  return Array.isArray(data) && data.every(isValidRoom);
};

// Atomic file write helper
const atomicWriteFile = (filePath, data) => {
  const tempPath = filePath + '.tmp';
  try {
    writeFileSync(tempPath, data);
    renameSync(tempPath, filePath);
  } catch (error) {
    // Clean up temp file if it exists
    try { unlinkSync(tempPath); } catch {}
    throw error;
  }
};

// API Routes
app.get('/api/rooms', (req, res) => {
  try {
    const data = readFileSync(DATA_FILE, 'utf-8');
    const rooms = JSON.parse(data);
    logger.info({ type: 'data', action: 'read', roomCount: rooms.length, requestId: req.id });
    res.json(rooms);
  } catch (error) {
    logger.error({ type: 'error', action: 'read', error: error.message, code: error.code, requestId: req.id });
    if (error.code === 'ENOENT') {
      res.json([]);
    } else {
      res.status(500).json({ error: '📋❌ Failed to read data', requestId: req.id });
    }
  }
});

app.post('/api/rooms', writeLimiter, (req, res) => {
  try {
    // Validate input
    if (!isValidRoomsArray(req.body)) {
      logger.warn({ type: 'validation', action: 'save', error: 'Invalid data format', roomCount: req.body?.length, requestId: req.id });
      return res.status(400).json({ error: '❌ Invalid data format', requestId: req.id });
    }

    // Atomic write to prevent corruption
    atomicWriteFile(DATA_FILE, JSON.stringify(req.body, null, 2));
    logger.info({ type: 'data', action: 'save', roomCount: req.body.length, requestId: req.id });
    res.json({ success: true, requestId: req.id });
  } catch (error) {
    logger.error({ type: 'error', action: 'save', error: error.message, stack: error.stack, requestId: req.id });
    res.status(500).json({ error: '💾❌ Failed to save data', requestId: req.id });
  }
});

// Enhanced health check endpoint
app.get('/api/health', (req, res) => {
  const health = {
    status: '✅',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    dataFile: {
      exists: existsSync(DATA_FILE),
      size: existsSync(DATA_FILE) ? statSync(DATA_FILE).size : 0
    }
  };
  res.json(health);
});

// Debug info endpoint - provides server and data statistics
app.get('/api/debug/info', (req, res) => {
  try {
    const data = existsSync(DATA_FILE) ? JSON.parse(readFileSync(DATA_FILE, 'utf-8')) : [];
    res.json({
      server: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        nodeVersion: process.version,
        platform: process.platform
      },
      data: {
        roomCount: data.length,
        roomTypes: data.reduce((acc, r) => {
          acc[r.type] = (acc[r.type] || 0) + 1;
          return acc;
        }, {}),
        staffAssignments: data.reduce((acc, r) => {
          acc[r.assignedTo] = (acc[r.assignedTo] || 0) + 1;
          return acc;
        }, {}),
        lastModified: existsSync(DATA_FILE)
          ? statSync(DATA_FILE).mtime.toISOString()
          : null
      }
    });
  } catch (error) {
    logger.error({ type: 'error', action: 'debug/info', error: error.message, requestId: req.id });
    res.status(500).json({ error: error.message, requestId: req.id });
  }
});

// Data validation endpoint - checks data integrity
app.get('/api/debug/validate', (req, res) => {
  try {
    const data = existsSync(DATA_FILE) ? JSON.parse(readFileSync(DATA_FILE, 'utf-8')) : [];
    const issues = [];

    data.forEach((room, index) => {
      if (!room.id) issues.push({ index, issue: 'Missing ID' });
      if (!room.type) issues.push({ index, issue: 'Missing type' });
      if (!room.tasks) issues.push({ index, issue: 'Missing tasks' });
      if (room.tasks && typeof room.tasks !== 'object') issues.push({ index, issue: 'Invalid tasks format' });
    });

    res.json({
      valid: issues.length === 0,
      roomCount: data.length,
      issues
    });
  } catch (error) {
    logger.error({ type: 'error', action: 'debug/validate', error: error.message, requestId: req.id });
    res.json({ valid: false, error: error.message, requestId: req.id });
  }
});

// Serve index.html for all other routes (SPA support)
app.get('*', (req, res) => {
  const indexPath = join(staticPath, 'index.html');
  if (existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({ error: '🏠❌' });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error({
    type: 'error',
    requestId: req.id,
    method: req.method,
    path: req.path,
    error: err.message,
    stack: err.stack,
    body: req.method === 'POST' ? { roomCount: req.body?.length } : undefined
  });
  res.status(500).json({ error: '⚠️ Something went wrong', requestId: req.id });
});

app.listen(PORT, '0.0.0.0', () => {
  logger.info({ type: 'startup', message: '🏠✨ Server running', port: PORT });
  logger.info({ type: 'startup', message: '🔒 Security middleware enabled' });
  logger.info({ type: 'startup', message: '📊 Observability enabled', features: ['structured-logging', 'request-tracing', 'debug-endpoints'] });
});
