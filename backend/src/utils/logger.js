// A09: Security Logging & Monitoring — Winston structured logger
const winston = require('winston');

// SSE client registry for real-time log streaming to the frontend
const sseClients = new Set();

function broadcastLog(entry) {
  if (sseClients.size === 0) return;
  const data = JSON.stringify(entry);
  for (const res of sseClients) {
    try {
      res.write('data: ' + data + '\n\n');
    } catch (_) {
      sseClients.delete(res);
    }
  }
}

// ── Winston instance ─────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  // File transports use JSON for machine-readable audit trail (A09)
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    // Console — human-readable in development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize({ all: true }),
        winston.format.printf(({ level, message, timestamp, ...meta }) => {
          // Strip internal Winston fields
          const { splat, service, ...rest } = meta;
          const metaStr = Object.keys(rest).length
            ? ' ' + JSON.stringify(rest)
            : '';
          return `${timestamp} ${level}: ${message}${metaStr}`;
        })
      ),
    }),
  ],
});

// ── logEvent — the single function every file calls ─────────────────────────
function logEvent(event, details = {}) {
  const entry = {
    id: Date.now() + '-' + Math.random().toString(36).slice(2, 7),
    event,
    timestamp: new Date().toISOString(),
    ...details,
  };

  // Log to Winston — message is the event name, meta is the details
  const { id, timestamp, ...meta } = entry;
  logger.info(event, meta);

  // Broadcast to any connected SSE clients (Live Logs page)
  broadcastLog(entry);

  return entry;
}

module.exports = { logger, logEvent, sseClients };
