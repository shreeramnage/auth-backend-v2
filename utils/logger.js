import pino from 'pino';

// Pretty-printed and readable while developing; raw JSON in production,
// which is what a real log aggregator actually wants to ingest
const logger = pino({
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty' }
    : undefined,
});

export default logger;
