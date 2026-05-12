import rateLimit from 'express-rate-limit';
import { ErrTooManyRequests } from '../errors/appError.js';

/**
 * Rate limiter for login endpoint.
 * 5 attempts per 15 minutes per IP.
 */
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip ?? req.headers['x-forwarded-for']?.toString() ?? 'unknown',
  handler: (_req, _res, next) => {
    next(ErrTooManyRequests('Too many login attempts. Please try again in 15 minutes.'));
  },
  skip: () => process.env.NODE_ENV === 'test',
});