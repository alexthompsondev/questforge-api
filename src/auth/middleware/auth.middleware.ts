import type { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../services/auth.service.js';
import { ErrUnauthorized } from '../errors/appError.js';

/**
 * Protects routes using a Bearer access token.
 * Sets req.user on success.
 */
export const requireAuth = (req: Request, _res: Response, next: NextFunction): void => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return next(ErrUnauthorized('Missing or malformed Authorization header. Expected: Bearer <token>'));
  }
  const token = header.slice(7);
  try {
    const payload = verifyAccessToken(token);
    if (payload.type !== 'access') {
      return next(ErrUnauthorized('Invalid token type — access token required'));
    }
    req.user = { id: payload.sub, email: payload.email };
    next();
  } catch (err) {
    const e = err as Error & { name?: string };
    if (e.name === 'TokenExpiredError') {
      return next(ErrUnauthorized('Access token has expired'));
    }
    return next(ErrUnauthorized('Invalid access token'));
  }
};

/**
 * Optional auth — sets req.user if a valid Bearer token is present but does not
 * fail if missing. Useful for endpoints that behave differently for logged-in users.
 */
export const optionalAuth = (req: Request, _res: Response, next: NextFunction): void => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return next();
  const token = header.slice(7);
  try {
    const payload = verifyAccessToken(token);
    if (payload.type === 'access') {
      req.user = { id: payload.sub, email: payload.email };
    }
  } catch {
    // ignore invalid tokens in optional context
  }
  next();
};