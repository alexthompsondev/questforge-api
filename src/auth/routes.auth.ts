import express from 'express';
import crypto from 'crypto';
import {
  hashPassword,
  comparePassword,
  generateTokens,
  verifyRefreshToken,
} from './services/auth.service.js';
import { requireAuth } from './middleware/auth.middleware.js';
import { loginRateLimiter } from './middleware/rateLimit.middleware.js';
import {
  ErrBadRequest,
  ErrUnauthorized,
  ErrConflict,
  refreshTokenStore,
} from './errors/appError.js';
import type { AuthUser, RegisterInput, LoginInput } from './types/auth.types.js';

// In-memory user store — swap for a real DB adapter in production
const users = new Map<string, { id: string; email: string; passwordHash: string }>();

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

// ─── Cookie options ────────────────────────────────────────────────────────────
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  path: '/auth/refresh',
  maxAge: 7 * 24 * 60 * 60 * 1000,
};

function setRefreshCookie(res: express.Response, token: string) {
  res.cookie('refresh_token', token, COOKIE_OPTIONS);
}

function clearRefreshCookie(res: express.Response) {
  res.clearCookie('refresh_token', { ...COOKIE_OPTIONS, maxAge: 0 });
}

// ─── POST /auth/register ───────────────────────────────────────────────────────
export const register = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> => {
  try {
    const { email, password } = req.body as RegisterInput;

    if (!email || !password) {
      return next(ErrBadRequest('email and password are required', 'VALIDATION_ERROR'));
    }
    if (typeof email !== 'string' || !email.includes('@')) {
      return next(ErrBadRequest('Invalid email format', 'VALIDATION_ERROR'));
    }
    if (typeof password !== 'string' || password.length < 8) {
      return next(ErrBadRequest('Password must be at least 8 characters', 'VALIDATION_ERROR'));
    }

    const normalized = normalizeEmail(email);
    if (users.has(normalized)) {
      return next(ErrConflict('An account with this email already exists', 'EMAIL_IN_USE'));
    }

    const id = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    users.set(normalized, { id, email: normalized, passwordHash });

    const tokens = generateTokens(id, normalized);
    const decoded = verifyRefreshToken(tokens.refreshToken);
    refreshTokenStore.store(
      decoded.jti,
      id,
      normalized,
      decoded.family,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    );

    setRefreshCookie(res, tokens.refreshToken);

    const user: AuthUser = { id, email: normalized };
    res.status(201).json({ user, accessToken: tokens.accessToken });
  } catch (err) {
    next(err);
  }
};

// ─── POST /auth/login ──────────────────────────────────────────────────────────
export const login = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> => {
  try {
    const { email, password } = req.body as LoginInput;

    if (!email || !password) {
      return next(ErrBadRequest('email and password are required', 'VALIDATION_ERROR'));
    }

    const normalized = normalizeEmail(email);
    const record = users.get(normalized);

    if (!record || !(await comparePassword(password, record.passwordHash))) {
      return next(ErrUnauthorized('Invalid email or password'));
    }

    const tokens = generateTokens(record.id, record.email);
    const decoded = verifyRefreshToken(tokens.refreshToken);
    refreshTokenStore.store(
      decoded.jti,
      record.id,
      record.email,
      decoded.family,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    );

    setRefreshCookie(res, tokens.refreshToken);

    const user: AuthUser = { id: record.id, email: record.email };
    res.status(200).json({ user, accessToken: tokens.accessToken });
  } catch (err) {
    next(err);
  }
};

// ─── POST /auth/refresh ────────────────────────────────────────────────────────
export const refresh = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> => {
  try {
    const token = req.cookies?.refresh_token;
    if (!token) {
      return next(ErrUnauthorized('No refresh token provided'));
    }

    let decoded: ReturnType<typeof verifyRefreshToken>;
    try {
      decoded = verifyRefreshToken(token);
    } catch {
      return next(ErrUnauthorized('Invalid or expired refresh token'));
    }

    const stored = refreshTokenStore.get(decoded.jti);
    if (!stored) {
      // Token reuse — revoke entire family as precaution
      refreshTokenStore.revokeFamily(decoded.family);
      return next(ErrUnauthorized('Refresh token has been revoked'));
    }

    // Rotate: revoke old token, issue new pair
    refreshTokenStore.revoke(decoded.jti);

    const newTokens = generateTokens(decoded.sub, decoded.email);
    const newDecoded = verifyRefreshToken(newTokens.refreshToken);
    refreshTokenStore.store(
      newDecoded.jti,
      decoded.sub,
      decoded.email,
      newDecoded.family,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    );

    setRefreshCookie(res, newTokens.refreshToken);

    const user: AuthUser = { id: decoded.sub, email: decoded.email };
    res.status(200).json({ user, accessToken: newTokens.accessToken });
  } catch (err) {
    next(err);
  }
};

// ─── POST /auth/logout ─────────────────────────────────────────────────────────
export const logout = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> => {
  try {
    const token = req.cookies?.refresh_token;
    if (token) {
      try {
        const decoded = verifyRefreshToken(token);
        refreshTokenStore.revoke(decoded.jti);
      } catch {
        // invalid token — nothing to revoke
      }
    }
    clearRefreshCookie(res);
    res.status(204).send();
  } catch (err) {
    next(err);
  }
};

// ─── POST /auth/logout-all ─────────────────────────────────────────────────────
export const logoutAll = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> => {
  try {
    if (!req.user) return next(ErrUnauthorized());
    refreshTokenStore.revokeAllForUser(req.user.id);
    clearRefreshCookie(res);
    res.status(204).send();
  } catch (err) {
    next(err);
  }
};

// ─── GET /auth/me ──────────────────────────────────────────────────────────────
export const me = (req: express.Request, res: express.Response): void => {
  res.json({ user: req.user });
};

// ─── Router factory ─────────────────────────────────────────────────────────────
export function buildAuthRouter(): express.Router {
  const router = express.Router();

  router.post('/register', register);
  router.post('/login', loginRateLimiter, login);
  router.post('/refresh', refresh);
  router.post('/logout', logout);
  router.post('/logout-all', requireAuth, logoutAll);
  router.get('/me', requireAuth, me);

  return router;
}