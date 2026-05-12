import crypto from 'crypto';

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly isOperational: boolean;
  public readonly errors?: unknown[];

  constructor(
    statusCode: number,
    message: string,
    code: string = 'INTERNAL_ERROR',
    isOperational = true,
    errors?: unknown[]
  ) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    this.errors = errors;
    Object.setPrototypeOf(this, AppError.prototype);
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.errors && this.errors.length > 0 && { errors: this.errors }),
      },
    };
  }
}

export const ErrBadRequest = (msg: string, code = 'BAD_REQUEST', errors?: unknown[]) =>
  new AppError(400, msg, code, true, errors);

export const ErrUnauthorized = (msg = 'Unauthorized') =>
  new AppError(401, msg, 'UNAUTHORIZED');

export const ErrForbidden = (msg = 'Forbidden') =>
  new AppError(403, msg, 'FORBIDDEN');

export const ErrNotFound = (msg = 'Resource not found') =>
  new AppError(404, msg, 'NOT_FOUND');

export const ErrConflict = (msg: string, code = 'CONFLICT') =>
  new AppError(409, msg, code);

export const ErrTooManyRequests = (msg = 'Too many requests, please try again later') =>
  new AppError(429, msg, 'TOO_MANY_REQUESTS');

export const ErrInternal = (msg = 'Internal server error') =>
  new AppError(500, msg, 'INTERNAL_ERROR', false);

export const generateJti = () => crypto.randomUUID();

// ─── In-memory refresh token store (replace with Redis in production) ─────────
interface RefreshTokenMeta {
  userId: string;
  email: string;
  family: string;
  expiresAt: Date;
}

const store = new Map<string, RefreshTokenMeta>();

export const refreshTokenStore = {
  store(jti: string, userId: string, email: string, family: string, expiresAt: Date) {
    store.set(jti, { userId, email, family, expiresAt });
  },
  get(jti: string): RefreshTokenMeta | undefined {
    return store.get(jti);
  },
  revoke(jti: string) {
    store.delete(jti);
  },
  revokeFamily(family: string) {
    for (const [key, val] of store.entries()) {
      if (val.family === family) store.delete(key);
    }
  },
  revokeAllForUser(userId: string) {
    for (const [key, val] of store.entries()) {
      if (val.userId === userId) store.delete(key);
    }
  },
};