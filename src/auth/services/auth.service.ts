import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { generateJti } from '../errors/appError.js';

// Separate types to avoid literal type conflict across `type` field
interface AccessPayload {
  sub: string;
  email: string;
  type: 'access';
}

interface RefreshPayload {
  sub: string;
  email: string;
  type: 'refresh';
  jti: string;
  family: string;
}

export const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, 12);
};

export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

export const generateTokens = (userId: string, email: string): { accessToken: string; refreshToken: string } => {
  const secret = process.env.JWT_SECRET ?? 'dev-secret-change-me';

  const accessToken = jwt.sign(
    { sub: userId, email, type: 'access' } as AccessPayload,
    secret,
    { expiresIn: '15m' }
  );

  const refreshJti = generateJti();
  const refreshFamily = generateJti();

  const refreshToken = jwt.sign(
    { sub: userId, email, type: 'refresh', jti: refreshJti, family: refreshFamily } as unknown as RefreshPayload,
    secret,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
};

export const verifyAccessToken = (token: string): AccessPayload => {
  const secret = process.env.JWT_SECRET ?? 'dev-secret-change-me';
  return jwt.verify(token, secret) as AccessPayload;
};

export const verifyRefreshToken = (token: string): RefreshPayload => {
  const secret = process.env.JWT_SECRET ?? 'dev-secret-change-me';
  return jwt.verify(token, secret) as RefreshPayload;
};