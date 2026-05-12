import express, { type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import morgan from 'morgan';
import { buildAuthRouter } from './auth/routes.auth.js';
import { globalErrorHandler, notFoundHandler } from './middleware/error.middleware.js';

export function buildApp(): express.Application {
  const app = express();

  app.set('trust proxy', 1);

  app.use(cors());
  app.use(express.json());
  app.use(cookieParser());

  if (process.env.NODE_ENV !== 'test') {
    app.use(morgan('dev'));
  }

  app.get('/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  app.use('/auth', buildAuthRouter());

  app.use(notFoundHandler);
  app.use(globalErrorHandler);

  return app;
}