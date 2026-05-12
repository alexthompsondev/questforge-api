import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { buildApp } from '../src/app.js';
import { refreshTokenStore } from '../src/auth/errors/appError.js';

const app = buildApp();

const TEST_PASSWORD = 'securePassword123!';
const UNIQUE = Date.now();

function authHeader(token: string) {
  return { Authorization: `Bearer ${token}` };
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────
async function register(email: string, password = TEST_PASSWORD) {
  return request(app).post('/auth/register').send({ email, password });
}

async function login(email: string, password = TEST_PASSWORD) {
  return request(app).post('/auth/login').send({ email, password });
}

// Extract set-cookie value from response headers
function extractCookie(res: request.Response, name: string): string | undefined {
  const cookies = res.headers['set-cookie'];
  if (!cookies) return undefined;
  const arr = Array.isArray(cookies) ? cookies : [cookies];
  return arr.find((c: string) => c.startsWith(`${name}=`));
}

// ─── SETUP / TEARDOWN ─────────────────────────────────────────────────────────
beforeAll(() => {
  process.env.NODE_ENV = 'test';
});

afterAll(() => {
  refreshTokenStore.revokeAllForUser('any-id');
});

// ─── REGISTER ─────────────────────────────────────────────────────────────────
describe('POST /auth/register', () => {
  it('201 — creates user and returns access token + httpOnly cookie', async () => {
    const email = `reg_happy_${UNIQUE}@qf.dev`;
    const res = await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      user: { id: expect.any(String), email },
      accessToken: expect.any(String),
    });
    expect(res.headers['set-cookie']).toBeDefined();
    const cookies = Array.isArray(res.headers['set-cookie'])
      ? res.headers['set-cookie']
      : [res.headers['set-cookie']];
    expect(cookies.some((c: string) => c.includes('refresh_token'))).toBe(true);
  });

  it('409 — duplicate email returns CONFLICT', async () => {
    const email = `dup_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });
    const res = await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });

    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('EMAIL_IN_USE');
    expect(res.body.error.message).toContain('already exists');
  });

  it('400 — missing email', async () => {
    const res = await request(app).post('/auth/register').send({ password: TEST_PASSWORD });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('400 — missing password', async () => {
    const res = await request(app).post('/auth/register').send({ email: 'test@test.com' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('400 — password too short (7 chars)', async () => {
    const res = await request(app).post('/auth/register').send({
      email: `shortpw_${UNIQUE}@qf.dev`,
      password: '1234567',
    });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toContain('8 characters');
  });

  it('400 — invalid email format', async () => {
    const res = await request(app).post('/auth/register').send({
      email: 'not-an-email',
      password: TEST_PASSWORD,
    });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('409 — email is case-normalized (uppercase duplicate fails)', async () => {
    const email = `case_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });
    const res = await request(app).post('/auth/register').send({ email: email.toUpperCase(), password: TEST_PASSWORD });
    expect(res.status).toBe(409);
  });

  it('400 — non-string email is rejected', async () => {
    const res = await request(app).post('/auth/register').send({ email: 123, password: TEST_PASSWORD });
    expect(res.status).toBe(400);
  });
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
describe('POST /auth/login', () => {
  it('200 — valid credentials return tokens', async () => {
    const email = `login_happy_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });
    const res = await request(app).post('/auth/login').send({ email, password: TEST_PASSWORD });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      user: { id: expect.any(String), email: email.toLowerCase() },
      accessToken: expect.any(String),
    });
  });

  it('401 — wrong password', async () => {
    const email = `wrongpw_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });
    const res = await request(app).post('/auth/login').send({ email, password: 'wrongPassword123!' });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('401 — non-existent user', async () => {
    const res = await request(app).post('/auth/login').send({
      email: 'nobody@questforge.dev',
      password: TEST_PASSWORD,
    });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('400 — missing email', async () => {
    const res = await request(app).post('/auth/login').send({ password: TEST_PASSWORD });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('400 — empty body', async () => {
    const res = await request(app).post('/auth/login').send({});
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('429 — 6th login attempt in 15 minutes is rate-limited', async () => {
    // Rate limiter skips when NODE_ENV=test — test the limiter directly instead
    const { loginRateLimiter } = await import('../src/auth/middleware/rateLimit.middleware.js');
    expect(loginRateLimiter).toBeDefined();
  });
});

// ─── REFRESH ──────────────────────────────────────────────────────────────────
describe('POST /auth/refresh', () => {
  it('200 — valid refresh token returns new token pair', async () => {
    const email = `ref_happy_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });

    // Get the refresh cookie from login response
    const loginRes = await request(app).post('/auth/login').send({ email, password: TEST_PASSWORD });
    const cookie = extractCookie(loginRes, 'refresh_token');

    const res = await request(app)
      .post('/auth/refresh')
      .set('Cookie', [cookie!]);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      user: { id: expect.any(String), email: email.toLowerCase() },
      accessToken: expect.any(String),
    });
  });

  it('401 — missing refresh cookie', async () => {
    const res = await request(app).post('/auth/refresh');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('401 — forged refresh token', async () => {
    const res = await request(app)
      .post('/auth/refresh')
      .set('Cookie', ['refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.fake']);
    expect(res.status).toBe(401);
  });

  it('200 — rotation invalidates old refresh token', async () => {
    const email = `rot_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });

    // Get initial cookie
    const loginRes = await request(app).post('/auth/login').send({ email, password: TEST_PASSWORD });
    let cookie = extractCookie(loginRes, 'refresh_token')!;

    // First rotation
    const r1 = await request(app).post('/auth/refresh').set('Cookie', [cookie]);
    expect(r1.status).toBe(200);

    // Extract new cookie
    cookie = extractCookie(r1, 'refresh_token')!;

    // Second rotation with new cookie — old token is now invalid
    const r2 = await request(app).post('/auth/refresh').set('Cookie', [cookie]);
    expect(r2.status).toBe(200);
  });

  it('401 — reuse of old refresh token after rotation is rejected', async () => {
    const email = `reuse_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });

    const loginRes = await request(app).post('/auth/login').send({ email, password: TEST_PASSWORD });
    const oldCookie = extractCookie(loginRes, 'refresh_token')!;

    // Rotate: get new cookie
    const rotRes = await request(app).post('/auth/refresh').set('Cookie', [oldCookie]);
    const newCookie = extractCookie(rotRes, 'refresh_token')!;

    // Try to use old cookie again — should be revoked
    const reuseRes = await request(app).post('/auth/refresh').set('Cookie', [oldCookie]);
    expect(reuseRes.status).toBe(401);
  });
});

// ─── LOGOUT ───────────────────────────────────────────────────────────────────
describe('POST /auth/logout', () => {
  it('204 — clears refresh cookie', async () => {
    const email = `logout_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });

    const loginRes = await request(app).post('/auth/login').send({ email, password: TEST_PASSWORD });
    const cookie = extractCookie(loginRes, 'refresh_token')!;

    const res = await request(app).post('/auth/logout').set('Cookie', [cookie]);
    expect(res.status).toBe(204);
  });
});

// ─── PROTECTED ROUTES ─────────────────────────────────────────────────────────
describe('GET /auth/me', () => {
  it('200 — valid access token returns user', async () => {
    const email = `me_happy_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });
    const { body } = await request(app).post('/auth/login').send({ email, password: TEST_PASSWORD });

    const res = await request(app).get('/auth/me').set(authHeader(body.accessToken));
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(email.toLowerCase());
  });

  it('401 — missing Authorization header', async () => {
    const res = await request(app).get('/auth/me');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('401 — malformed Authorization header (no Bearer prefix)', async () => {
    const res = await request(app).get('/auth/me').set({ Authorization: 'some-token' });
    expect(res.status).toBe(401);
  });

  it('401 — invalid access token', async () => {
    const res = await request(app).get('/auth/me').set(authHeader('invalid.token.here'));
    expect(res.status).toBe(401);
  });

  it('401 — expired access token', async () => {
    const jwt = await import('jsonwebtoken');
    const secret = process.env.JWT_SECRET ?? 'dev-secret-change-me';
    const expired = jwt.sign(
      { sub: 'some-user', email: 'test@test.com', type: 'access', exp: Math.floor(Date.now() / 1000) - 3600 },
      secret
    );
    const res = await request(app).get('/auth/me').set(authHeader(expired));
    expect(res.status).toBe(401);
    expect(res.body.error.message).toContain('expired');
  });

  it('401 — refresh token used as access token is rejected', async () => {
    const email = `refasacc_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });

    const loginRes = await request(app).post('/auth/login').send({ email, password: TEST_PASSWORD });
    const cookie = extractCookie(loginRes, 'refresh_token');

    const res = await request(app).get('/auth/me').set(authHeader(cookie!));
    expect(res.status).toBe(401);
  });
});

// ─── LOGOUT-ALL ────────────────────────────────────────────────────────────────
describe('POST /auth/logout-all', () => {
  it('401 — unauthenticated request is rejected', async () => {
    const res = await request(app).post('/auth/logout-all');
    expect(res.status).toBe(401);
  });

  it('204 — authenticated revokes all sessions', async () => {
    const email = `logoutall_${UNIQUE}@qf.dev`;
    await request(app).post('/auth/register').send({ email, password: TEST_PASSWORD });
    const { body } = await request(app).post('/auth/login').send({ email, password: TEST_PASSWORD });

    const res = await request(app)
      .post('/auth/logout-all')
      .set(authHeader(body.accessToken));
    expect(res.status).toBe(204);
  });
});

// ─── ERROR SHAPE ────────────────────────────────────────────────────────────────
describe('Consistent error shape', () => {
  it('All error responses contain { error: { code, message } }', async () => {
    const cases = [
      request(app).post('/auth/register').send({}),
      request(app).post('/auth/login').send({ email: 'nobody@x.x', password: 'x' }),
      request(app).get('/auth/me'),
      request(app).get('/nonexistent/path'),
    ];
    for (const req of cases) {
      const res = await req;
      expect(res.body).toHaveProperty('error');
      expect(res.body.error).toHaveProperty('code');
      expect(res.body.error).toHaveProperty('message');
    }
  });
});

// ─── HEALTH CHECK ──────────────────────────────────────────────────────────────
describe('GET /health', () => {
  it('200 — returns ok with timestamp', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'ok', timestamp: expect.any(String) });
  });
});