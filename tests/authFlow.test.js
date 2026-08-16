import request from 'supertest';
import mongoose from 'mongoose';
import app from '../app.js';

const testEmail = `flow-test-${Date.now()}@example.com`;
const testPassword = 'testPassword123';

// Set-Cookie comes back as an array of full "name=value; attr=..." strings —
// this pulls out just the value for one named cookie
function extractCookieValue(cookieHeaders, name) {
  const line = cookieHeaders.find((c) => c.startsWith(`${name}=`));
  return line ? line.split(';')[0].split('=')[1] : null;
}

beforeAll(async () => {
  await mongoose.connect(process.env.MONGO_URI, { dbName: 'auth-db-v2-test' });
});

afterAll(async () => {
  // Leave the test database clean so re-running this suite doesn't hit
  // "duplicate email" errors from a previous run
  await mongoose.connection.collection('users').deleteMany({ email: testEmail });
  await mongoose.connection.collection('refreshtokens').deleteMany({});
  await mongoose.disconnect();
});

describe('Full auth flow', () => {
  let verificationToken;
  let accessToken;
  let staleCookies, staleCsrf; // the very first login's session — becomes stale after rotation
  let currentCookies, currentCsrf; // always the latest valid session

  test('register', async () => {
    const res = await request(app)
      .post('/register')
      .send({ email: testEmail, password: testPassword });

    expect(res.status).toBe(201);
    expect(res.body.email).toBe(testEmail);
    verificationToken = res.body.verificationToken;
    expect(verificationToken).toBeDefined();
  });

  test('verify email', async () => {
    const res = await request(app)
      .post('/verify-email')
      .send({ token: verificationToken });

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Email verified');
  });

  test('login', async () => {
    const res = await request(app)
      .post('/login')
      .send({ email: testEmail, password: testPassword });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();

    accessToken = res.body.accessToken;
    staleCookies = res.headers['set-cookie'];
    staleCsrf = extractCookieValue(staleCookies, 'csrfToken');
    currentCookies = staleCookies;
    currentCsrf = staleCsrf;
  });

  test('refresh rotates the token', async () => {
    const res = await request(app)
      .post('/refresh')
      .set('Cookie', currentCookies)
      .set('X-CSRF-Token', currentCsrf);

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.accessToken).not.toBe(accessToken); // genuinely a new token

    accessToken = res.body.accessToken;
    currentCookies = res.headers['set-cookie'];
    currentCsrf = extractCookieValue(currentCookies, 'csrfToken');
  });

  test('reusing the pre-rotation token is detected and revokes the family', async () => {
    const res = await request(app)
      .post('/refresh')
      .set('Cookie', staleCookies) // the ORIGINAL login cookies — already rotated away
      .set('X-CSRF-Token', staleCsrf);

    expect(res.status).toBe(401);
    expect(res.body.message).toMatch(/reuse detected/i);
  });

  test('change-password succeeds with a still-valid access token', async () => {
    // Access tokens don't depend on refresh-token/session state at all —
    // this one is still valid even though the whole family was just revoked
    const res = await request(app)
      .post('/change-password')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ currentPassword: testPassword, newPassword: 'newTestPassword456' });

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/all sessions/i);
  });

  test('logout succeeds on a fresh session', async () => {
    // The old family is already dead — log in again with the new password
    // to get a real, live session worth actually testing logout against
    const loginRes = await request(app)
      .post('/login')
      .send({ email: testEmail, password: 'newTestPassword456' });

    const cookies = loginRes.headers['set-cookie'];
    const csrf = extractCookieValue(cookies, 'csrfToken');

    const res = await request(app)
      .post('/logout')
      .set('Cookie', cookies)
      .set('X-CSRF-Token', csrf);

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Logged out');
  });
});
