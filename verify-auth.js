/**
 * Post-deploy verification for auth feature
 * Usage: BASE_URL=https://devbook.digital node verify-auth.js
 */
const BASE = process.env.BASE_URL || 'https://devbook.digital';
const testEmail = `test_${Date.now()}@reqpad-test.com`;
const testPassword = 'TestPass123!';

let passed = 0;
let failed = 0;

async function check(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    console.log(`  ✗ ${name}: ${err.message}`);
  }
}

async function run() {
  console.log(`\nVerifying auth at ${BASE}\n`);

  // 1. Health check
  await check('Health endpoint', async () => {
    const res = await fetch(`${BASE}/health`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'healthy') throw new Error('Not healthy');
  });

  // 2. Login page serves HTML
  await check('Login page serves HTML', async () => {
    const res = await fetch(`${BASE}/login`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const html = await res.text();
    if (!html.includes('auth-form')) throw new Error('Missing auth form');
  });

  // 3. API routes require auth
  await check('API routes return 401 without token', async () => {
    const res = await fetch(`${BASE}/api/templates`);
    if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
  });

  // 4. Signup
  let token;
  await check('Signup creates account and returns JWT', async () => {
    const res = await fetch(`${BASE}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: testPassword })
    });
    if (res.status !== 201) throw new Error(`Status ${res.status}: ${await res.text()}`);
    const data = await res.json();
    if (!data.token) throw new Error('No token returned');
    if (!data.user || !data.user.email) throw new Error('No user returned');
    token = data.token;
  });

  // 5. Duplicate signup fails
  await check('Duplicate signup returns 409', async () => {
    const res = await fetch(`${BASE}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: testPassword })
    });
    if (res.status !== 409) throw new Error(`Expected 409, got ${res.status}`);
  });

  // 6. Login
  await check('Login returns JWT', async () => {
    const res = await fetch(`${BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: testPassword })
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (!data.token) throw new Error('No token');
    token = data.token;
  });

  // 7. GET /auth/me
  await check('GET /auth/me returns user', async () => {
    const res = await fetch(`${BASE}/auth/me`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (!data.user || data.user.email !== testEmail) throw new Error('Wrong user');
  });

  // 8. Authenticated API access
  await check('Authenticated API access works', async () => {
    const res = await fetch(`${BASE}/api/templates`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (!Array.isArray(data)) throw new Error('Expected array');
  });

  // 9. Bad password fails
  await check('Wrong password returns 401', async () => {
    const res = await fetch(`${BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: 'wrongpassword' })
    });
    if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
  });

  // 10. Short password rejected
  await check('Short password rejected on signup', async () => {
    const res = await fetch(`${BASE}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'short@test.com', password: '123' })
    });
    if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
  });

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run();
