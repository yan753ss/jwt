const test = require('node:test');
const assert = require('node:assert/strict');
const { app, users, failedAttempts, resetTokens } = require('../src/server');

let server;
let baseUrl;

async function request(path, options = {}) {
  const res = await fetch(`${baseUrl}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  });

  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }

  return { status: res.status, body };
}

test.before(() => {
  users.length = 0;
  failedAttempts.clear();
  resetTokens.clear();
  server = app.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

test.after(() => {
  server.close();
});

test('register/login/rbac/single-session and reset flow', async () => {
  let elevatedRegister = await request('/register', {
    method: 'POST',
    body: JSON.stringify({ username: 'bob', password: 'Password1!', role: 'admin' })
  });
  assert.equal(elevatedRegister.status, 201);
  assert.equal(elevatedRegister.body.role, 'user');

  let res = await request('/register', {
    method: 'POST',
    body: JSON.stringify({ username: 'alice', password: 'Password1!', role: 'user' })
  });
  assert.equal(res.status, 201);

  for (let i = 0; i < 3; i += 1) {
    const attempt = await request('/login', {
      method: 'POST',
      body: JSON.stringify({ username: 'alice', password: 'wrong' })
    });
    assert.equal(attempt.status, 401);
  }

  res = await request('/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'alice', password: 'wrong' })
  });
  assert.equal(res.status, 429);

  users.length = 0;
  failedAttempts.clear();
  resetTokens.clear();

  await request('/register', {
    method: 'POST',
    body: JSON.stringify({ username: 'alice', password: 'Password1!', role: 'user' })
  });

  res = await request('/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'alice', password: 'Password1!' })
  });
  assert.equal(res.status, 200);
  const token1 = res.body.token;

  const me = await request('/me', { headers: { Authorization: `Bearer ${token1}` } });
  assert.equal(me.status, 200);

  const adminDenied = await request('/admin', { headers: { Authorization: `Bearer ${token1}` } });
  assert.equal(adminDenied.status, 403);

  const secondLogin = await request('/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'alice', password: 'Password1!' })
  });
  assert.equal(secondLogin.status, 200);
  const token2 = secondLogin.body.token;

  const oldToken = await request('/me', { headers: { Authorization: `Bearer ${token1}` } });
  assert.equal(oldToken.status, 401);

  const newToken = await request('/me', { headers: { Authorization: `Bearer ${token2}` } });
  assert.equal(newToken.status, 200);

  const resetRequest = await request('/password-reset/request', {
    method: 'POST',
    body: JSON.stringify({ username: 'alice' })
  });
  assert.equal(resetRequest.status, 200);
  assert.ok(resetRequest.body.resetToken);

  const resetConfirm = await request('/password-reset/confirm', {
    method: 'POST',
    body: JSON.stringify({ resetToken: resetRequest.body.resetToken, newPassword: 'NewPass123!' })
  });
  assert.equal(resetConfirm.status, 200);

  const oldPass = await request('/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'alice', password: 'Password1!' })
  });
  assert.equal(oldPass.status, 401);

  const newPass = await request('/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'alice', password: 'NewPass123!' })
  });
  assert.equal(newPass.status, 200);

});
