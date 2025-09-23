import { test, expect } from '@playwright/test';

// Simple health check example
test('GET /health returns 200', async ({ request, baseURL }) => {
  const response = await request.get(`${baseURL}/health`);
  expect(response.status()).toBe(200);
});

// Example of POST with JSON body
test('POST /echo echoes payload', async ({ request, baseURL }) => {
  const payload = { ping: 'pong' };
  const response = await request.post(`${baseURL}/echo`, {
    data: payload,
    headers: { 'Content-Type': 'application/json' },
  });
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  expect(body).toMatchObject(payload);
});
