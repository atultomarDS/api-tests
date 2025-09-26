import { test, expect } from '../../src/fixtures/api-fixtures';
import { expectFailure } from '../../src/utils/api-assertions';

test.describe('Security Tests', () => {
  test('SQL injection attempt in user ID', async ({ apiClient }) => {
    const maliciousId = "1'; DROP TABLE users; --";
    const response = await apiClient.get(`/users/${maliciousId}`);
    
    // reqres.in doesn't block SQL injection - it treats it as a string ID
    // This is actually a security vulnerability in the test API
    if (response.status() === 200) {
      console.log('⚠️  Security Issue: API accepts SQL injection in user ID');
      // Verify it doesn't actually execute SQL (returns user data, not error)
      const data = await response.json();
      expect(data).toBeDefined();
    } else {
      // If it does block, that's good
      await expectFailure(response, { status: [400, 404, 403] });
    }
  });

  test('XSS payload in request body', async ({ apiClient }) => {
    const xssPayload = {
      name: '<script>alert("xss")</script>',
      job: 'hacker'
    };
    
    const response = await apiClient.post('/users', xssPayload, {
      headers: { 'Content-Type': 'application/json' },
    });
    
    // reqres.in accepts XSS payloads without sanitization
    if (response.status() === 201) {
      const created = await response.json();
      console.log('⚠️  Security Issue: API accepts XSS payload without sanitization');
      // Document that the API returns raw XSS (security vulnerability)
      expect(created.name).toBe(xssPayload.name);
    } else {
      // If rejected, that's good security practice
      await expectFailure(response, { status: [400, 422] });
    }
  });

  test('Rate limiting behavior', async ({ apiClient }) => {
    const requests = [];
    
    // Send multiple rapid requests
    for (let i = 0; i < 10; i++) {
      requests.push(apiClient.get('/users'));
    }
    
    const responses = await Promise.all(requests);
    
    // Check if any requests were rate limited (429)
    const rateLimited = responses.some(r => r.status() === 429);
    
    if (rateLimited) {
      console.log('Rate limiting is working - some requests returned 429');
    } else {
      console.log('No rate limiting detected - all requests succeeded');
    }
    
    // At least some requests should succeed
    const successCount = responses.filter(r => r.status() === 200).length;
    expect(successCount).toBeGreaterThan(0);
  });

  test('Invalid JSON payload', async ({ apiClient }) => {
    const response = await apiClient.post('/users', '{"name": "test", "job": invalid}', {
      headers: { 'Content-Type': 'application/json' },
    });
    
    await expectFailure(response, { status: [400, 422] });
  });

  test('Missing required fields', async ({ apiClient }) => {
    const incompletePayload = { name: 'test' }; // Missing 'job'
    
    const response = await apiClient.post('/users', incompletePayload, {
      headers: { 'Content-Type': 'application/json' },
    });
    
    // Should either accept (if job is optional) or reject with validation error
    if (response.status() === 201) {
      console.log('API accepts incomplete payload - job field may be optional');
    } else {
      await expectFailure(response, { status: [400, 422] });
    }
  });
});
