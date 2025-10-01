import { test, expect } from '../../src/fixtures/api-fixtures';
import { expectFailure } from '../../src/utils/api-assertions';

// Skip if not Iron environment or if running in CI without proper setup
test.skip(
  process.env.TEST_ENV !== 'iron' || (process.env.CI && !process.env.API_TOKEN),
  'Iron MCB tests require TEST_ENV=iron and API_TOKEN (or run locally)'
);

test.describe('Iron MCB - Security Tests', () => {
  test.describe('Authentication & Authorization', () => {
    test('Unauthorized access without token', async ({ apiClient }) => {
      const response = await apiClient.get('/accounts');
      await expectFailure(response, { status: [401, 403] });
    });

    test('Invalid token rejection', async ({ apiClient }) => {
      const response = await apiClient.get('/accounts', {
        headers: { 'Authorization': 'Bearer invalid-token-12345' }
      });
      await expectFailure(response, { status: [401, 403] });
    });

    test('Expired token handling', async ({ apiClient }) => {
      const response = await apiClient.get('/accounts', {
        headers: { 'Authorization': 'Bearer expired-token' }
      });
      await expectFailure(response, { status: [401, 403] });
    });

    test('Malformed token rejection', async ({ apiClient }) => {
      const response = await apiClient.get('/accounts', {
        headers: { 'Authorization': 'InvalidFormat token' }
      });
      await expectFailure(response, { status: [401, 403] });
    });
  });

  test.describe('Input Validation & Injection', () => {
    test('SQL injection in account ID', async ({ apiClient }) => {
      const maliciousId = "1'; DROP TABLE accounts; --";
      const response = await apiClient.get(`/accounts/${maliciousId}`, {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });
      
      await expectFailure(response, { status: [400, 404] });
    });

    test('SQL injection in customer data', async ({ apiClient }) => {
      const maliciousData = {
        firstName: "John'; DROP TABLE customers; --",
        lastName: "Doe",
        email: "john.doe@example.com"
      };

      const response = await apiClient.post('/customers', maliciousData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      // Should either reject or sanitize the input
      await expectFailure(response, { status: [400, 422] });
    });

    test('XSS in customer name', async ({ apiClient }) => {
      const xssData = {
        firstName: '<script>alert("xss")</script>',
        lastName: 'Doe',
        email: 'john.doe@example.com'
      };

      const response = await apiClient.post('/customers', xssData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      // Should either reject or sanitize XSS
      if (response.status() === 201) {
        const created = await response.json();
        expect(created.firstName).not.toContain('<script>');
      } else {
        await expectFailure(response, { status: [400, 422] });
      }
    });

    test('XSS in transaction description', async ({ apiClient }) => {
      const xssData = {
        type: 'DEPOSIT',
        amount: 100.00,
        currency: 'USD',
        accountId: process.env.IRON_TEST_ACCOUNT_ID || 'test-account',
        description: '<script>alert("xss")</script>'
      };

      const response = await apiClient.post('/transactions', xssData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      // Should either reject or sanitize XSS
      if (response.status() === 201) {
        const created = await response.json();
        expect(created.description).not.toContain('<script>');
      } else {
        await expectFailure(response, { status: [400, 422] });
      }
    });
  });

  test.describe('Rate Limiting & Abuse Prevention', () => {
    test('Rate limiting validation', async ({ apiClient }) => {
      const requests = [];
      
      // Send multiple rapid requests
      for (let i = 0; i < 20; i++) {
        requests.push(apiClient.get('/accounts', {
          headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
        }));
      }
      
      const responses = await Promise.all(requests);
      
      // Check if any requests were rate limited (429)
      const rateLimited = responses.some(r => r.status() === 429);
      
      if (rateLimited) {
        console.log('✅ Rate limiting is working - some requests returned 429');
      } else {
        console.log('⚠️ No rate limiting detected - consider implementing rate limits');
      }
      
      // At least some requests should succeed
      const successCount = responses.filter(r => r.status() === 200).length;
      expect(successCount).toBeGreaterThan(0);
    });

    test('Concurrent request handling', async ({ apiClient }) => {
      const requests = [];
      
      // Send concurrent requests from different sources
      for (let i = 0; i < 10; i++) {
        requests.push(apiClient.get('/customers', {
          headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
        }));
      }
      
      const responses = await Promise.all(requests);
      
      // All requests should be handled appropriately
      responses.forEach(response => {
        expect([200, 429, 503]).toContain(response.status());
      });
    });
  });

  test.describe('Data Protection & Privacy', () => {
    test('PII data exposure check', async ({ apiClient }) => {
      const response = await apiClient.get('/customers', {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });

      if (response.status() === 200) {
        const customers = await response.json();
        
        // Check that sensitive data is not exposed
        if (Array.isArray(customers) && customers.length > 0) {
          const customer = customers[0];
          
          // SSN should be masked or not returned
          if (customer.ssn) {
            expect(customer.ssn).toMatch(/\*{3}-\*{2}-\*{4}/); // Masked format
          }
          
          // Credit card numbers should be masked
          if (customer.creditCard) {
            expect(customer.creditCard).toMatch(/\*{4}-\*{4}-\*{4}-\d{4}/); // Masked format
          }
        }
      }
    });

    test('Audit trail integrity', async ({ apiClient }) => {
      const response = await apiClient.get('/audit-logs', {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });

      if (response.status() === 200) {
        const logs = await response.json();
        
        // Verify audit logs have required fields
        if (Array.isArray(logs) && logs.length > 0) {
          const log = logs[0];
          expect(log).toHaveProperty('timestamp');
          expect(log).toHaveProperty('userId');
          expect(log).toHaveProperty('action');
          expect(log).toHaveProperty('resource');
        }
      }
    });
  });

  test.describe('Error Handling & Information Disclosure', () => {
    test('Error message information disclosure', async ({ apiClient }) => {
      const response = await apiClient.get('/accounts/nonexistent-id', {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });

      if (response.status() >= 400) {
        const errorBody = await response.text();
        
        // Error messages should not expose sensitive information
        expect(errorBody).not.toContain('password');
        expect(errorBody).not.toContain('secret');
        expect(errorBody).not.toContain('token');
        expect(errorBody).not.toContain('database');
        expect(errorBody).not.toContain('sql');
      }
    });

    test('Stack trace exposure prevention', async ({ apiClient }) => {
      // Try to trigger an internal server error
      const response = await apiClient.post('/accounts', {
        invalidField: 'trigger-error'
      }, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      if (response.status() >= 500) {
        const errorBody = await response.text();
        
        // Should not expose stack traces or internal paths
        expect(errorBody).not.toContain('at ');
        expect(errorBody).not.toContain('Error:');
        expect(errorBody).not.toContain('Stack:');
        expect(errorBody).not.toContain('/usr/local/');
        expect(errorBody).not.toContain('/opt/');
      }
    });
  });

  test.describe('Compliance & Regulatory', () => {
    test('PCI DSS compliance check', async ({ apiClient }) => {
      // Test that payment data is properly handled
      const paymentData = {
        amount: 100.00,
        currency: 'USD',
        cardNumber: '4111111111111111',
        expiryDate: '12/25',
        cvv: '123'
      };

      const response = await apiClient.post('/payments', paymentData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      // Payment should be processed securely
      if (response.status() === 201) {
        const payment = await response.json();
        
        // Card details should not be returned in response
        expect(payment).not.toHaveProperty('cardNumber');
        expect(payment).not.toHaveProperty('cvv');
        
        // Should return masked card number
        if (payment.maskedCardNumber) {
          expect(payment.maskedCardNumber).toMatch(/\*{4}-\*{4}-\*{4}-\d{4}/);
        }
      }
    });

    test('SOX compliance validation', async ({ apiClient }) => {
      // Test financial data integrity
      const transactionData = {
        type: 'DEPOSIT',
        amount: 1000.00,
        currency: 'USD',
        accountId: process.env.IRON_TEST_ACCOUNT_ID || 'test-account',
        description: 'SOX compliance test'
      };

      const response = await apiClient.post('/transactions', transactionData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      if (response.status() === 201) {
        const transaction = await response.json();
        
        // Verify transaction has audit fields
        expect(transaction).toHaveProperty('id');
        expect(transaction).toHaveProperty('timestamp');
        expect(transaction).toHaveProperty('createdBy');
        expect(transaction.amount).toBe(transactionData.amount);
      }
    });
  });
});
