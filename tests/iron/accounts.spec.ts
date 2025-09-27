import { test, expect } from '../../src/fixtures/api-fixtures';
import { expectOk, expectJson, expectFailure } from '../../src/utils/api-assertions';

// Skip if not Iron environment
test.skip(process.env.TEST_ENV !== 'iron', 'Iron MCB tests only');

test.describe('Iron MCB - Account Management', () => {
  test.describe.serial('Account CRUD Operations', () => {
    let accountId: string | undefined;

    test('Create customer account', async ({ apiClient }) => {
      const accountData = {
        type: 'CHECKING',
        currency: 'USD',
        initialBalance: 1000.00,
        customerId: process.env.IRON_TEST_CUSTOMER_ID || 'test-customer-uuid',
        branchCode: '001',
        productCode: 'CHK001'
      };

      const response = await apiClient.post('/accounts', accountData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      await expectOk(response, [200, 201]);
      const created = await expectJson(response);
      expect(created.id).toBeTruthy();
      expect(created.type).toBe(accountData.type);
      expect(created.currency).toBe(accountData.currency);
      accountId = created.id;
    });

    test('Get account details', async ({ apiClient }) => {
      expect(accountId).toBeTruthy();
      
      const response = await apiClient.get(`/accounts/${accountId}`, {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });

      await expectOk(response, 200);
      const account = await expectJson(response);
      expect(account.id).toBe(accountId);
    });

    test('Update account information', async ({ apiClient }) => {
      expect(accountId).toBeTruthy();
      
      const updateData = {
        status: 'ACTIVE',
        overdraftLimit: 500.00
      };

      const response = await apiClient.put(`/accounts/${accountId}`, updateData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      await expectOk(response, [200, 204]);
    });

    test('List customer accounts', async ({ apiClient }) => {
      const response = await apiClient.get('/accounts', {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` },
        params: { customerId: process.env.IRON_TEST_CUSTOMER_ID }
      });

      await expectOk(response, 200);
      const accounts = await expectJson(response);
      expect(Array.isArray(accounts)).toBeTruthy();
    });

    test('Close customer account', async ({ apiClient }) => {
      expect(accountId).toBeTruthy();
      
      const response = await apiClient.delete(`/accounts/${accountId}`, {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });

      await expectOk(response, [200, 204]);
      
      // Verify account is closed
      const verifyResponse = await apiClient.get(`/accounts/${accountId}`, {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });
      
      await expectFailure(verifyResponse, { status: [404, 410] });
    });
  });

  test.describe('Account Security Tests', () => {
    test('Unauthorized access to accounts', async ({ apiClient }) => {
      const response = await apiClient.get('/accounts');
      await expectFailure(response, { status: [401, 403] });
    });

    test('Access account without valid token', async ({ apiClient }) => {
      const response = await apiClient.get('/accounts/test-id', {
        headers: { 'Authorization': 'Bearer invalid-token' }
      });
      await expectFailure(response, { status: [401, 403] });
    });

    test('SQL injection in account ID', async ({ apiClient }) => {
      const maliciousId = "1'; DROP TABLE accounts; --";
      const response = await apiClient.get(`/accounts/${maliciousId}`, {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });
      
      // Should return 400/404, not execute SQL
      await expectFailure(response, { status: [400, 404] });
    });
  });

  test.describe('Account Performance Tests', () => {
    test('Response time for account operations', async ({ apiClient }) => {
      const startTime = Date.now();
      const response = await apiClient.get('/accounts', {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });
      const endTime = Date.now();

      await expectOk(response, 200);
      expect(endTime - startTime).toBeLessThan(500); // < 500ms
    });

    test('Concurrent account requests', async ({ apiClient }) => {
      const requests = [];
      for (let i = 0; i < 5; i++) {
        requests.push(apiClient.get('/accounts', {
          headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
        }));
      }

      const responses = await Promise.all(requests);
      responses.forEach(response => {
        expect(response.status()).toBe(200);
      });
    });
  });
});
