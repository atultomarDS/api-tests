import { test, expect } from '../../src/fixtures/api-fixtures';
import { expectOk, expectJson, expectFailure } from '../../src/utils/api-assertions';

// Skip if not Iron environment
test.skip(process.env.TEST_ENV !== 'iron', 'Iron MCB tests only');

test.describe('Iron MCB - Transaction Management', () => {
  test.describe.serial('Transaction Operations', () => {
    let transactionId: string | undefined;
    let accountId: string | undefined;

    test.beforeAll(async ({ apiClient }) => {
      // Create test account for transactions
      const accountData = {
        type: 'CHECKING',
        currency: 'USD',
        initialBalance: 10000.00,
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

      if (response.status() === 201) {
        const account = await response.json();
        accountId = account.id;
      }
    });

    test('Create transaction', async ({ apiClient }) => {
      expect(accountId).toBeTruthy();

      const transactionData = {
        type: 'DEPOSIT',
        amount: 100.00,
        currency: 'USD',
        accountId: accountId,
        description: 'Test deposit transaction',
        reference: 'TXN-001',
        category: 'PERSONAL'
      };

      const response = await apiClient.post('/transactions', transactionData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`,
          'Idempotency-Key': `test-deposit-${Date.now()}`
        },
      });

      await expectOk(response, [200, 201]);
      const created = await expectJson(response);
      expect(created.id).toBeTruthy();
      expect(created.amount).toBe(transactionData.amount);
      expect(created.type).toBe(transactionData.type);
      transactionId = created.id;
    });

    test('Get transaction details', async ({ apiClient }) => {
      expect(transactionId).toBeTruthy();
      
      const response = await apiClient.get(`/transactions/${transactionId}`, {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });

      await expectOk(response, 200);
      const transaction = await expectJson(response);
      expect(transaction.id).toBe(transactionId);
    });

    test('Update transaction', async ({ apiClient }) => {
      expect(transactionId).toBeTruthy();
      
      const updateData = {
        description: 'Updated test deposit transaction',
        category: 'BUSINESS'
      };

      const response = await apiClient.put(`/transactions/${transactionId}`, updateData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      await expectOk(response, [200, 204]);
    });

    test('Partial update transaction', async ({ apiClient }) => {
      expect(transactionId).toBeTruthy();
      
      const updateData = {
        status: 'COMPLETED'
      };

      const response = await apiClient.patch(`/transactions/${transactionId}`, updateData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      await expectOk(response, [200, 204]);
    });

    test('List transactions', async ({ apiClient }) => {
      const response = await apiClient.get('/transactions', {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` },
        params: { accountId: accountId }
      });

      await expectOk(response, 200);
      const transactions = await expectJson(response);
      expect(Array.isArray(transactions)).toBeTruthy();
    });

    test.afterAll(async ({ apiClient }) => {
      // Cleanup test account
      if (accountId) {
        await apiClient.delete(`/accounts/${accountId}`, {
          headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
        });
      }
    });
  });

  test.describe('Transaction Idempotency', () => {
    test('Transaction idempotency with same key', async ({ apiClient }) => {
      const idempotencyKey = `idem-test-${Date.now()}`;
      const transactionData = {
        type: 'TRANSFER',
        amount: 50.00,
        currency: 'USD',
        fromAccountId: process.env.IRON_TEST_ACCOUNT_ID || 'test-account-1',
        toAccountId: process.env.IRON_TEST_ACCOUNT_ID || 'test-account-2',
        description: 'Idempotency test transfer',
        reference: 'IDEM-001'
      };

      const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.API_TOKEN}`,
        'Idempotency-Key': idempotencyKey
      };

      const first = await apiClient.post('/transactions', transactionData, { headers });
      await expectOk(first, [200, 201]);
      const firstBody = await expectJson(first);
      const id1 = firstBody.id;

      const second = await apiClient.post('/transactions', transactionData, { headers });
      await expectOk(second, [200, 201]);
      const secondBody = await expectJson(second);
      const id2 = secondBody.id;

      expect(id2).toBe(id1);
    });
  });

  test.describe('Transaction Security Tests', () => {
    test('Unauthorized transaction creation', async ({ apiClient }) => {
      const transactionData = {
        type: 'DEPOSIT',
        amount: 100.00,
        currency: 'USD',
        accountId: 'test-account',
        description: 'Unauthorized test'
      };

      const response = await apiClient.post('/transactions', transactionData);
      await expectFailure(response, { status: [401, 403] });
    });

    test('Invalid transaction amount', async ({ apiClient }) => {
      const transactionData = {
        type: 'DEPOSIT',
        amount: -100.00, // Negative amount
        currency: 'USD',
        accountId: process.env.IRON_TEST_ACCOUNT_ID || 'test-account',
        description: 'Invalid amount test'
      };

      const response = await apiClient.post('/transactions', transactionData, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.API_TOKEN}`
        },
      });

      await expectFailure(response, { status: [400, 422] });
    });

    test('SQL injection in transaction ID', async ({ apiClient }) => {
      const maliciousId = "1'; DROP TABLE transactions; --";
      const response = await apiClient.get(`/transactions/${maliciousId}`, {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });
      
      await expectFailure(response, { status: [400, 404] });
    });
  });

  test.describe('Transaction Performance Tests', () => {
    test('Transaction response time', async ({ apiClient }) => {
      const startTime = Date.now();
      const response = await apiClient.get('/transactions', {
        headers: { 'Authorization': `Bearer ${process.env.API_TOKEN}` }
      });
      const endTime = Date.now();

      await expectOk(response, 200);
      expect(endTime - startTime).toBeLessThan(1000); // < 1 second
    });

    test('Concurrent transaction processing', async ({ apiClient }) => {
      const requests = [];
      for (let i = 0; i < 3; i++) {
        requests.push(apiClient.get('/transactions', {
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
