import { test, expect } from '../../src/fixtures/api-fixtures';
import { expectOk } from '../../src/utils/api-assertions';

test.describe('Performance Tests', () => {
  test('Response time validation', async ({ apiClient }) => {
    const startTime = Date.now();
    const response = await apiClient.get('/users');
    const endTime = Date.now();
    
    const responseTime = endTime - startTime;
    
    await expectOk(response, 200);
    
    // Assert response time is under 2 seconds
    expect(responseTime).toBeLessThan(2000);
    console.log(`Response time: ${responseTime}ms`);
  });

  test('Concurrent request handling', async ({ apiClient }) => {
    const concurrentRequests = 5;
    const requests = [];
    
    const startTime = Date.now();
    
    // Send concurrent requests
    for (let i = 0; i < concurrentRequests; i++) {
      requests.push(apiClient.get('/users'));
    }
    
    const responses = await Promise.all(requests);
    const endTime = Date.now();
    
    const totalTime = endTime - startTime;
    
    // All requests should succeed
    responses.forEach(response => {
      expect(response.status()).toBe(200);
    });
    
    // Should handle concurrent requests efficiently
    expect(totalTime).toBeLessThan(5000); // All requests within 5 seconds
    console.log(`Handled ${concurrentRequests} concurrent requests in ${totalTime}ms`);
  });

  test('Large payload handling', async ({ apiClient }) => {
    // Create a large payload (1MB of data)
    const largeName = 'x'.repeat(1000000); // 1MB string
    const largePayload = {
      name: largeName,
      job: 'performance tester'
    };
    
    const startTime = Date.now();
    const response = await apiClient.post('/users', largePayload, {
      headers: { 'Content-Type': 'application/json' },
    });
    const endTime = Date.now();
    
    const responseTime = endTime - startTime;
    
    // Should either accept or reject gracefully
    if (response.status() === 201) {
      console.log(`Large payload accepted in ${responseTime}ms`);
      await expectOk(response, 201);
    } else {
      // If rejected, should be a proper error response
      await expectFailure(response, { status: [400, 413, 422] });
      console.log(`Large payload rejected with status ${response.status()}`);
    }
    
    // Response time should be reasonable even for large payloads
    expect(responseTime).toBeLessThan(10000); // Under 10 seconds
  });

  test('Memory usage monitoring', async ({ apiClient }) => {
    const initialMemory = process.memoryUsage();
    
    // Perform multiple operations
    for (let i = 0; i < 10; i++) {
      const response = await apiClient.get('/users');
      expect(response.status()).toBe(200);
    }
    
    const finalMemory = process.memoryUsage();
    const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
    
    // Memory increase should be reasonable (less than 50MB)
    expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    console.log(`Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
  });
});
