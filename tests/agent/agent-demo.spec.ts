import { test, expect } from '../../src/fixtures/api-fixtures';
import { 
  createTestRunner, 
  createApiTesterAgent, 
  createTestGenerator,
  ApiSpec,
  TestRunConfig 
} from '../../src/agent';

test.describe('API Tester Agent Demo', () => {
  test('Demonstrate API Tester Agent functionality', async ({ apiClient }) => {
    // Create API specification for reqres.in
    const apiSpec: ApiSpec = {
      name: 'ReqRes API',
      baseUrl: 'https://reqres.in/api',
      endpoints: [
        {
          path: '/users',
          methods: ['GET'],
          description: 'Get list of users',
          parameters: [
            {
              name: 'page',
              type: 'number',
              required: false,
              description: 'Page number',
              example: 1,
              validation: { min: 1, max: 10 }
            }
          ],
          responses: [
            { statusCode: 200, description: 'Success' },
            { statusCode: 400, description: 'Bad request' }
          ],
          security: {
            requiresAuth: false,
            inputValidation: true,
            outputEncoding: true
          },
          performance: {
            maxResponseTime: 2000,
            expectedThroughput: 100
          }
        },
        {
          path: '/users/{id}',
          methods: ['GET'],
          description: 'Get user by ID',
          parameters: [
            {
              name: 'id',
              type: 'number',
              required: true,
              description: 'User ID',
              example: 1,
              validation: { min: 1 }
            }
          ],
          responses: [
            { statusCode: 200, description: 'Success' },
            { statusCode: 404, description: 'User not found' }
          ],
          security: {
            requiresAuth: false,
            inputValidation: true,
            outputEncoding: true
          },
          performance: {
            maxResponseTime: 1500,
            expectedThroughput: 100
          }
        },
        {
          path: '/users',
          methods: ['POST'],
          description: 'Create new user',
          requestBody: {
            contentType: 'application/json',
            schema: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                job: { type: 'string' }
              },
              required: ['name', 'job']
            },
            required: true,
            description: 'User data'
          },
          responses: [
            { statusCode: 201, description: 'User created' },
            { statusCode: 400, description: 'Bad request' }
          ],
          security: {
            requiresAuth: false,
            inputValidation: true,
            outputEncoding: true
          },
          performance: {
            maxResponseTime: 2000,
            expectedThroughput: 50
          }
        }
      ],
      authentication: {
        type: 'api-key',
        header: 'x-api-key',
        description: 'API key authentication'
      },
      rateLimiting: {
        requestsPerMinute: 60,
        burstLimit: 10,
        windowSize: 60
      }
    };

    // Create test runner with custom configuration
    const testConfig: Partial<TestRunConfig> = {
      environment: 'demo',
      baseUrl: 'https://reqres.in/api',
      parallel: false, // Run sequentially for demo
      generateReport: true,
      reportFormat: 'markdown'
    };

    const testRunner = createTestRunner(apiClient, testConfig);

    // Run tests from API specification
    const result = await testRunner.runTestsFromSpec(apiSpec);

    // Verify test results
    expect(result.totalTests).toBeGreaterThan(0);
    expect(result.successRate).toBeGreaterThanOrEqual(0);
    expect(result.duration).toBeGreaterThan(0);
    expect(result.report).toBeDefined();

    console.log('Test Run Result:', {
      totalTests: result.totalTests,
      passedTests: result.passedTests,
      failedTests: result.failedTests,
      successRate: result.successRate,
      duration: result.duration
    });

    // Verify that we have test results
    expect(result.testResults.length).toBeGreaterThan(0);
    
    // Check that at least some tests passed
    expect(result.passedTests).toBeGreaterThan(0);
  });

  test('Demonstrate individual agent components', async ({ apiClient }) => {
    // Create API tester agent
    const agent = createApiTesterAgent(apiClient);

    // Generate a simple test suite
    const testSuite = agent.generateTestSuite('/users', ['GET', 'POST']);

    // Execute the test suite
    const results = await agent.executeTestSuite(testSuite);

    // Verify results
    expect(results.length).toBeGreaterThan(0);
    expect(results.every(r => r.testName)).toBeTruthy();
    expect(results.every(r => r.status)).toBeTruthy();
    expect(results.every(r => r.duration >= 0)).toBeTruthy();

    // Get test report
    const report = agent.generateTestReport();
    expect(report).toContain('API Test Report');
    expect(report).toContain('Summary');

    console.log('Generated Test Report:', report.substring(0, 500) + '...');
  });

  test('Demonstrate test generator', async ({ apiClient }) => {
    // Create API specification
    const apiSpec: ApiSpec = {
      name: 'Simple API',
      baseUrl: 'https://reqres.in/api',
      endpoints: [
        {
          path: '/users',
          methods: ['GET'],
          description: 'Get users',
          parameters: [
            {
              name: 'page',
              type: 'number',
              required: false,
              validation: { min: 1, max: 10 }
            }
          ],
          security: {
            requiresAuth: false,
            inputValidation: true,
            outputEncoding: true
          },
          performance: {
            maxResponseTime: 2000,
            expectedThroughput: 100
          }
        }
      ]
    };

    // Create test generator
    const generator = createTestGenerator(apiSpec);

    // Generate test suites
    const testSuites = generator.generateTestSuite();

    // Verify test suites were generated
    expect(testSuites.length).toBeGreaterThan(0);
    expect(testSuites[0].name).toContain('Endpoint Tests');
    expect(testSuites[0].tests.length).toBeGreaterThan(0);

    // Check that security and performance tests were generated
    const hasSecurityTests = testSuites.some(suite => 
      suite.tests.some(test => test.securityChecks)
    );
    const hasPerformanceTests = testSuites.some(suite => 
      suite.tests.some(test => test.performanceChecks)
    );

    expect(hasSecurityTests).toBeTruthy();
    expect(hasPerformanceTests).toBeTruthy();

    console.log(`Generated ${testSuites.length} test suites with ${testSuites.reduce((sum, suite) => sum + suite.tests.length, 0)} total tests`);
  });

  test('Demonstrate API analysis', async ({ apiClient }) => {
    const agent = createApiTesterAgent(apiClient);

    // Analyze API endpoints
    const analysis = await agent.analyzeApi(['/users', '/users/2']);

    // Verify analysis results
    expect(analysis.endpoints.length).toBeGreaterThan(0);
    expect(analysis.endpoints[0].path).toBeDefined();
    expect(analysis.endpoints[0].responseTime).toBeGreaterThan(0);
    expect(analysis.endpoints[0].statusCodes.length).toBeGreaterThan(0);

    console.log('API Analysis:', {
      endpoints: analysis.endpoints.length,
      securityIssues: analysis.securityIssues.length,
      performanceIssues: analysis.performanceIssues.length,
      recommendations: analysis.recommendations.length
    });
  });
});
