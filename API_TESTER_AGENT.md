# API Tester Agent

A comprehensive software testing agent designed specifically for API testing. This agent provides intelligent test generation, execution, and analysis capabilities for REST APIs.

## Features

### 🧪 Intelligent Test Generation
- **Automatic Test Suite Creation**: Generate comprehensive test suites from API specifications
- **Parameter Validation**: Automatically test parameter validation rules
- **Security Testing**: Built-in security tests for SQL injection, XSS, and authentication bypass
- **Performance Testing**: Response time and load testing capabilities
- **Schema Validation**: JSON schema validation for request/response bodies

### 🚀 Test Execution
- **Parallel Execution**: Run tests in parallel for faster execution
- **Retry Logic**: Automatic retry for failed tests with exponential backoff
- **Environment Support**: Support for multiple testing environments
- **Real-time Reporting**: Live test execution feedback

### 📊 Analysis & Reporting
- **Comprehensive Reports**: Detailed test reports in multiple formats (JSON, HTML, Markdown)
- **Security Analysis**: Identify security vulnerabilities and provide recommendations
- **Performance Analysis**: Detect performance issues and bottlenecks
- **API Health Monitoring**: Continuous API health assessment

### 🔧 Integration
- **Playwright Integration**: Seamless integration with existing Playwright test framework
- **Standalone Mode**: Can be used independently without test frameworks
- **CI/CD Ready**: Designed for continuous integration pipelines
- **Extensible**: Easy to extend with custom test types and validations

## Quick Start

### 1. Basic Usage with Playwright

```typescript
import { test, expect } from '../src/fixtures/api-fixtures';
import { createTestRunner, ApiSpec } from '../src/agent';

test('API Testing with Agent', async ({ apiClient }) => {
  // Define your API specification
  const apiSpec: ApiSpec = {
    name: 'My API',
    baseUrl: 'https://api.example.com',
    endpoints: [
      {
        path: '/users',
        methods: ['GET', 'POST'],
        description: 'User management endpoints',
        security: {
          requiresAuth: true,
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

  // Create and run tests
  const testRunner = createTestRunner(apiClient, {
    environment: 'test',
    generateReport: true
  });

  const result = await testRunner.runTestsFromSpec(apiSpec);
  
  expect(result.successRate).toBeGreaterThan(80);
});
```

### 2. Standalone Usage

```javascript
const { createTestRunner } = require('./src/agent');
const { ApiClient } = require('./src/api/api-client');

// Create API client
const apiClient = new ApiClient(mockRequest, 'https://api.example.com');

// Create test runner
const testRunner = createTestRunner(apiClient, {
  environment: 'production',
  parallel: true,
  generateReport: true,
  reportFormat: 'html'
});

// Run tests
const result = await testRunner.runTestsFromSpec(apiSpec);
console.log(`Tests completed: ${result.passedTests}/${result.totalTests} passed`);
```

### 3. Command Line Usage

```bash
# Run the agent demo
node scripts/run-agent.js

# Run specific test suites
npm run test:agent
```

## API Specification Format

The agent uses a structured API specification to generate comprehensive tests:

```typescript
interface ApiSpec {
  name: string;
  baseUrl: string;
  endpoints: EndpointSpec[];
  authentication?: AuthSpec;
  rateLimiting?: RateLimitSpec;
}

interface EndpointSpec {
  path: string;
  methods: HttpMethod[];
  description?: string;
  parameters?: ParameterSpec[];
  requestBody?: RequestBodySpec;
  responses?: ResponseSpec[];
  security?: SecuritySpec;
  performance?: PerformanceSpec;
}
```

### Example API Specification

```typescript
const apiSpec: ApiSpec = {
  name: 'User Management API',
  baseUrl: 'https://api.example.com',
  endpoints: [
    {
      path: '/users',
      methods: ['GET', 'POST'],
      description: 'User management endpoints',
      parameters: [
        {
          name: 'page',
          type: 'number',
          required: false,
          validation: { min: 1, max: 100 }
        }
      ],
      requestBody: {
        contentType: 'application/json',
        schema: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            email: { type: 'string', format: 'email' }
          },
          required: ['name', 'email']
        },
        required: true
      },
      responses: [
        { statusCode: 200, description: 'Success' },
        { statusCode: 201, description: 'Created' },
        { statusCode: 400, description: 'Bad Request' }
      ],
      security: {
        requiresAuth: true,
        inputValidation: true,
        outputEncoding: true
      },
      performance: {
        maxResponseTime: 2000,
        expectedThroughput: 100
      }
    }
  ],
  authentication: {
    type: 'bearer',
    header: 'Authorization'
  },
  rateLimiting: {
    requestsPerMinute: 60,
    burstLimit: 10,
    windowSize: 60
  }
};
```

## Test Types Generated

### 1. Basic Functionality Tests
- Happy path testing
- Method validation
- Status code verification
- Response time validation

### 2. Parameter Validation Tests
- Required parameter validation
- Type validation
- Range validation (min/max)
- Pattern validation
- Enum validation

### 3. Security Tests
- SQL injection protection
- XSS prevention
- Authentication bypass attempts
- Rate limiting validation
- Input sanitization

### 4. Performance Tests
- Response time monitoring
- Load testing
- Memory usage monitoring
- Concurrent request handling

### 5. Integration Tests
- Cross-endpoint dependencies
- Data flow validation
- End-to-end scenarios

## Configuration Options

```typescript
interface TestRunConfig {
  environment: string;
  baseUrl: string;
  timeout: number;
  retries: number;
  parallel: boolean;
  maxConcurrency: number;
  generateReport: boolean;
  reportFormat: 'json' | 'html' | 'markdown';
  outputDir: string;
}
```

### Default Configuration

```typescript
const defaultConfig: TestRunConfig = {
  environment: 'test',
  baseUrl: 'https://reqres.in/api',
  timeout: 30000,
  retries: 2,
  parallel: true,
  maxConcurrency: 5,
  generateReport: true,
  reportFormat: 'markdown',
  outputDir: './reports'
};
```

## Test Reports

The agent generates comprehensive test reports including:

### Summary Statistics
- Total tests executed
- Pass/fail/skip counts
- Success rate percentage
- Average execution time
- Tests per second

### Detailed Results
- Individual test results
- Error messages and stack traces
- Performance metrics
- Security findings

### Analysis & Recommendations
- Security vulnerabilities
- Performance bottlenecks
- API health assessment
- Improvement suggestions

### Example Report

```markdown
# API Test Report

## Summary
- **Total Tests**: 25
- **Passed**: 23 (92.0%)
- **Failed**: 2 (8.0%)
- **Skipped**: 0 (0.0%)
- **Average Duration**: 245.67ms

## Test Results
✅ **GET /users - Happy Path** (156ms)
✅ **GET /users - Parameter Validation** (189ms)
❌ **POST /users - XSS Test** (234ms)
   Error: Security issue: XSS payload not sanitized

## Security Issues
- **HIGH**: API accepts SQL injection in path parameter
  Endpoint: /users/1'; DROP TABLE users; --
  Recommendation: Implement input validation and parameterized queries

## Performance Issues
- **MEDIUM**: Response time 3245ms is too slow
  Endpoint: /users
  Recommendation: Optimize database queries and implement caching

## Recommendations
- Optimize /users - response time is 3245ms
- Implement input sanitization for XSS protection
- Add rate limiting for /users endpoint
```

## Advanced Usage

### Custom Test Generation

```typescript
import { createTestGenerator, ApiSpec } from '../src/agent';

const generator = createTestGenerator(apiSpec);
const testSuites = generator.generateTestSuite();

// Customize test suites
testSuites.forEach(suite => {
  suite.tests.push({
    name: 'Custom Test',
    description: 'My custom test',
    method: 'GET',
    path: '/custom-endpoint',
    expectedStatus: 200
  });
});
```

### API Analysis

```typescript
import { createApiTesterAgent } from '../src/agent';

const agent = createApiTesterAgent(apiClient);
const analysis = await agent.analyzeApi(['/users', '/posts', '/comments']);

console.log('Endpoints analyzed:', analysis.endpoints.length);
console.log('Security issues found:', analysis.securityIssues.length);
console.log('Performance issues found:', analysis.performanceIssues.length);
```

### Integration with CI/CD

```yaml
# GitHub Actions example
name: API Tests
on: [push, pull_request]

jobs:
  api-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: npm install
      - run: npm run test:agent
      - uses: actions/upload-artifact@v2
        with:
          name: test-reports
          path: reports/
```

## Best Practices

### 1. API Specification
- Provide comprehensive endpoint documentation
- Include all possible response codes
- Define clear parameter validation rules
- Specify security requirements

### 2. Test Configuration
- Use appropriate timeouts for your API
- Enable parallel execution for faster feedback
- Configure retry logic for flaky tests
- Set up proper environment variables

### 3. Security Testing
- Always include security tests for public endpoints
- Test authentication and authorization
- Validate input sanitization
- Check for common vulnerabilities

### 4. Performance Testing
- Set realistic response time expectations
- Test under various load conditions
- Monitor memory usage
- Validate rate limiting

### 5. Reporting
- Generate reports in multiple formats
- Include detailed error information
- Provide actionable recommendations
- Archive reports for historical analysis

## Troubleshooting

### Common Issues

1. **Tests failing due to timeouts**
   - Increase timeout configuration
   - Check API response times
   - Verify network connectivity

2. **Security tests failing unexpectedly**
   - Review API security implementation
   - Check if security features are enabled
   - Validate test expectations

3. **Performance tests inconsistent**
   - Run tests multiple times
   - Check for external factors
   - Adjust performance thresholds

### Debug Mode

Enable debug logging by setting environment variables:

```bash
DEBUG=api-tester-agent npm run test:agent
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the ISC License - see the LICENSE file for details.

## Support

For questions, issues, or contributions:
- Create an issue in the repository
- Check existing documentation
- Review test examples
- Contact the maintainers
