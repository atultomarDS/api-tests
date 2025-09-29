import { HttpMethod } from '../api/api-client';
import { TestSuite, TestCase } from './api-tester-agent';

export interface ApiSpec {
  name: string;
  baseUrl: string;
  endpoints: EndpointSpec[];
  authentication?: AuthSpec;
  rateLimiting?: RateLimitSpec;
}

export interface EndpointSpec {
  path: string;
  methods: HttpMethod[];
  description?: string;
  parameters?: ParameterSpec[];
  requestBody?: RequestBodySpec;
  responses?: ResponseSpec[];
  security?: SecuritySpec;
  performance?: PerformanceSpec;
}

export interface ParameterSpec {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  required: boolean;
  description?: string;
  example?: any;
  validation?: ValidationSpec;
}

export interface RequestBodySpec {
  contentType: 'application/json' | 'application/x-www-form-urlencoded' | 'multipart/form-data';
  schema: any;
  required: boolean;
  description?: string;
}

export interface ResponseSpec {
  statusCode: number;
  description?: string;
  schema?: any;
  headers?: Record<string, string>;
}

export interface SecuritySpec {
  requiresAuth: boolean;
  roles?: string[];
  rateLimit?: number;
  inputValidation: boolean;
  outputEncoding: boolean;
}

export interface PerformanceSpec {
  maxResponseTime: number;
  expectedThroughput: number;
  memoryLimit?: number;
}

export interface AuthSpec {
  type: 'bearer' | 'api-key' | 'basic' | 'oauth2';
  header?: string;
  parameter?: string;
  description?: string;
}

export interface RateLimitSpec {
  requestsPerMinute: number;
  burstLimit: number;
  windowSize: number;
}

export interface ValidationSpec {
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  min?: number;
  max?: number;
  enum?: any[];
}

export class TestGenerator {
  private apiSpec: ApiSpec;

  constructor(apiSpec: ApiSpec) {
    this.apiSpec = apiSpec;
  }

  /**
   * Generate comprehensive test suite from API specification
   */
  generateTestSuite(): TestSuite[] {
    const testSuites: TestSuite[] = [];

    for (const endpoint of this.apiSpec.endpoints) {
      const testSuite = this.generateEndpointTestSuite(endpoint);
      testSuites.push(testSuite);
    }

    // Add cross-endpoint tests
    if (this.apiSpec.endpoints.length > 1) {
      testSuites.push(this.generateIntegrationTestSuite());
    }

    // Add security test suite
    testSuites.push(this.generateSecurityTestSuite());

    // Add performance test suite
    testSuites.push(this.generatePerformanceTestSuite());

    return testSuites;
  }

  /**
   * Generate test suite for a specific endpoint
   */
  private generateEndpointTestSuite(endpoint: EndpointSpec): TestSuite {
    const tests: TestCase[] = [];

    for (const method of endpoint.methods) {
      // Basic functionality tests
      tests.push(...this.generateBasicTests(endpoint, method));

      // Parameter validation tests
      if (endpoint.parameters) {
        tests.push(...this.generateParameterTests(endpoint, method));
      }

      // Request body tests
      if (endpoint.requestBody) {
        tests.push(...this.generateRequestBodyTests(endpoint, method));
      }

      // Response validation tests
      if (endpoint.responses) {
        tests.push(...this.generateResponseTests(endpoint, method));
      }

      // Security tests
      if (endpoint.security) {
        tests.push(...this.generateSecurityTests(endpoint, method));
      }

      // Performance tests
      if (endpoint.performance) {
        tests.push(...this.generatePerformanceTests(endpoint, method));
      }
    }

    return {
      name: `Endpoint Tests - ${endpoint.path}`,
      description: endpoint.description || `Comprehensive tests for ${endpoint.path}`,
      tests
    };
  }

  /**
   * Generate basic functionality tests
   */
  private generateBasicTests(endpoint: EndpointSpec, method: HttpMethod): TestCase[] {
    const tests: TestCase[] = [];

    // Happy path test
    tests.push({
      name: `${method} ${endpoint.path} - Happy Path`,
      description: `Test basic ${method} functionality with valid data`,
      method,
      path: endpoint.path,
      expectedStatus: this.getExpectedStatus(method),
      expectedResponseTime: endpoint.performance?.maxResponseTime || 2000
    });

    // Method not allowed test
    if (!endpoint.methods.includes(method)) {
      tests.push({
        name: `${method} ${endpoint.path} - Method Not Allowed`,
        description: `Test that ${method} is not allowed on ${endpoint.path}`,
        method,
        path: endpoint.path,
        expectedStatus: 405
      });
    }

    return tests;
  }

  /**
   * Generate parameter validation tests
   */
  private generateParameterTests(endpoint: EndpointSpec, method: HttpMethod): TestCase[] {
    const tests: TestCase[] = [];

    if (!endpoint.parameters) return tests;

    for (const param of endpoint.parameters) {
      // Required parameter test
      if (param.required) {
        tests.push({
          name: `${method} ${endpoint.path} - Missing Required Parameter: ${param.name}`,
          description: `Test error handling when required parameter ${param.name} is missing`,
          method,
          path: endpoint.path,
          expectedStatus: 400
        });
      }

      // Invalid parameter type test
      tests.push({
        name: `${method} ${endpoint.path} - Invalid Parameter Type: ${param.name}`,
        description: `Test error handling for invalid ${param.name} parameter type`,
        method,
        path: endpoint.path,
        options: {
          params: { [param.name]: this.getInvalidValue(param.type) }
        },
        expectedStatus: 400
      });

      // Parameter validation tests
      if (param.validation) {
        tests.push(...this.generateParameterValidationTests(endpoint, method, param));
      }
    }

    return tests;
  }

  /**
   * Generate parameter validation tests
   */
  private generateParameterValidationTests(endpoint: EndpointSpec, method: HttpMethod, param: ParameterSpec): TestCase[] {
    const tests: TestCase[] = [];

    if (!param.validation) return tests;

    // String length validation
    if (param.type === 'string' && param.validation.minLength) {
      tests.push({
        name: `${method} ${endpoint.path} - Parameter Too Short: ${param.name}`,
        description: `Test validation when ${param.name} is shorter than minimum length`,
        method,
        path: endpoint.path,
        options: {
          params: { [param.name]: 'a'.repeat(param.validation.minLength - 1) }
        },
        expectedStatus: 400
      });
    }

    if (param.type === 'string' && param.validation.maxLength) {
      tests.push({
        name: `${method} ${endpoint.path} - Parameter Too Long: ${param.name}`,
        description: `Test validation when ${param.name} is longer than maximum length`,
        method,
        path: endpoint.path,
        options: {
          params: { [param.name]: 'a'.repeat(param.validation.maxLength + 1) }
        },
        expectedStatus: 400
      });
    }

    // Number range validation
    if (param.type === 'number' && param.validation.min !== undefined) {
      tests.push({
        name: `${method} ${endpoint.path} - Parameter Below Minimum: ${param.name}`,
        description: `Test validation when ${param.name} is below minimum value`,
        method,
        path: endpoint.path,
        options: {
          params: { [param.name]: param.validation.min - 1 }
        },
        expectedStatus: 400
      });
    }

    if (param.type === 'number' && param.validation.max !== undefined) {
      tests.push({
        name: `${method} ${endpoint.path} - Parameter Above Maximum: ${param.name}`,
        description: `Test validation when ${param.name} is above maximum value`,
        method,
        path: endpoint.path,
        options: {
          params: { [param.name]: param.validation.max + 1 }
        },
        expectedStatus: 400
      });
    }

    // Enum validation
    if (param.validation.enum) {
      tests.push({
        name: `${method} ${endpoint.path} - Invalid Enum Value: ${param.name}`,
        description: `Test validation when ${param.name} has invalid enum value`,
        method,
        path: endpoint.path,
        options: {
          params: { [param.name]: 'invalid_enum_value' }
        },
        expectedStatus: 400
      });
    }

    return tests;
  }

  /**
   * Generate request body tests
   */
  private generateRequestBodyTests(endpoint: EndpointSpec, method: HttpMethod): TestCase[] {
    const tests: TestCase[] = [];

    if (!endpoint.requestBody) return tests;

    // Valid request body test
    tests.push({
      name: `${method} ${endpoint.path} - Valid Request Body`,
      description: `Test with valid request body`,
      method,
      path: endpoint.path,
      options: {
        data: this.generateValidRequestBody(endpoint.requestBody),
        headers: { 'Content-Type': endpoint.requestBody.contentType }
      },
      expectedStatus: this.getExpectedStatus(method),
      expectedSchema: endpoint.requestBody.schema
    });

    // Invalid JSON test
    tests.push({
      name: `${method} ${endpoint.path} - Invalid JSON`,
      description: `Test error handling for invalid JSON in request body`,
      method,
      path: endpoint.path,
      options: {
        data: '{"invalid": json}',
        headers: { 'Content-Type': 'application/json' }
      },
      expectedStatus: 400
    });

    // Missing required fields test
    if (endpoint.requestBody.required) {
      tests.push({
        name: `${method} ${endpoint.path} - Missing Required Fields`,
        description: `Test error handling when required fields are missing`,
        method,
        path: endpoint.path,
        options: {
          data: {},
          headers: { 'Content-Type': endpoint.requestBody.contentType }
        },
        expectedStatus: 400
      });
    }

    return tests;
  }

  /**
   * Generate response validation tests
   */
  private generateResponseTests(endpoint: EndpointSpec, method: HttpMethod): TestCase[] {
    const tests: TestCase[] = [];

    if (!endpoint.responses) return tests;

    for (const response of endpoint.responses) {
      tests.push({
        name: `${method} ${endpoint.path} - Response ${response.statusCode}`,
        description: response.description || `Test response with status ${response.statusCode}`,
        method,
        path: endpoint.path,
        expectedStatus: response.statusCode,
        expectedSchema: response.schema
      });
    }

    return tests;
  }

  /**
   * Generate security tests
   */
  private generateSecurityTests(endpoint: EndpointSpec, method: HttpMethod): TestCase[] {
    const tests: TestCase[] = [];

    if (!endpoint.security) return tests;

    // SQL injection test
    tests.push({
      name: `${method} ${endpoint.path} - SQL Injection Test`,
      description: `Test SQL injection protection`,
      method,
      path: `${endpoint.path}/1'; DROP TABLE users; --`,
      expectedStatus: [400, 404, 403],
      securityChecks: true
    });

    // XSS test
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      tests.push({
        name: `${method} ${endpoint.path} - XSS Test`,
        description: `Test XSS protection in request body`,
        method,
        path: endpoint.path,
        options: {
          data: {
            name: '<script>alert("xss")</script>',
            email: 'test@example.com'
          },
          headers: { 'Content-Type': 'application/json' }
        },
        expectedStatus: [400, 422],
        securityChecks: true
      });
    }

    // Authentication bypass test
    if (endpoint.security.requiresAuth) {
      tests.push({
        name: `${method} ${endpoint.path} - Authentication Bypass Test`,
        description: `Test authentication requirement`,
        method,
        path: endpoint.path,
        expectedStatus: [401, 403],
        securityChecks: true
      });
    }

    return tests;
  }

  /**
   * Generate performance tests
   */
  private generatePerformanceTests(endpoint: EndpointSpec, method: HttpMethod): TestCase[] {
    const tests: TestCase[] = [];

    if (!endpoint.performance) return tests;

    // Response time test
    tests.push({
      name: `${method} ${endpoint.path} - Response Time Test`,
      description: `Test response time is within acceptable limits`,
      method,
      path: endpoint.path,
      expectedResponseTime: endpoint.performance.maxResponseTime,
      performanceChecks: true
    });

    // Load test
    tests.push({
      name: `${method} ${endpoint.path} - Load Test`,
      description: `Test endpoint under load`,
      method,
      path: endpoint.path,
      expectedResponseTime: endpoint.performance.maxResponseTime * 2,
      performanceChecks: true
    });

    return tests;
  }

  /**
   * Generate integration test suite
   */
  private generateIntegrationTestSuite(): TestSuite {
    const tests: TestCase[] = [];

    // Test endpoint dependencies
    for (let i = 0; i < this.apiSpec.endpoints.length - 1; i++) {
      const currentEndpoint = this.apiSpec.endpoints[i];
      const nextEndpoint = this.apiSpec.endpoints[i + 1];

      tests.push({
        name: `Integration - ${currentEndpoint.path} → ${nextEndpoint.path}`,
        description: `Test integration between ${currentEndpoint.path} and ${nextEndpoint.path}`,
        method: 'GET',
        path: currentEndpoint.path,
        expectedStatus: 200
      });
    }

    return {
      name: 'Integration Tests',
      description: 'Cross-endpoint integration tests',
      tests
    };
  }

  /**
   * Generate security test suite
   */
  private generateSecurityTestSuite(): TestSuite {
    const tests: TestCase[] = [];

    // Rate limiting test
    if (this.apiSpec.rateLimiting) {
      tests.push({
        name: 'Security - Rate Limiting Test',
        description: 'Test rate limiting functionality',
        method: 'GET',
        path: this.apiSpec.endpoints[0]?.path || '/',
        expectedStatus: [200, 429],
        securityChecks: true
      });
    }

    // Authentication test
    if (this.apiSpec.authentication) {
      tests.push({
        name: 'Security - Authentication Test',
        description: 'Test authentication mechanism',
        method: 'GET',
        path: this.apiSpec.endpoints[0]?.path || '/',
        expectedStatus: [200, 401, 403],
        securityChecks: true
      });
    }

    return {
      name: 'Security Tests',
      description: 'Comprehensive security tests',
      tests
    };
  }

  /**
   * Generate performance test suite
   */
  private generatePerformanceTestSuite(): TestSuite {
    const tests: TestCase[] = [];

    // Memory usage test
    tests.push({
      name: 'Performance - Memory Usage Test',
      description: 'Test memory usage under load',
      method: 'GET',
      path: this.apiSpec.endpoints[0]?.path || '/',
      performanceChecks: true
    });

    // Concurrent requests test
    tests.push({
      name: 'Performance - Concurrent Requests Test',
      description: 'Test handling of concurrent requests',
      method: 'GET',
      path: this.apiSpec.endpoints[0]?.path || '/',
      performanceChecks: true
    });

    return {
      name: 'Performance Tests',
      description: 'Comprehensive performance tests',
      tests
    };
  }

  /**
   * Get expected status code for HTTP method
   */
  private getExpectedStatus(method: HttpMethod): number {
    switch (method) {
      case 'GET':
        return 200;
      case 'POST':
        return 201;
      case 'PUT':
      case 'PATCH':
        return 200;
      case 'DELETE':
        return 204;
      default:
        return 200;
    }
  }

  /**
   * Get invalid value for parameter type
   */
  private getInvalidValue(type: string): any {
    switch (type) {
      case 'string':
        return 123;
      case 'number':
        return 'invalid';
      case 'boolean':
        return 'maybe';
      case 'array':
        return 'not-an-array';
      case 'object':
        return 'not-an-object';
      default:
        return null;
    }
  }

  /**
   * Generate valid request body based on schema
   */
  private generateValidRequestBody(requestBody: RequestBodySpec): any {
    // Simple implementation - in practice, you'd use a more sophisticated schema generator
    if (requestBody.contentType === 'application/json') {
      return {
        name: 'Test User',
        email: 'test@example.com',
        age: 25
      };
    }
    return {};
  }
}

export default TestGenerator;
