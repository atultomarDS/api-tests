import { ApiClient, HttpMethod, RequestOptions } from '../api/api-client';
import { APIResponse } from '@playwright/test';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

export interface TestResult {
  testName: string;
  status: 'PASS' | 'FAIL' | 'SKIP';
  duration: number;
  error?: string;
  details?: any;
}

export interface TestSuite {
  name: string;
  description: string;
  tests: TestCase[];
}

export interface TestCase {
  name: string;
  description: string;
  method: HttpMethod;
  path: string;
  options?: RequestOptions;
  expectedStatus?: number | number[];
  expectedSchema?: any;
  expectedResponseTime?: number;
  securityChecks?: boolean;
  performanceChecks?: boolean;
}

export interface ApiAnalysis {
  endpoints: EndpointInfo[];
  securityIssues: SecurityIssue[];
  performanceIssues: PerformanceIssue[];
  recommendations: string[];
}

export interface EndpointInfo {
  path: string;
  methods: HttpMethod[];
  responseTime: number;
  statusCodes: number[];
  schema?: any;
}

export interface SecurityIssue {
  type: 'SQL_INJECTION' | 'XSS' | 'AUTH_BYPASS' | 'RATE_LIMIT' | 'DATA_EXPOSURE';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  endpoint: string;
  recommendation: string;
}

export interface PerformanceIssue {
  type: 'SLOW_RESPONSE' | 'MEMORY_LEAK' | 'HIGH_CPU' | 'TIMEOUT';
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  description: string;
  endpoint: string;
  recommendation: string;
}

export class ApiTesterAgent {
  private apiClient: ApiClient;
  private testResults: TestResult[] = [];
  private analysis: ApiAnalysis = {
    endpoints: [],
    securityIssues: [],
    performanceIssues: [],
    recommendations: []
  };

  constructor(apiClient: ApiClient) {
    this.apiClient = apiClient;
  }

  /**
   * Generate comprehensive test suite for an API endpoint
   */
  generateTestSuite(endpoint: string, methods: HttpMethod[] = ['GET']): TestSuite {
    const tests: TestCase[] = [];

    for (const method of methods) {
      // Basic functionality test
      tests.push({
        name: `${method} ${endpoint} - Basic functionality`,
        description: `Test basic ${method} functionality for ${endpoint}`,
        method,
        path: endpoint,
        expectedStatus: method === 'POST' ? [200, 201] : 200,
        expectedResponseTime: 2000
      });

      // Security tests
      if (method === 'GET') {
        tests.push({
          name: `${method} ${endpoint} - SQL Injection test`,
          description: `Test SQL injection protection for ${endpoint}`,
          method,
          path: `${endpoint}/1'; DROP TABLE users; --`,
          expectedStatus: [400, 404, 403],
          securityChecks: true
        });
      }

      if (method === 'POST' || method === 'PUT') {
        tests.push({
          name: `${method} ${endpoint} - XSS protection test`,
          description: `Test XSS protection for ${endpoint}`,
          method,
          path: endpoint,
          options: {
            data: {
              name: '<script>alert("xss")</script>',
              job: 'hacker'
            },
            headers: { 'Content-Type': 'application/json' }
          },
          expectedStatus: [400, 422],
          securityChecks: true
        });
      }

      // Performance tests
      tests.push({
        name: `${method} ${endpoint} - Performance test`,
        description: `Test performance for ${endpoint}`,
        method,
        path: endpoint,
        expectedResponseTime: 2000,
        performanceChecks: true
      });
    }

    return {
      name: `API Test Suite - ${endpoint}`,
      description: `Comprehensive test suite for ${endpoint} endpoint`,
      tests
    };
  }

  /**
   * Execute a test case and return results
   */
  async executeTest(testCase: TestCase): Promise<TestResult> {
    const startTime = Date.now();
    
    try {
      console.log(`🧪 Running test: ${testCase.name}`);
      
      const response = await this.apiClient.requestMethod(
        testCase.method,
        testCase.path,
        testCase.options || {}
      );
      
      const duration = Date.now() - startTime;
      const result: TestResult = {
        testName: testCase.name,
        status: 'PASS',
        duration,
        details: {
          statusCode: response.status(),
          responseTime: duration,
          headers: response.headers()
        }
      };

      // Status code validation
      if (testCase.expectedStatus) {
        const expectedStatuses = Array.isArray(testCase.expectedStatus) 
          ? testCase.expectedStatus 
          : [testCase.expectedStatus];
        
        if (!expectedStatuses.includes(response.status())) {
          result.status = 'FAIL';
          result.error = `Expected status ${expectedStatuses.join(' or ')}, got ${response.status()}`;
        }
      }

      // Response time validation
      if (testCase.expectedResponseTime && duration > testCase.expectedResponseTime) {
        result.status = 'FAIL';
        result.error = `Response time ${duration}ms exceeds expected ${testCase.expectedResponseTime}ms`;
      }

      // Schema validation
      if (testCase.expectedSchema && response.ok()) {
        try {
          const json = await response.json();
          const ajv = new Ajv({ allErrors: true, strict: false });
          addFormats(ajv);
          const validate = ajv.compile(testCase.expectedSchema);
          
          if (!validate(json)) {
            result.status = 'FAIL';
            result.error = `Schema validation failed: ${JSON.stringify(validate.errors)}`;
          }
        } catch (e) {
          result.status = 'FAIL';
          result.error = `Failed to parse JSON response: ${e}`;
        }
      }

      // Security checks
      if (testCase.securityChecks) {
        const securityResult = await this.performSecurityChecks(testCase, response);
        if (securityResult) {
          result.status = 'FAIL';
          result.error = securityResult;
        }
      }

      // Performance checks
      if (testCase.performanceChecks) {
        const performanceResult = await this.performPerformanceChecks(testCase, response, duration);
        if (performanceResult) {
          result.status = 'FAIL';
          result.error = performanceResult;
        }
      }

      console.log(`✅ Test ${testCase.name}: ${result.status} (${duration}ms)`);
      return result;

    } catch (error) {
      const duration = Date.now() - startTime;
      console.log(`❌ Test ${testCase.name}: FAIL (${duration}ms)`);
      
      return {
        testName: testCase.name,
        status: 'FAIL',
        duration,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute a complete test suite
   */
  async executeTestSuite(testSuite: TestSuite): Promise<TestResult[]> {
    console.log(`🚀 Starting test suite: ${testSuite.name}`);
    console.log(`📋 Description: ${testSuite.description}`);
    console.log(`🔢 Total tests: ${testSuite.tests.length}`);
    
    const results: TestResult[] = [];
    
    for (const testCase of testSuite.tests) {
      const result = await this.executeTest(testCase);
      results.push(result);
      this.testResults.push(result);
    }
    
    this.printTestSummary(results);
    return results;
  }

  /**
   * Perform security checks on an endpoint
   */
  private async performSecurityChecks(testCase: TestCase, response: APIResponse): Promise<string | null> {
    const status = response.status();
    
    // SQL Injection check
    if (testCase.path.includes("'; DROP TABLE")) {
      if (status === 200) {
        this.analysis.securityIssues.push({
          type: 'SQL_INJECTION',
          severity: 'HIGH',
          description: 'API accepts SQL injection in path parameter',
          endpoint: testCase.path,
          recommendation: 'Implement input validation and parameterized queries'
        });
        return 'Security issue: SQL injection not blocked';
      }
    }
    
    // XSS check
    if (testCase.options?.data && JSON.stringify(testCase.options.data).includes('<script>')) {
      if (status === 201 || status === 200) {
        this.analysis.securityIssues.push({
          type: 'XSS',
          severity: 'MEDIUM',
          description: 'API accepts XSS payload without sanitization',
          endpoint: testCase.path,
          recommendation: 'Implement input sanitization and output encoding'
        });
        return 'Security issue: XSS payload not sanitized';
      }
    }
    
    return null;
  }

  /**
   * Perform performance checks on an endpoint
   */
  private async performPerformanceChecks(testCase: TestCase, response: APIResponse, duration: number): Promise<string | null> {
    // Slow response check
    if (duration > 5000) {
      this.analysis.performanceIssues.push({
        type: 'SLOW_RESPONSE',
        severity: 'HIGH',
        description: `Response time ${duration}ms is too slow`,
        endpoint: testCase.path,
        recommendation: 'Optimize database queries and implement caching'
      });
      return `Performance issue: Response time ${duration}ms exceeds threshold`;
    }
    
    return null;
  }

  /**
   * Analyze API endpoints and generate recommendations
   */
  async analyzeApi(endpoints: string[]): Promise<ApiAnalysis> {
    console.log(`🔍 Analyzing API endpoints: ${endpoints.join(', ')}`);
    
    for (const endpoint of endpoints) {
      try {
        const startTime = Date.now();
        const response = await this.apiClient.get(endpoint);
        const duration = Date.now() - startTime;
        
        this.analysis.endpoints.push({
          path: endpoint,
          methods: ['GET'],
          responseTime: duration,
          statusCodes: [response.status()],
          schema: response.ok() ? await response.json().catch(() => null) : null
        });
        
        // Generate recommendations based on analysis
        if (duration > 2000) {
          this.analysis.recommendations.push(`Optimize ${endpoint} - response time is ${duration}ms`);
        }
        
        if (!response.ok()) {
          this.analysis.recommendations.push(`Fix ${endpoint} - returns status ${response.status()}`);
        }
        
      } catch (error) {
        console.log(`⚠️  Failed to analyze endpoint ${endpoint}: ${error}`);
      }
    }
    
    return this.analysis;
  }

  /**
   * Generate comprehensive test report
   */
  generateTestReport(): string {
    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter(r => r.status === 'PASS').length;
    const failedTests = this.testResults.filter(r => r.status === 'FAIL').length;
    const skippedTests = this.testResults.filter(r => r.status === 'SKIP').length;
    
    const avgDuration = this.testResults.reduce((sum, r) => sum + r.duration, 0) / totalTests;
    
    let report = `
# API Test Report

## Summary
- **Total Tests**: ${totalTests}
- **Passed**: ${passedTests} (${((passedTests/totalTests)*100).toFixed(1)}%)
- **Failed**: ${failedTests} (${((failedTests/totalTests)*100).toFixed(1)}%)
- **Skipped**: ${skippedTests} (${((skippedTests/totalTests)*100).toFixed(1)}%)
- **Average Duration**: ${avgDuration.toFixed(2)}ms

## Test Results
`;

    for (const result of this.testResults) {
      const status = result.status === 'PASS' ? '✅' : result.status === 'FAIL' ? '❌' : '⏭️';
      report += `\n${status} **${result.testName}** (${result.duration}ms)`;
      if (result.error) {
        report += `\n   Error: ${result.error}`;
      }
    }

    if (this.analysis.securityIssues.length > 0) {
      report += `\n\n## Security Issues\n`;
      for (const issue of this.analysis.securityIssues) {
        report += `\n- **${issue.severity}**: ${issue.description}\n  Endpoint: ${issue.endpoint}\n  Recommendation: ${issue.recommendation}\n`;
      }
    }

    if (this.analysis.performanceIssues.length > 0) {
      report += `\n\n## Performance Issues\n`;
      for (const issue of this.analysis.performanceIssues) {
        report += `\n- **${issue.severity}**: ${issue.description}\n  Endpoint: ${issue.endpoint}\n  Recommendation: ${issue.recommendation}\n`;
      }
    }

    if (this.analysis.recommendations.length > 0) {
      report += `\n\n## Recommendations\n`;
      for (const rec of this.analysis.recommendations) {
        report += `\n- ${rec}`;
      }
    }

    return report;
  }

  /**
   * Print test summary to console
   */
  private printTestSummary(results: TestResult[]): void {
    const passed = results.filter(r => r.status === 'PASS').length;
    const failed = results.filter(r => r.status === 'FAIL').length;
    const skipped = results.filter(r => r.status === 'SKIP').length;
    
    console.log(`\n📊 Test Summary:`);
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`⏭️  Skipped: ${skipped}`);
    console.log(`📈 Success Rate: ${((passed/results.length)*100).toFixed(1)}%\n`);
  }

  /**
   * Get all test results
   */
  getTestResults(): TestResult[] {
    return this.testResults;
  }

  /**
   * Get API analysis
   */
  getAnalysis(): ApiAnalysis {
    return this.analysis;
  }

  /**
   * Clear all test results and analysis
   */
  clearResults(): void {
    this.testResults = [];
    this.analysis = {
      endpoints: [],
      securityIssues: [],
      performanceIssues: [],
      recommendations: []
    };
  }
}

export default ApiTesterAgent;
