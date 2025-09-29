import { ApiTesterAgent, TestSuite, TestResult } from './api-tester-agent';
import { TestGenerator, ApiSpec } from './test-generator';
import { ApiClient } from '../api/api-client';

export interface TestRunConfig {
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

export interface TestRunResult {
  config: TestRunConfig;
  startTime: Date;
  endTime: Date;
  duration: number;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  skippedTests: number;
  successRate: number;
  testResults: TestResult[];
  report?: string;
  errors: string[];
}

export class TestRunner {
  private apiClient: ApiClient;
  private agent: ApiTesterAgent;
  private generator: TestGenerator;
  private config: TestRunConfig;

  constructor(apiClient: ApiClient, config: TestRunConfig) {
    this.apiClient = apiClient;
    this.agent = new ApiTesterAgent(apiClient);
    this.config = config;
    this.generator = new TestGenerator({
      name: 'API Test Suite',
      baseUrl: config.baseUrl,
      endpoints: []
    });
  }

  /**
   * Run tests from API specification
   */
  async runTestsFromSpec(apiSpec: ApiSpec): Promise<TestRunResult> {
    console.log(`🚀 Starting test run for ${apiSpec.name}`);
    console.log(`🌐 Environment: ${this.config.environment}`);
    console.log(`🔗 Base URL: ${this.config.baseUrl}`);
    
    const startTime = new Date();
    const errors: string[] = [];
    
    try {
      // Update generator with new spec
      this.generator = new TestGenerator(apiSpec);
      
      // Generate test suites
      const testSuites = this.generator.generateTestSuite();
      console.log(`📋 Generated ${testSuites.length} test suites`);
      
      // Execute test suites
      const allResults: TestResult[] = [];
      
      if (this.config.parallel) {
        allResults.push(...await this.runTestSuitesParallel(testSuites));
      } else {
        allResults.push(...await this.runTestSuitesSequential(testSuites));
      }
      
      const endTime = new Date();
      const duration = endTime.getTime() - startTime.getTime();
      
      // Generate report
      let report: string | undefined;
      if (this.config.generateReport) {
        report = await this.generateReport(allResults, duration);
      }
      
      const result: TestRunResult = {
        config: this.config,
        startTime,
        endTime,
        duration,
        totalTests: allResults.length,
        passedTests: allResults.filter(r => r.status === 'PASS').length,
        failedTests: allResults.filter(r => r.status === 'FAIL').length,
        skippedTests: allResults.filter(r => r.status === 'SKIP').length,
        successRate: (allResults.filter(r => r.status === 'PASS').length / allResults.length) * 100,
        testResults: allResults,
        report,
        errors
      };
      
      this.printTestRunSummary(result);
      return result;
      
    } catch (error) {
      const endTime = new Date();
      const duration = endTime.getTime() - startTime.getTime();
      
      errors.push(error instanceof Error ? error.message : String(error));
      
      return {
        config: this.config,
        startTime,
        endTime,
        duration,
        totalTests: 0,
        passedTests: 0,
        failedTests: 0,
        skippedTests: 0,
        successRate: 0,
        testResults: [],
        errors
      };
    }
  }

  /**
   * Run tests from existing test suites
   */
  async runTestsFromSuites(testSuites: TestSuite[]): Promise<TestRunResult> {
    console.log(`🚀 Starting test run with ${testSuites.length} test suites`);
    
    const startTime = new Date();
    const errors: string[] = [];
    
    try {
      const allResults: TestResult[] = [];
      
      if (this.config.parallel) {
        allResults.push(...await this.runTestSuitesParallel(testSuites));
      } else {
        allResults.push(...await this.runTestSuitesSequential(testSuites));
      }
      
      const endTime = new Date();
      const duration = endTime.getTime() - startTime.getTime();
      
      // Generate report
      let report: string | undefined;
      if (this.config.generateReport) {
        report = await this.generateReport(allResults, duration);
      }
      
      const result: TestRunResult = {
        config: this.config,
        startTime,
        endTime,
        duration,
        totalTests: allResults.length,
        passedTests: allResults.filter(r => r.status === 'PASS').length,
        failedTests: allResults.filter(r => r.status === 'FAIL').length,
        skippedTests: allResults.filter(r => r.status === 'SKIP').length,
        successRate: (allResults.filter(r => r.status === 'PASS').length / allResults.length) * 100,
        testResults: allResults,
        report,
        errors
      };
      
      this.printTestRunSummary(result);
      return result;
      
    } catch (error) {
      const endTime = new Date();
      const duration = endTime.getTime() - startTime.getTime();
      
      errors.push(error instanceof Error ? error.message : String(error));
      
      return {
        config: this.config,
        startTime,
        endTime,
        duration,
        totalTests: 0,
        passedTests: 0,
        failedTests: 0,
        skippedTests: 0,
        successRate: 0,
        testResults: [],
        errors
      };
    }
  }

  /**
   * Run test suites sequentially
   */
  private async runTestSuitesSequential(testSuites: TestSuite[]): Promise<TestResult[]> {
    const allResults: TestResult[] = [];
    
    for (const testSuite of testSuites) {
      console.log(`\n📋 Running test suite: ${testSuite.name}`);
      const results = await this.agent.executeTestSuite(testSuite);
      allResults.push(...results);
    }
    
    return allResults;
  }

  /**
   * Run test suites in parallel
   */
  private async runTestSuitesParallel(testSuites: TestSuite[]): Promise<TestResult[]> {
    const allResults: TestResult[] = [];
    
    // Create chunks of test suites to run in parallel
    const chunks = this.chunkArray(testSuites, this.config.maxConcurrency);
    
    for (const chunk of chunks) {
      const promises = chunk.map(async (testSuite) => {
        console.log(`\n📋 Running test suite: ${testSuite.name}`);
        return this.agent.executeTestSuite(testSuite);
      });
      
      const chunkResults = await Promise.all(promises);
      allResults.push(...chunkResults.flat());
    }
    
    return allResults;
  }

  /**
   * Generate test report
   */
  private async generateReport(testResults: TestResult[], duration: number): Promise<string> {
    const report = this.agent.generateTestReport();
    
    // Add additional metrics
    const enhancedReport = report + `
## Test Run Metrics
- **Total Duration**: ${duration}ms (${(duration/1000).toFixed(2)}s)
- **Tests per Second**: ${(testResults.length / (duration/1000)).toFixed(2)}
- **Average Test Duration**: ${(testResults.reduce((sum, r) => sum + r.duration, 0) / testResults.length).toFixed(2)}ms
- **Environment**: ${this.config.environment}
- **Base URL**: ${this.config.baseUrl}
- **Generated at**: ${new Date().toISOString()}
`;

    return enhancedReport;
  }

  /**
   * Print test run summary
   */
  private printTestRunSummary(result: TestRunResult): void {
    console.log(`\n🎯 Test Run Summary:`);
    console.log(`⏱️  Duration: ${(result.duration/1000).toFixed(2)}s`);
    console.log(`📊 Total Tests: ${result.totalTests}`);
    console.log(`✅ Passed: ${result.passedTests} (${result.successRate.toFixed(1)}%)`);
    console.log(`❌ Failed: ${result.failedTests}`);
    console.log(`⏭️  Skipped: ${result.skippedTests}`);
    
    if (result.errors.length > 0) {
      console.log(`\n⚠️  Errors:`);
      result.errors.forEach(error => console.log(`   - ${error}`));
    }
    
    if (result.report) {
      console.log(`\n📄 Report generated: ${this.config.outputDir}/test-report.${this.config.reportFormat}`);
    }
  }

  /**
   * Chunk array into smaller arrays
   */
  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  /**
   * Get test results
   */
  getTestResults(): TestResult[] {
    return this.agent.getTestResults();
  }

  /**
   * Get API analysis
   */
  getAnalysis() {
    return this.agent.getAnalysis();
  }

  /**
   * Clear all results
   */
  clearResults(): void {
    this.agent.clearResults();
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<TestRunConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Get current configuration
   */
  getConfig(): TestRunConfig {
    return this.config;
  }
}

export default TestRunner;
