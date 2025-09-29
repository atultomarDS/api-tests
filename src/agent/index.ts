// Security Testing Agent - Main Entry Point
export { default as SecurityTestingAgent } from './security-testing-agent';
export { default as SecurityVulnerabilityScanner } from './security-vulnerability-scanner';
export { default as SecurityComplianceChecker } from './security-compliance-checker';
export { default as SecurityReportGenerator } from './security-report-generator';
export { default as SecurityTestSuiteGenerator } from './security-test-suite-generator';

// Re-export types and interfaces
export type {
  SecurityTestResult,
  SecurityVulnerability,
  SecurityVulnerabilityType,
  SecurityTestSuite,
  SecurityTestCase,
  SecurityAnalysis,
  ComplianceStatus,
  SecurityRecommendation,
  AttackSurface,
  EndpointSecurity
} from './security-testing-agent';

export type {
  VulnerabilityScanResult,
  ScanConfiguration
} from './security-vulnerability-scanner';

export type {
  ComplianceFramework,
  ComplianceRequirement,
  ComplianceTestCase,
  ComplianceTestResult,
  ComplianceReport,
  ComplianceRequirementResult,
  ComplianceSummary
} from './security-compliance-checker';

export type {
  SecurityReport,
  SecurityReportSummary,
  RiskAssessment,
  RiskFactor,
  BusinessImpact,
  LikelihoodAssessment,
  RiskMatrix,
  MitigationStrategy,
  TechnicalDetails,
  ScanConfiguration as ReportScanConfiguration,
  TestingMethodology,
  ReportAppendix
} from './security-report-generator';

export type {
  AttackVector,
  SecurityTestSuiteConfig,
  GeneratedTestSuite
} from './security-test-suite-generator';

// Main Security Agent Class that combines all functionality
import { ApiClient } from '../api/api-client';
import SecurityTestingAgent from './security-testing-agent';
import SecurityVulnerabilityScanner from './security-vulnerability-scanner';
import SecurityComplianceChecker from './security-compliance-checker';
import SecurityReportGenerator from './security-report-generator';
import SecurityTestSuiteGenerator from './security-test-suite-generator';

export class SecurityAgent {
  private securityTester: SecurityTestingAgent;
  private vulnerabilityScanner: SecurityVulnerabilityScanner;
  private complianceChecker: SecurityComplianceChecker;
  private reportGenerator: SecurityReportGenerator;
  private testSuiteGenerator: SecurityTestSuiteGenerator;

  constructor(apiClient: ApiClient) {
    this.securityTester = new SecurityTestingAgent(apiClient);
    this.vulnerabilityScanner = new SecurityVulnerabilityScanner(apiClient);
    this.complianceChecker = new SecurityComplianceChecker(apiClient);
    this.reportGenerator = new SecurityReportGenerator();
    this.testSuiteGenerator = new SecurityTestSuiteGenerator(apiClient);
  }

  /**
   * Perform comprehensive security assessment
   */
  async performSecurityAssessment(
    endpoints: string[],
    methods: string[] = ['GET', 'POST', 'PUT', 'DELETE'],
    options: {
      includeCompliance?: boolean;
      includeVulnerabilityScan?: boolean;
      includeRiskAssessment?: boolean;
      testDepth?: 'BASIC' | 'STANDARD' | 'COMPREHENSIVE' | 'PENETRATION';
    } = {}
  ) {
    const {
      includeCompliance = true,
      includeVulnerabilityScan = true,
      includeRiskAssessment = true,
      testDepth = 'STANDARD'
    } = options;

    console.log('🛡️ Starting comprehensive security assessment...');
    console.log(`📋 Endpoints: ${endpoints.length}`);
    console.log(`🔧 Methods: ${methods.join(', ')}`);
    console.log(`📊 Test Depth: ${testDepth}`);

    const results = {
      vulnerabilities: [],
      complianceReports: [],
      scanResults: [],
      riskAssessment: null,
      securityReport: null
    };

    // Generate comprehensive test suite
    const testSuiteConfig = {
      endpoints,
      methods: methods as any[],
      attackVectors: [
        'SQL_INJECTION',
        'XSS',
        'INJECTION',
        'XML_EXTERNAL_ENTITY',
        'AUTH_BYPASS',
        'RATE_LIMIT_BYPASS',
        'DATA_EXPOSURE',
        'INFORMATION_DISCLOSURE'
      ],
      includeAuthTests: true,
      includeInjectionTests: true,
      includeRateLimitTests: true,
      includeDataExposureTests: true,
      includeComplianceTests: true,
      testDepth
    };

    const generatedTestSuite = this.testSuiteGenerator.generateSecurityTestSuite(testSuiteConfig);
    console.log(`✅ Generated test suite with ${generatedTestSuite.totalTests} tests`);

    // Execute security tests
    for (const suite of generatedTestSuite.testSuites) {
      const testResults = await this.securityTester.executeSecurityTestSuite(suite);
      results.vulnerabilities.push(...testResults.map(r => r.vulnerability).filter(Boolean));
    }

    // Perform vulnerability scan
    if (includeVulnerabilityScan) {
      const scanConfig = {
        endpoints,
        methods: methods as any[],
        includeAuthTests: true,
        includeInjectionTests: true,
        includeRateLimitTests: true,
        includeDataExposureTests: true,
        timeout: 30000,
        maxConcurrentRequests: 5
      };

      const scanResults = await this.vulnerabilityScanner.scanVulnerabilities(scanConfig);
      results.scanResults = scanResults;
      results.vulnerabilities.push(...scanResults.flatMap(r => r.vulnerabilities));
    }

    // Perform compliance checks
    if (includeCompliance) {
      const owaspReport = await this.complianceChecker.checkOwaspCompliance(endpoints);
      results.complianceReports.push(owaspReport);

      // Add PCI DSS and SOX checks if applicable
      if (endpoints.some(e => e.includes('payment') || e.includes('card'))) {
        const pciReport = await this.complianceChecker.checkPciDssCompliance(endpoints);
        results.complianceReports.push(pciReport);
      }

      if (endpoints.some(e => e.includes('financial') || e.includes('transaction'))) {
        const soxReport = await this.complianceChecker.checkSoxCompliance(endpoints);
        results.complianceReports.push(soxReport);
      }
    }

    // Generate comprehensive security report
    if (includeRiskAssessment) {
      const analysis = this.securityTester.getSecurityAnalysis();
      results.securityReport = this.reportGenerator.generateComprehensiveReport(
        results.vulnerabilities,
        results.complianceReports,
        results.scanResults,
        analysis
      );
    }

    console.log('✅ Security assessment completed');
    return results;
  }

  /**
   * Quick security scan
   */
  async quickSecurityScan(endpoints: string[]) {
    console.log('🔍 Performing quick security scan...');
    
    const scanConfig = {
      endpoints,
      methods: ['GET', 'POST'] as any[],
      includeAuthTests: true,
      includeInjectionTests: true,
      includeRateLimitTests: false,
      includeDataExposureTests: true,
      timeout: 15000,
      maxConcurrentRequests: 3
    };

    const scanResults = await this.vulnerabilityScanner.scanVulnerabilities(scanConfig);
    const vulnerabilities = scanResults.flatMap(r => r.vulnerabilities);
    
    const report = this.reportGenerator.generateVulnerabilityReport(vulnerabilities, scanResults);
    
    console.log(`✅ Quick scan completed - Found ${vulnerabilities.length} vulnerabilities`);
    return { vulnerabilities, scanResults, report };
  }

  /**
   * Compliance-only assessment
   */
  async complianceAssessment(endpoints: string[]) {
    console.log('📋 Performing compliance assessment...');
    
    const complianceReports = [];
    
    // OWASP Top 10
    const owaspReport = await this.complianceChecker.checkOwaspCompliance(endpoints);
    complianceReports.push(owaspReport);
    
    // PCI DSS (if payment-related endpoints)
    if (endpoints.some(e => e.includes('payment') || e.includes('card'))) {
      const pciReport = await this.complianceChecker.checkPciDssCompliance(endpoints);
      complianceReports.push(pciReport);
    }
    
    // SOX (if financial endpoints)
    if (endpoints.some(e => e.includes('financial') || e.includes('transaction'))) {
      const soxReport = await this.complianceChecker.checkSoxCompliance(endpoints);
      complianceReports.push(soxReport);
    }
    
    const report = this.reportGenerator.generateComplianceReport(complianceReports);
    
    console.log(`✅ Compliance assessment completed - ${complianceReports.length} frameworks assessed`);
    return { complianceReports, report };
  }

  /**
   * Generate security test suite
   */
  generateTestSuite(config: any) {
    return this.testSuiteGenerator.generateSecurityTestSuite(config);
  }

  /**
   * Export security report
   */
  exportReport(report: any, format: 'HTML' | 'PDF' | 'JSON' | 'MARKDOWN') {
    return this.reportGenerator.exportReport(report, format);
  }

  /**
   * Get security testing agent
   */
  getSecurityTester() {
    return this.securityTester;
  }

  /**
   * Get vulnerability scanner
   */
  getVulnerabilityScanner() {
    return this.vulnerabilityScanner;
  }

  /**
   * Get compliance checker
   */
  getComplianceChecker() {
    return this.complianceChecker;
  }

  /**
   * Get report generator
   */
  getReportGenerator() {
    return this.reportGenerator;
  }

  /**
   * Get test suite generator
   */
  getTestSuiteGenerator() {
    return this.testSuiteGenerator;
  }
}

export default SecurityAgent;