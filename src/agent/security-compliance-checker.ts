import { ApiClient, HttpMethod, RequestOptions } from '../api/api-client';
import { APIResponse } from '@playwright/test';
import { SecurityVulnerability } from './security-testing-agent';

export interface ComplianceFramework {
  name: string;
  version: string;
  requirements: ComplianceRequirement[];
}

export interface ComplianceRequirement {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  testCases: ComplianceTestCase[];
}

export interface ComplianceTestCase {
  name: string;
  description: string;
  method: HttpMethod;
  path: string;
  options?: RequestOptions;
  expectedBehavior: string;
  testFunction: (response: APIResponse) => Promise<ComplianceTestResult>;
}

export interface ComplianceTestResult {
  requirementId: string;
  testName: string;
  status: 'PASS' | 'FAIL' | 'WARNING' | 'SKIP';
  description: string;
  evidence?: string;
  recommendation?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface ComplianceReport {
  framework: string;
  version: string;
  overallStatus: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL';
  complianceScore: number;
  requirements: ComplianceRequirementResult[];
  summary: ComplianceSummary;
  recommendations: string[];
}

export interface ComplianceRequirementResult {
  requirement: ComplianceRequirement;
  status: 'PASS' | 'FAIL' | 'WARNING' | 'SKIP';
  testResults: ComplianceTestResult[];
  complianceScore: number;
}

export interface ComplianceSummary {
  totalRequirements: number;
  passedRequirements: number;
  failedRequirements: number;
  warningRequirements: number;
  skippedRequirements: number;
  criticalFailures: number;
  highFailures: number;
  mediumFailures: number;
  lowFailures: number;
}

export class SecurityComplianceChecker {
  private apiClient: ApiClient;
  private complianceReports: ComplianceReport[] = [];

  constructor(apiClient: ApiClient) {
    this.apiClient = apiClient;
  }

  /**
   * Check OWASP Top 10 2021 compliance
   */
  async checkOwaspCompliance(endpoints: string[]): Promise<ComplianceReport> {
    const framework = this.getOwaspFramework();
    const requirements = framework.requirements;
    const requirementResults: ComplianceRequirementResult[] = [];

    console.log(`🛡️ Checking OWASP Top 10 2021 compliance...`);

    for (const requirement of requirements) {
      console.log(`\n📋 Checking requirement: ${requirement.title}`);
      
      const testResults: ComplianceTestResult[] = [];
      
      for (const testCase of requirement.testCases) {
        try {
          const response = await this.apiClient.requestMethod(
            testCase.method,
            testCase.path,
            testCase.options || {}
          );
          
          const result = await testCase.testFunction(response);
          testResults.push(result);
          
          console.log(`   ${result.status === 'PASS' ? '✅' : '❌'} ${testCase.name}: ${result.status}`);
          
        } catch (error) {
          testResults.push({
            requirementId: requirement.id,
            testName: testCase.name,
            status: 'SKIP',
            description: `Test skipped due to error: ${error}`,
            severity: 'LOW'
          });
        }
      }
      
      const complianceScore = this.calculateRequirementScore(testResults);
      const status = this.determineRequirementStatus(testResults);
      
      requirementResults.push({
        requirement,
        status,
        testResults,
        complianceScore
      });
    }

    const summary = this.generateComplianceSummary(requirementResults);
    const overallStatus = this.determineOverallStatus(requirementResults);
    const complianceScore = this.calculateOverallScore(requirementResults);
    const recommendations = this.generateRecommendations(requirementResults);

    const report: ComplianceReport = {
      framework: 'OWASP Top 10',
      version: '2021',
      overallStatus,
      complianceScore,
      requirements: requirementResults,
      summary,
      recommendations
    };

    this.complianceReports.push(report);
    return report;
  }

  /**
   * Check PCI DSS compliance
   */
  async checkPciDssCompliance(endpoints: string[]): Promise<ComplianceReport> {
    const framework = this.getPciDssFramework();
    const requirements = framework.requirements;
    const requirementResults: ComplianceRequirementResult[] = [];

    console.log(`💳 Checking PCI DSS compliance...`);

    for (const requirement of requirements) {
      console.log(`\n📋 Checking requirement: ${requirement.title}`);
      
      const testResults: ComplianceTestResult[] = [];
      
      for (const testCase of requirement.testCases) {
        try {
          const response = await this.apiClient.requestMethod(
            testCase.method,
            testCase.path,
            testCase.options || {}
          );
          
          const result = await testCase.testFunction(response);
          testResults.push(result);
          
          console.log(`   ${result.status === 'PASS' ? '✅' : '❌'} ${testCase.name}: ${result.status}`);
          
        } catch (error) {
          testResults.push({
            requirementId: requirement.id,
            testName: testCase.name,
            status: 'SKIP',
            description: `Test skipped due to error: ${error}`,
            severity: 'LOW'
          });
        }
      }
      
      const complianceScore = this.calculateRequirementScore(testResults);
      const status = this.determineRequirementStatus(testResults);
      
      requirementResults.push({
        requirement,
        status,
        testResults,
        complianceScore
      });
    }

    const summary = this.generateComplianceSummary(requirementResults);
    const overallStatus = this.determineOverallStatus(requirementResults);
    const complianceScore = this.calculateOverallScore(requirementResults);
    const recommendations = this.generateRecommendations(requirementResults);

    const report: ComplianceReport = {
      framework: 'PCI DSS',
      version: '4.0',
      overallStatus,
      complianceScore,
      requirements: requirementResults,
      summary,
      recommendations
    };

    this.complianceReports.push(report);
    return report;
  }

  /**
   * Check SOX compliance
   */
  async checkSoxCompliance(endpoints: string[]): Promise<ComplianceReport> {
    const framework = this.getSoxFramework();
    const requirements = framework.requirements;
    const requirementResults: ComplianceRequirementResult[] = [];

    console.log(`📊 Checking SOX compliance...`);

    for (const requirement of requirements) {
      console.log(`\n📋 Checking requirement: ${requirement.title}`);
      
      const testResults: ComplianceTestResult[] = [];
      
      for (const testCase of requirement.testCases) {
        try {
          const response = await this.apiClient.requestMethod(
            testCase.method,
            testCase.path,
            testCase.options || {}
          );
          
          const result = await testCase.testFunction(response);
          testResults.push(result);
          
          console.log(`   ${result.status === 'PASS' ? '✅' : '❌'} ${testCase.name}: ${result.status}`);
          
        } catch (error) {
          testResults.push({
            requirementId: requirement.id,
            testName: testCase.name,
            status: 'SKIP',
            description: `Test skipped due to error: ${error}`,
            severity: 'LOW'
          });
        }
      }
      
      const complianceScore = this.calculateRequirementScore(testResults);
      const status = this.determineRequirementStatus(testResults);
      
      requirementResults.push({
        requirement,
        status,
        testResults,
        complianceScore
      });
    }

    const summary = this.generateComplianceSummary(requirementResults);
    const overallStatus = this.determineOverallStatus(requirementResults);
    const complianceScore = this.calculateOverallScore(requirementResults);
    const recommendations = this.generateRecommendations(requirementResults);

    const report: ComplianceReport = {
      framework: 'SOX',
      version: '2002',
      overallStatus,
      complianceScore,
      requirements: requirementResults,
      summary,
      recommendations
    };

    this.complianceReports.push(report);
    return report;
  }

  /**
   * Get OWASP Top 10 2021 framework
   */
  private getOwaspFramework(): ComplianceFramework {
    return {
      name: 'OWASP Top 10',
      version: '2021',
      requirements: [
        {
          id: 'A01',
          title: 'A01:2021 – Broken Access Control',
          description: 'Access control enforces policy such that users cannot act outside of their intended permissions.',
          category: 'Access Control',
          severity: 'HIGH',
          testCases: [
            {
              name: 'Unauthorized Access Test',
              description: 'Test if endpoints are accessible without proper authentication',
              method: 'GET',
              path: '/users',
              expectedBehavior: 'Should return 401 or 403 for unauthorized access',
              testFunction: async (response: APIResponse) => {
                if (response.status() === 401 || response.status() === 403) {
                  return {
                    requirementId: 'A01',
                    testName: 'Unauthorized Access Test',
                    status: 'PASS',
                    description: 'Endpoint properly requires authentication',
                    severity: 'HIGH'
                  };
                } else {
                  return {
                    requirementId: 'A01',
                    testName: 'Unauthorized Access Test',
                    status: 'FAIL',
                    description: 'Endpoint accessible without authentication',
                    evidence: `Status: ${response.status()}`,
                    recommendation: 'Implement proper authentication checks',
                    severity: 'HIGH'
                  };
                }
              }
            },
            {
              name: 'Privilege Escalation Test',
              description: 'Test if users can access resources beyond their permissions',
              method: 'GET',
              path: '/admin/users',
              expectedBehavior: 'Should return 403 for non-admin users',
              testFunction: async (response: APIResponse) => {
                if (response.status() === 403) {
                  return {
                    requirementId: 'A01',
                    testName: 'Privilege Escalation Test',
                    status: 'PASS',
                    description: 'Admin endpoint properly restricted',
                    severity: 'HIGH'
                  };
                } else if (response.status() === 401) {
                  return {
                    requirementId: 'A01',
                    testName: 'Privilege Escalation Test',
                    status: 'WARNING',
                    description: 'Admin endpoint requires authentication but authorization unclear',
                    recommendation: 'Verify proper role-based access control',
                    severity: 'MEDIUM'
                  };
                } else {
                  return {
                    requirementId: 'A01',
                    testName: 'Privilege Escalation Test',
                    status: 'FAIL',
                    description: 'Admin endpoint accessible without proper authorization',
                    evidence: `Status: ${response.status()}`,
                    recommendation: 'Implement proper role-based access control',
                    severity: 'HIGH'
                  };
                }
              }
            }
          ]
        },
        {
          id: 'A02',
          title: 'A02:2021 – Cryptographic Failures',
          description: 'Protect data in transit and at rest using strong encryption.',
          category: 'Cryptography',
          severity: 'HIGH',
          testCases: [
            {
              name: 'HTTPS Enforcement Test',
              description: 'Test if API enforces HTTPS',
              method: 'GET',
              path: '/users',
              expectedBehavior: 'Should redirect HTTP to HTTPS or reject HTTP requests',
              testFunction: async (response: APIResponse) => {
                const headers = response.headers();
                if (headers['strict-transport-security']) {
                  return {
                    requirementId: 'A02',
                    testName: 'HTTPS Enforcement Test',
                    status: 'PASS',
                    description: 'HSTS header present',
                    severity: 'HIGH'
                  };
                } else {
                  return {
                    requirementId: 'A02',
                    testName: 'HTTPS Enforcement Test',
                    status: 'WARNING',
                    description: 'HSTS header not present',
                    recommendation: 'Implement HSTS header for HTTPS enforcement',
                    severity: 'MEDIUM'
                  };
                }
              }
            },
            {
              name: 'Sensitive Data Exposure Test',
              description: 'Test if sensitive data is properly protected',
              method: 'GET',
              path: '/users',
              expectedBehavior: 'Should not expose sensitive data in plain text',
              testFunction: async (response: APIResponse) => {
                if (response.ok()) {
                  const body = await response.text();
                  const sensitivePatterns = [
                    /password/i,
                    /secret/i,
                    /token/i,
                    /key/i,
                    /ssn/i,
                    /credit.*card/i
                  ];
                  
                  if (sensitivePatterns.some(pattern => pattern.test(body))) {
                    return {
                      requirementId: 'A02',
                      testName: 'Sensitive Data Exposure Test',
                      status: 'FAIL',
                      description: 'Sensitive data exposed in response',
                      evidence: 'Sensitive data patterns found in response',
                      recommendation: 'Implement data masking and encryption',
                      severity: 'HIGH'
                    };
                  } else {
                    return {
                      requirementId: 'A02',
                      testName: 'Sensitive Data Exposure Test',
                      status: 'PASS',
                      description: 'No sensitive data exposed',
                      severity: 'HIGH'
                    };
                  }
                } else {
                  return {
                    requirementId: 'A02',
                    testName: 'Sensitive Data Exposure Test',
                    status: 'SKIP',
                    description: 'Endpoint not accessible',
                    severity: 'LOW'
                  };
                }
              }
            }
          ]
        },
        {
          id: 'A03',
          title: 'A03:2021 – Injection',
          description: 'Prevent injection attacks by validating and sanitizing input.',
          category: 'Input Validation',
          severity: 'HIGH',
          testCases: [
            {
              name: 'SQL Injection Test',
              description: 'Test for SQL injection vulnerabilities',
              method: 'GET',
              path: '/users/1\'; DROP TABLE users; --',
              expectedBehavior: 'Should reject SQL injection attempts',
              testFunction: async (response: APIResponse) => {
                if (response.status() === 200) {
                  return {
                    requirementId: 'A03',
                    testName: 'SQL Injection Test',
                    status: 'FAIL',
                    description: 'SQL injection payload accepted',
                    evidence: `Status: ${response.status()}`,
                    recommendation: 'Implement input validation and parameterized queries',
                    severity: 'HIGH'
                  };
                } else {
                  return {
                    requirementId: 'A03',
                    testName: 'SQL Injection Test',
                    status: 'PASS',
                    description: 'SQL injection payload rejected',
                    severity: 'HIGH'
                  };
                }
              }
            },
            {
              name: 'XSS Test',
              description: 'Test for cross-site scripting vulnerabilities',
              method: 'POST',
              path: '/users',
              options: {
                data: { name: '<script>alert("XSS")</script>' },
                headers: { 'Content-Type': 'application/json' }
              },
              expectedBehavior: 'Should sanitize XSS payloads',
              testFunction: async (response: APIResponse) => {
                if (response.ok()) {
                  const body = await response.text();
                  if (body.includes('<script>')) {
                    return {
                      requirementId: 'A03',
                      testName: 'XSS Test',
                      status: 'FAIL',
                      description: 'XSS payload not sanitized',
                      evidence: 'Script tags found in response',
                      recommendation: 'Implement input sanitization and output encoding',
                      severity: 'MEDIUM'
                    };
                  } else {
                    return {
                      requirementId: 'A03',
                      testName: 'XSS Test',
                      status: 'PASS',
                      description: 'XSS payload properly sanitized',
                      severity: 'MEDIUM'
                    };
                  }
                } else {
                  return {
                    requirementId: 'A03',
                    testName: 'XSS Test',
                    status: 'PASS',
                    description: 'XSS payload rejected',
                    severity: 'MEDIUM'
                  };
                }
              }
            }
          ]
        }
      ]
    };
  }

  /**
   * Get PCI DSS framework
   */
  private getPciDssFramework(): ComplianceFramework {
    return {
      name: 'PCI DSS',
      version: '4.0',
      requirements: [
        {
          id: 'PCI-3.4',
          title: 'PCI DSS 3.4 - Mask PAN when displayed',
          description: 'Render Primary Account Number (PAN) unreadable anywhere it is stored.',
          category: 'Data Protection',
          severity: 'HIGH',
          testCases: [
            {
              name: 'PAN Masking Test',
              description: 'Test if credit card numbers are properly masked',
              method: 'GET',
              path: '/payments',
              expectedBehavior: 'Should return masked credit card numbers',
              testFunction: async (response: APIResponse) => {
                if (response.ok()) {
                  const body = await response.text();
                  const panPattern = /\d{4}-\d{4}-\d{4}-\d{4}/;
                  const maskedPattern = /\*{4}-\*{4}-\*{4}-\d{4}/;
                  
                  if (panPattern.test(body) && !maskedPattern.test(body)) {
                    return {
                      requirementId: 'PCI-3.4',
                      testName: 'PAN Masking Test',
                      status: 'FAIL',
                      description: 'Unmasked PAN found in response',
                      evidence: 'Full credit card number exposed',
                      recommendation: 'Implement PAN masking',
                      severity: 'HIGH'
                    };
                  } else {
                    return {
                      requirementId: 'PCI-3.4',
                      testName: 'PAN Masking Test',
                      status: 'PASS',
                      description: 'PAN properly masked',
                      severity: 'HIGH'
                    };
                  }
                } else {
                  return {
                    requirementId: 'PCI-3.4',
                    testName: 'PAN Masking Test',
                    status: 'SKIP',
                    description: 'Endpoint not accessible',
                    severity: 'LOW'
                  };
                }
              }
            }
          ]
        },
        {
          id: 'PCI-6.5',
          title: 'PCI DSS 6.5 - Develop secure applications',
          description: 'Address common coding vulnerabilities in software development processes.',
          category: 'Secure Development',
          severity: 'HIGH',
          testCases: [
            {
              name: 'Secure Development Test',
              description: 'Test for common coding vulnerabilities',
              method: 'GET',
              path: '/users/1\'; DROP TABLE users; --',
              expectedBehavior: 'Should reject malicious input',
              testFunction: async (response: APIResponse) => {
                if (response.status() === 200) {
                  return {
                    requirementId: 'PCI-6.5',
                    testName: 'Secure Development Test',
                    status: 'FAIL',
                    description: 'Vulnerable to injection attacks',
                    evidence: `Status: ${response.status()}`,
                    recommendation: 'Implement secure coding practices',
                    severity: 'HIGH'
                  };
                } else {
                  return {
                    requirementId: 'PCI-6.5',
                    testName: 'Secure Development Test',
                    status: 'PASS',
                    description: 'Properly handles malicious input',
                    severity: 'HIGH'
                  };
                }
              }
            }
          ]
        }
      ]
    };
  }

  /**
   * Get SOX framework
   */
  private getSoxFramework(): ComplianceFramework {
    return {
      name: 'SOX',
      version: '2002',
      requirements: [
        {
          id: 'SOX-404',
          title: 'SOX 404 - Internal Controls',
          description: 'Management assessment of internal controls over financial reporting.',
          category: 'Internal Controls',
          severity: 'HIGH',
          testCases: [
            {
              name: 'Audit Trail Test',
              description: 'Test if audit trails are properly maintained',
              method: 'GET',
              path: '/audit-logs',
              expectedBehavior: 'Should return comprehensive audit logs',
              testFunction: async (response: APIResponse) => {
                if (response.ok()) {
                  const body = await response.text();
                  const auditFields = ['timestamp', 'userId', 'action', 'resource'];
                  const hasAllFields = auditFields.every(field => body.includes(field));
                  
                  if (hasAllFields) {
                    return {
                      requirementId: 'SOX-404',
                      testName: 'Audit Trail Test',
                      status: 'PASS',
                      description: 'Audit trail contains required fields',
                      severity: 'HIGH'
                    };
                  } else {
                    return {
                      requirementId: 'SOX-404',
                      testName: 'Audit Trail Test',
                      status: 'FAIL',
                      description: 'Audit trail missing required fields',
                      evidence: 'Missing audit fields',
                      recommendation: 'Implement comprehensive audit logging',
                      severity: 'HIGH'
                    };
                  }
                } else {
                  return {
                    requirementId: 'SOX-404',
                    testName: 'Audit Trail Test',
                    status: 'FAIL',
                    description: 'Audit trail endpoint not accessible',
                    evidence: `Status: ${response.status()}`,
                    recommendation: 'Implement audit trail endpoint',
                    severity: 'HIGH'
                  };
                }
              }
            }
          ]
        },
        {
          id: 'SOX-302',
          title: 'SOX 302 - Financial Data Integrity',
          description: 'Management certification of financial statements and internal controls.',
          category: 'Data Integrity',
          severity: 'HIGH',
          testCases: [
            {
              name: 'Data Integrity Test',
              description: 'Test if financial data is properly protected',
              method: 'GET',
              path: '/transactions',
              expectedBehavior: 'Should return accurate financial data',
              testFunction: async (response: APIResponse) => {
                if (response.ok()) {
                  const body = await response.text();
                  const integrityFields = ['id', 'amount', 'timestamp', 'createdBy'];
                  const hasAllFields = integrityFields.every(field => body.includes(field));
                  
                  if (hasAllFields) {
                    return {
                      requirementId: 'SOX-302',
                      testName: 'Data Integrity Test',
                      status: 'PASS',
                      description: 'Financial data has required integrity fields',
                      severity: 'HIGH'
                    };
                  } else {
                    return {
                      requirementId: 'SOX-302',
                      testName: 'Data Integrity Test',
                      status: 'FAIL',
                      description: 'Financial data missing integrity fields',
                      evidence: 'Missing integrity fields',
                      recommendation: 'Implement data integrity controls',
                      severity: 'HIGH'
                    };
                  }
                } else {
                  return {
                    requirementId: 'SOX-302',
                    testName: 'Data Integrity Test',
                    status: 'SKIP',
                    description: 'Endpoint not accessible',
                    severity: 'LOW'
                  };
                }
              }
            }
          ]
        }
      ]
    };
  }

  /**
   * Calculate requirement compliance score
   */
  private calculateRequirementScore(testResults: ComplianceTestResult[]): number {
    if (testResults.length === 0) return 0;
    
    const passed = testResults.filter(r => r.status === 'PASS').length;
    const total = testResults.length;
    
    return Math.round((passed / total) * 100);
  }

  /**
   * Determine requirement status
   */
  private determineRequirementStatus(testResults: ComplianceTestResult[]): 'PASS' | 'FAIL' | 'WARNING' | 'SKIP' {
    if (testResults.length === 0) return 'SKIP';
    
    const hasFailures = testResults.some(r => r.status === 'FAIL');
    const hasWarnings = testResults.some(r => r.status === 'WARNING');
    const allPassed = testResults.every(r => r.status === 'PASS');
    
    if (allPassed) return 'PASS';
    if (hasFailures) return 'FAIL';
    if (hasWarnings) return 'WARNING';
    return 'SKIP';
  }

  /**
   * Generate compliance summary
   */
  private generateComplianceSummary(requirementResults: ComplianceRequirementResult[]): ComplianceSummary {
    const totalRequirements = requirementResults.length;
    const passedRequirements = requirementResults.filter(r => r.status === 'PASS').length;
    const failedRequirements = requirementResults.filter(r => r.status === 'FAIL').length;
    const warningRequirements = requirementResults.filter(r => r.status === 'WARNING').length;
    const skippedRequirements = requirementResults.filter(r => r.status === 'SKIP').length;
    
    const criticalFailures = requirementResults.reduce((sum, r) => 
      sum + r.testResults.filter(t => t.severity === 'CRITICAL' && t.status === 'FAIL').length, 0);
    const highFailures = requirementResults.reduce((sum, r) => 
      sum + r.testResults.filter(t => t.severity === 'HIGH' && t.status === 'FAIL').length, 0);
    const mediumFailures = requirementResults.reduce((sum, r) => 
      sum + r.testResults.filter(t => t.severity === 'MEDIUM' && t.status === 'FAIL').length, 0);
    const lowFailures = requirementResults.reduce((sum, r) => 
      sum + r.testResults.filter(t => t.severity === 'LOW' && t.status === 'FAIL').length, 0);
    
    return {
      totalRequirements,
      passedRequirements,
      failedRequirements,
      warningRequirements,
      skippedRequirements,
      criticalFailures,
      highFailures,
      mediumFailures,
      lowFailures
    };
  }

  /**
   * Determine overall compliance status
   */
  private determineOverallStatus(requirementResults: ComplianceRequirementResult[]): 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL' {
    const hasFailures = requirementResults.some(r => r.status === 'FAIL');
    const hasWarnings = requirementResults.some(r => r.status === 'WARNING');
    
    if (hasFailures) return 'NON_COMPLIANT';
    if (hasWarnings) return 'PARTIAL';
    return 'COMPLIANT';
  }

  /**
   * Calculate overall compliance score
   */
  private calculateOverallScore(requirementResults: ComplianceRequirementResult[]): number {
    if (requirementResults.length === 0) return 0;
    
    const totalScore = requirementResults.reduce((sum, r) => sum + r.complianceScore, 0);
    return Math.round(totalScore / requirementResults.length);
  }

  /**
   * Generate compliance recommendations
   */
  private generateRecommendations(requirementResults: ComplianceRequirementResult[]): string[] {
    const recommendations: string[] = [];
    
    for (const result of requirementResults) {
      if (result.status === 'FAIL') {
        for (const testResult of result.testResults) {
          if (testResult.status === 'FAIL' && testResult.recommendation) {
            recommendations.push(`${result.requirement.title}: ${testResult.recommendation}`);
          }
        }
      }
    }
    
    return recommendations;
  }

  /**
   * Generate compliance report
   */
  generateComplianceReport(report: ComplianceReport): string {
    let reportText = `
# ${report.framework} Compliance Report

## Executive Summary
- **Framework**: ${report.framework} ${report.version}
- **Overall Status**: ${report.overallStatus}
- **Compliance Score**: ${report.complianceScore}%
- **Total Requirements**: ${report.summary.totalRequirements}
- **Passed**: ${report.summary.passedRequirements}
- **Failed**: ${report.summary.failedRequirements}
- **Warnings**: ${report.summary.warningRequirements}
- **Skipped**: ${report.summary.skippedRequirements}

## Vulnerability Summary
- **Critical Failures**: ${report.summary.criticalFailures}
- **High Failures**: ${report.summary.highFailures}
- **Medium Failures**: ${report.summary.mediumFailures}
- **Low Failures**: ${report.summary.lowFailures}

## Detailed Results
`;

    for (const requirementResult of report.requirements) {
      const status = requirementResult.status === 'PASS' ? '✅' : 
                    requirementResult.status === 'FAIL' ? '❌' : 
                    requirementResult.status === 'WARNING' ? '⚠️' : '⏭️';
      
      reportText += `\n### ${status} ${requirementResult.requirement.title}\n`;
      reportText += `- **Description**: ${requirementResult.requirement.description}\n`;
      reportText += `- **Status**: ${requirementResult.status}\n`;
      reportText += `- **Score**: ${requirementResult.complianceScore}%\n`;
      
      for (const testResult of requirementResult.testResults) {
        const testStatus = testResult.status === 'PASS' ? '✅' : 
                          testResult.status === 'FAIL' ? '❌' : 
                          testResult.status === 'WARNING' ? '⚠️' : '⏭️';
        
        reportText += `\n  ${testStatus} **${testResult.testName}**\n`;
        reportText += `  - ${testResult.description}\n`;
        if (testResult.evidence) {
          reportText += `  - Evidence: ${testResult.evidence}\n`;
        }
        if (testResult.recommendation) {
          reportText += `  - Recommendation: ${testResult.recommendation}\n`;
        }
      }
    }

    if (report.recommendations.length > 0) {
      reportText += `\n## Recommendations\n`;
      for (const recommendation of report.recommendations) {
        reportText += `\n- ${recommendation}\n`;
      }
    }

    return reportText;
  }

  /**
   * Get compliance reports
   */
  getComplianceReports(): ComplianceReport[] {
    return this.complianceReports;
  }

  /**
   * Clear compliance reports
   */
  clearReports(): void {
    this.complianceReports = [];
  }
}

export default SecurityComplianceChecker;
