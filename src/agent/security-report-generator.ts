import { SecurityVulnerability, SecurityAnalysis } from './security-testing-agent';
import { VulnerabilityScanResult } from './security-vulnerability-scanner';
import { ComplianceReport } from './security-compliance-checker';

export interface SecurityReport {
  reportId: string;
  generatedAt: Date;
  reportType: 'COMPREHENSIVE' | 'VULNERABILITY' | 'COMPLIANCE' | 'RISK_ASSESSMENT';
  summary: SecurityReportSummary;
  vulnerabilities: SecurityVulnerability[];
  complianceReports: ComplianceReport[];
  riskAssessment: RiskAssessment;
  recommendations: SecurityRecommendation[];
  executiveSummary: string;
  technicalDetails: TechnicalDetails;
  appendices: ReportAppendix[];
}

export interface SecurityReportSummary {
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities: number;
  lowVulnerabilities: number;
  overallRiskScore: number;
  complianceScore: number;
  securityPosture: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR' | 'CRITICAL';
  lastUpdated: Date;
}

export interface RiskAssessment {
  overallRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  riskFactors: RiskFactor[];
  businessImpact: BusinessImpact;
  likelihoodAssessment: LikelihoodAssessment;
  riskMatrix: RiskMatrix;
  mitigationStrategies: MitigationStrategy[];
}

export interface RiskFactor {
  factor: string;
  impact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  likelihood: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  affectedSystems: string[];
}

export interface BusinessImpact {
  financialImpact: string;
  operationalImpact: string;
  reputationalImpact: string;
  regulatoryImpact: string;
  customerImpact: string;
}

export interface LikelihoodAssessment {
  attackVector: string;
  exploitability: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threatLandscape: string;
  historicalData: string;
  confidenceLevel: number;
}

export interface RiskMatrix {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface MitigationStrategy {
  strategy: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  effort: 'LOW' | 'MEDIUM' | 'HIGH';
  cost: 'LOW' | 'MEDIUM' | 'HIGH';
  timeline: string;
  effectiveness: number;
}

export interface SecurityRecommendation {
  id: string;
  title: string;
  description: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  implementation: string;
  estimatedEffort: 'LOW' | 'MEDIUM' | 'HIGH';
  estimatedCost: 'LOW' | 'MEDIUM' | 'HIGH';
  timeline: string;
  businessJustification: string;
  technicalDetails: string;
  complianceImpact: string[];
}

export interface TechnicalDetails {
  scanConfiguration: ScanConfiguration;
  testingMethodology: TestingMethodology;
  toolsUsed: string[];
  limitations: string[];
  falsePositives: string[];
  nextSteps: string[];
}

export interface ScanConfiguration {
  endpoints: string[];
  methods: string[];
  payloads: number;
  duration: string;
  concurrency: number;
}

export interface TestingMethodology {
  approach: string;
  standards: string[];
  frameworks: string[];
  techniques: string[];
}

export interface ReportAppendix {
  title: string;
  content: string;
  type: 'TECHNICAL' | 'COMPLIANCE' | 'RISK' | 'RECOMMENDATIONS';
}

export class SecurityReportGenerator {
  private reports: SecurityReport[] = [];

  /**
   * Generate comprehensive security report
   */
  generateComprehensiveReport(
    vulnerabilities: SecurityVulnerability[],
    complianceReports: ComplianceReport[],
    scanResults: VulnerabilityScanResult[],
    analysis: SecurityAnalysis
  ): SecurityReport {
    const reportId = this.generateReportId();
    const generatedAt = new Date();
    
    const summary = this.generateSummary(vulnerabilities, complianceReports);
    const riskAssessment = this.generateRiskAssessment(vulnerabilities, analysis);
    const recommendations = this.generateRecommendations(vulnerabilities, complianceReports);
    const executiveSummary = this.generateExecutiveSummary(summary, riskAssessment);
    const technicalDetails = this.generateTechnicalDetails(scanResults);
    const appendices = this.generateAppendices(vulnerabilities, complianceReports);

    const report: SecurityReport = {
      reportId,
      generatedAt,
      reportType: 'COMPREHENSIVE',
      summary,
      vulnerabilities,
      complianceReports,
      riskAssessment,
      recommendations,
      executiveSummary,
      technicalDetails,
      appendices
    };

    this.reports.push(report);
    return report;
  }

  /**
   * Generate vulnerability-focused report
   */
  generateVulnerabilityReport(
    vulnerabilities: SecurityVulnerability[],
    scanResults: VulnerabilityScanResult[]
  ): SecurityReport {
    const reportId = this.generateReportId();
    const generatedAt = new Date();
    
    const summary = this.generateSummary(vulnerabilities, []);
    const riskAssessment = this.generateRiskAssessment(vulnerabilities, { vulnerabilities, riskScore: 0, complianceStatus: { owasp: [], pciDss: [], sox: [], gdpr: [] }, recommendations: [], attackSurface: { endpoints: [], exposedData: [], authenticationMethods: [], authorizationLevels: [] } });
    const recommendations = this.generateRecommendations(vulnerabilities, []);
    const executiveSummary = this.generateExecutiveSummary(summary, riskAssessment);
    const technicalDetails = this.generateTechnicalDetails(scanResults);
    const appendices = this.generateAppendices(vulnerabilities, []);

    const report: SecurityReport = {
      reportId,
      generatedAt,
      reportType: 'VULNERABILITY',
      summary,
      vulnerabilities,
      complianceReports: [],
      riskAssessment,
      recommendations,
      executiveSummary,
      technicalDetails,
      appendices
    };

    this.reports.push(report);
    return report;
  }

  /**
   * Generate compliance-focused report
   */
  generateComplianceReport(complianceReports: ComplianceReport[]): SecurityReport {
    const reportId = this.generateReportId();
    const generatedAt = new Date();
    
    const summary = this.generateSummary([], complianceReports);
    const riskAssessment = this.generateRiskAssessment([], { vulnerabilities: [], riskScore: 0, complianceStatus: { owasp: [], pciDss: [], sox: [], gdpr: [] }, recommendations: [], attackSurface: { endpoints: [], exposedData: [], authenticationMethods: [], authorizationLevels: [] } });
    const recommendations = this.generateRecommendations([], complianceReports);
    const executiveSummary = this.generateExecutiveSummary(summary, riskAssessment);
    const technicalDetails = this.generateTechnicalDetails([]);
    const appendices = this.generateAppendices([], complianceReports);

    const report: SecurityReport = {
      reportId,
      generatedAt,
      reportType: 'COMPLIANCE',
      summary,
      vulnerabilities: [],
      complianceReports,
      riskAssessment,
      recommendations,
      executiveSummary,
      technicalDetails,
      appendices
    };

    this.reports.push(report);
    return report;
  }

  /**
   * Generate risk assessment report
   */
  generateRiskAssessmentReport(
    vulnerabilities: SecurityVulnerability[],
    analysis: SecurityAnalysis
  ): SecurityReport {
    const reportId = this.generateReportId();
    const generatedAt = new Date();
    
    const summary = this.generateSummary(vulnerabilities, []);
    const riskAssessment = this.generateRiskAssessment(vulnerabilities, analysis);
    const recommendations = this.generateRecommendations(vulnerabilities, []);
    const executiveSummary = this.generateExecutiveSummary(summary, riskAssessment);
    const technicalDetails = this.generateTechnicalDetails([]);
    const appendices = this.generateAppendices(vulnerabilities, []);

    const report: SecurityReport = {
      reportId,
      generatedAt,
      reportType: 'RISK_ASSESSMENT',
      summary,
      vulnerabilities,
      complianceReports: [],
      riskAssessment,
      recommendations,
      executiveSummary,
      technicalDetails,
      appendices
    };

    this.reports.push(report);
    return report;
  }

  /**
   * Generate report summary
   */
  private generateSummary(
    vulnerabilities: SecurityVulnerability[],
    complianceReports: ComplianceReport[]
  ): SecurityReportSummary {
    const totalVulnerabilities = vulnerabilities.length;
    const criticalVulnerabilities = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highVulnerabilities = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const mediumVulnerabilities = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const lowVulnerabilities = vulnerabilities.filter(v => v.severity === 'LOW').length;

    const overallRiskScore = this.calculateOverallRiskScore(vulnerabilities);
    const complianceScore = this.calculateComplianceScore(complianceReports);
    const securityPosture = this.determineSecurityPosture(overallRiskScore, criticalVulnerabilities);

    return {
      totalVulnerabilities,
      criticalVulnerabilities,
      highVulnerabilities,
      mediumVulnerabilities,
      lowVulnerabilities,
      overallRiskScore,
      complianceScore,
      securityPosture,
      lastUpdated: new Date()
    };
  }

  /**
   * Generate risk assessment
   */
  private generateRiskAssessment(
    vulnerabilities: SecurityVulnerability[],
    analysis: SecurityAnalysis
  ): RiskAssessment {
    const riskFactors = this.identifyRiskFactors(vulnerabilities);
    const businessImpact = this.assessBusinessImpact(vulnerabilities);
    const likelihoodAssessment = this.assessLikelihood(vulnerabilities);
    const riskMatrix = this.calculateRiskMatrix(vulnerabilities);
    const mitigationStrategies = this.generateMitigationStrategies(vulnerabilities);

    const overallRiskLevel = this.determineOverallRiskLevel(riskMatrix);

    return {
      overallRiskLevel,
      riskFactors,
      businessImpact,
      likelihoodAssessment,
      riskMatrix,
      mitigationStrategies
    };
  }

  /**
   * Generate security recommendations
   */
  private generateRecommendations(
    vulnerabilities: SecurityVulnerability[],
    complianceReports: ComplianceReport[]
  ): SecurityRecommendation[] {
    const recommendations: SecurityRecommendation[] = [];

    // Vulnerability-based recommendations
    for (const vuln of vulnerabilities) {
      if (vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH') {
        recommendations.push({
          id: `REC-${vuln.type}-${Date.now()}`,
          title: `Address ${vuln.type} Vulnerability`,
          description: vuln.description,
          priority: vuln.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
          category: vuln.type,
          implementation: vuln.recommendation,
          estimatedEffort: this.estimateEffort(vuln.severity),
          estimatedCost: this.estimateCost(vuln.severity),
          timeline: this.estimateTimeline(vuln.severity),
          businessJustification: this.generateBusinessJustification(vuln),
          technicalDetails: this.generateVulnerabilityTechnicalDetails(vuln),
          complianceImpact: this.assessComplianceImpact(vuln, complianceReports)
        });
      }
    }

    // Compliance-based recommendations
    for (const report of complianceReports) {
      for (const recommendation of report.recommendations) {
        recommendations.push({
          id: `REC-COMPLIANCE-${Date.now()}`,
          title: `${report.framework} Compliance Issue`,
          description: recommendation,
          priority: 'MEDIUM',
          category: 'COMPLIANCE',
          implementation: recommendation,
          estimatedEffort: 'MEDIUM',
          estimatedCost: 'MEDIUM',
          timeline: '30-60 days',
          businessJustification: `Required for ${report.framework} compliance`,
          technicalDetails: `Compliance requirement from ${report.framework}`,
          complianceImpact: [report.framework]
        });
      }
    }

    return recommendations.sort((a, b) => {
      const priorityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });
  }

  /**
   * Generate executive summary
   */
  private generateExecutiveSummary(
    summary: SecurityReportSummary,
    riskAssessment: RiskAssessment
  ): string {
    return `
## Executive Summary

This security assessment reveals a ${summary.securityPosture.toLowerCase()} security posture for the API under review. 

**Key Findings:**
- **Total Vulnerabilities**: ${summary.totalVulnerabilities}
- **Critical Issues**: ${summary.criticalVulnerabilities}
- **High Priority Issues**: ${summary.highVulnerabilities}
- **Overall Risk Score**: ${summary.overallRiskScore}/100
- **Compliance Score**: ${summary.complianceScore}%

**Risk Assessment:**
The overall risk level is **${riskAssessment.overallRiskLevel}** based on the identified vulnerabilities and their potential business impact.

**Immediate Actions Required:**
${summary.criticalVulnerabilities > 0 ? 
  `- Address ${summary.criticalVulnerabilities} critical vulnerabilities immediately` : 
  '- No critical vulnerabilities identified'}
${summary.highVulnerabilities > 0 ? 
  `- Prioritize remediation of ${summary.highVulnerabilities} high-priority issues` : 
  '- No high-priority vulnerabilities identified'}

**Business Impact:**
${riskAssessment.businessImpact.financialImpact}

**Recommendations:**
Implement the recommended security controls and remediation measures to improve the overall security posture and ensure compliance with relevant standards.
    `.trim();
  }

  /**
   * Generate technical details
   */
  private generateTechnicalDetails(scanResults: VulnerabilityScanResult[]): TechnicalDetails {
    const endpoints = [...new Set(scanResults.map(r => r.endpoint))];
    const methods = [...new Set(scanResults.map(r => r.method))];
    const totalPayloads = scanResults.reduce((sum, r) => sum + r.totalTests, 0);
    const totalDuration = scanResults.reduce((sum, r) => sum + r.scanDuration, 0);

    return {
      scanConfiguration: {
        endpoints,
        methods,
        payloads: totalPayloads,
        duration: `${Math.round(totalDuration / 1000)}s`,
        concurrency: 5
      },
      testingMethodology: {
        approach: 'Automated security testing with comprehensive payload injection',
        standards: ['OWASP Top 10 2021', 'PCI DSS 4.0', 'SOX 2002'],
        frameworks: ['OWASP Testing Guide', 'NIST Cybersecurity Framework'],
        techniques: ['SQL Injection', 'XSS', 'Command Injection', 'Path Traversal', 'XXE']
      },
      toolsUsed: [
        'Custom Security Testing Agent',
        'Vulnerability Scanner',
        'Compliance Checker',
        'Risk Assessment Engine'
      ],
      limitations: [
        'Testing limited to identified endpoints',
        'Some vulnerabilities may require manual verification',
        'False positives possible in complex applications'
      ],
      falsePositives: [
        'Legitimate error messages may be flagged as information disclosure',
        'Some input validation may be context-dependent'
      ],
      nextSteps: [
        'Manual verification of critical findings',
        'Implementation of recommended controls',
        'Regular security testing schedule',
        'Security awareness training for development team'
      ]
    };
  }

  /**
   * Generate report appendices
   */
  private generateAppendices(
    vulnerabilities: SecurityVulnerability[],
    complianceReports: ComplianceReport[]
  ): ReportAppendix[] {
    const appendices: ReportAppendix[] = [];

    // Technical appendix
    appendices.push({
      title: 'Technical Vulnerability Details',
      content: this.formatVulnerabilityDetails(vulnerabilities),
      type: 'TECHNICAL'
    });

    // Compliance appendix
    if (complianceReports.length > 0) {
      appendices.push({
        title: 'Compliance Assessment Details',
        content: this.formatComplianceDetails(complianceReports),
        type: 'COMPLIANCE'
      });
    }

    // Risk appendix
    appendices.push({
      title: 'Risk Assessment Methodology',
      content: this.formatRiskMethodology(),
      type: 'RISK'
    });

    // Recommendations appendix
    appendices.push({
      title: 'Detailed Recommendations',
      content: this.formatRecommendations(vulnerabilities, complianceReports),
      type: 'RECOMMENDATIONS'
    });

    return appendices;
  }

  /**
   * Calculate overall risk score
   */
  private calculateOverallRiskScore(vulnerabilities: SecurityVulnerability[]): number {
    let score = 0;
    
    for (const vuln of vulnerabilities) {
      switch (vuln.severity) {
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
    
    return Math.min(score, 100);
  }

  /**
   * Calculate compliance score
   */
  private calculateComplianceScore(complianceReports: ComplianceReport[]): number {
    if (complianceReports.length === 0) return 0;
    
    const totalScore = complianceReports.reduce((sum, report) => sum + report.complianceScore, 0);
    return Math.round(totalScore / complianceReports.length);
  }

  /**
   * Determine security posture
   */
  private determineSecurityPosture(riskScore: number, criticalVulns: number): 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR' | 'CRITICAL' {
    if (criticalVulns > 0) return 'CRITICAL';
    if (riskScore >= 80) return 'POOR';
    if (riskScore >= 60) return 'FAIR';
    if (riskScore >= 40) return 'GOOD';
    return 'EXCELLENT';
  }

  /**
   * Identify risk factors
   */
  private identifyRiskFactors(vulnerabilities: SecurityVulnerability[]): RiskFactor[] {
    const riskFactors: RiskFactor[] = [];
    
    // Group vulnerabilities by type
    const vulnByType = vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.type] = (acc[vuln.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    for (const [type, count] of Object.entries(vulnByType)) {
      const severity = vulnerabilities.find(v => v.type === type)?.severity || 'MEDIUM';
      riskFactors.push({
        factor: type,
        impact: severity === 'CRITICAL' ? 'CRITICAL' : severity === 'HIGH' ? 'HIGH' : 'MEDIUM',
        likelihood: count > 5 ? 'HIGH' : count > 2 ? 'MEDIUM' : 'LOW',
        description: `Multiple ${type} vulnerabilities identified`,
        affectedSystems: [...new Set(vulnerabilities.filter(v => v.type === type).map(v => v.endpoint))]
      });
    }

    return riskFactors;
  }

  /**
   * Assess business impact
   */
  private assessBusinessImpact(vulnerabilities: SecurityVulnerability[]): BusinessImpact {
    const criticalVulns = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highVulns = vulnerabilities.filter(v => v.severity === 'HIGH').length;

    return {
      financialImpact: criticalVulns > 0 ? 
        'High financial risk due to critical vulnerabilities' : 
        highVulns > 0 ? 
        'Moderate financial risk due to high-priority vulnerabilities' : 
        'Low financial risk',
      operationalImpact: criticalVulns > 0 ? 
        'Significant operational disruption possible' : 
        'Limited operational impact expected',
      reputationalImpact: criticalVulns > 0 ? 
        'Severe reputational damage risk' : 
        'Moderate reputational risk',
      regulatoryImpact: 'Potential regulatory compliance issues',
      customerImpact: criticalVulns > 0 ? 
        'High customer data exposure risk' : 
        'Moderate customer impact risk'
    };
  }

  /**
   * Assess likelihood
   */
  private assessLikelihood(vulnerabilities: SecurityVulnerability[]): LikelihoodAssessment {
    const totalVulns = vulnerabilities.length;
    const publicFacing = vulnerabilities.filter(v => v.endpoint.includes('/api/')).length;

    return {
      attackVector: 'Web application API',
      exploitability: totalVulns > 10 ? 'HIGH' : totalVulns > 5 ? 'MEDIUM' : 'LOW',
      threatLandscape: 'Active threat landscape with automated attack tools',
      historicalData: 'Based on industry benchmarks and vulnerability databases',
      confidenceLevel: publicFacing > 0 ? 85 : 70
    };
  }

  /**
   * Calculate risk matrix
   */
  private calculateRiskMatrix(vulnerabilities: SecurityVulnerability[]): RiskMatrix {
    const critical = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const high = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const medium = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const low = vulnerabilities.filter(v => v.severity === 'LOW').length;

    return {
      critical,
      high,
      medium,
      low,
      total: critical + high + medium + low
    };
  }

  /**
   * Generate mitigation strategies
   */
  private generateMitigationStrategies(vulnerabilities: SecurityVulnerability[]): MitigationStrategy[] {
    const strategies: MitigationStrategy[] = [];

    // Input validation strategy
    if (vulnerabilities.some(v => v.type === 'SQL_INJECTION' || v.type === 'XSS')) {
      strategies.push({
        strategy: 'Implement comprehensive input validation',
        priority: 'HIGH',
        effort: 'MEDIUM',
        cost: 'MEDIUM',
        timeline: '30-60 days',
        effectiveness: 90
      });
    }

    // Authentication strategy
    if (vulnerabilities.some(v => v.type === 'AUTH_BYPASS')) {
      strategies.push({
        strategy: 'Strengthen authentication mechanisms',
        priority: 'HIGH',
        effort: 'HIGH',
        cost: 'HIGH',
        timeline: '60-90 days',
        effectiveness: 95
      });
    }

    // Rate limiting strategy
    if (vulnerabilities.some(v => v.type === 'RATE_LIMIT_BYPASS')) {
      strategies.push({
        strategy: 'Implement rate limiting and abuse prevention',
        priority: 'MEDIUM',
        effort: 'LOW',
        cost: 'LOW',
        timeline: '15-30 days',
        effectiveness: 80
      });
    }

    return strategies;
  }

  /**
   * Determine overall risk level
   */
  private determineOverallRiskLevel(riskMatrix: RiskMatrix): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (riskMatrix.critical > 0) return 'CRITICAL';
    if (riskMatrix.high > 3) return 'HIGH';
    if (riskMatrix.high > 0 || riskMatrix.medium > 5) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Estimate effort for remediation
   */
  private estimateEffort(severity: string): 'LOW' | 'MEDIUM' | 'HIGH' {
    switch (severity) {
      case 'CRITICAL':
        return 'HIGH';
      case 'HIGH':
        return 'MEDIUM';
      default:
        return 'LOW';
    }
  }

  /**
   * Estimate cost for remediation
   */
  private estimateCost(severity: string): 'LOW' | 'MEDIUM' | 'HIGH' {
    switch (severity) {
      case 'CRITICAL':
        return 'HIGH';
      case 'HIGH':
        return 'MEDIUM';
      default:
        return 'LOW';
    }
  }

  /**
   * Estimate timeline for remediation
   */
  private estimateTimeline(severity: string): string {
    switch (severity) {
      case 'CRITICAL':
        return '1-7 days';
      case 'HIGH':
        return '7-30 days';
      case 'MEDIUM':
        return '30-60 days';
      default:
        return '60-90 days';
    }
  }

  /**
   * Generate business justification
   */
  private generateBusinessJustification(vuln: SecurityVulnerability): string {
    return `Addressing this ${vuln.severity.toLowerCase()}-severity ${vuln.type} vulnerability is essential to protect business assets, maintain customer trust, and ensure regulatory compliance.`;
  }

  /**
   * Generate technical details for vulnerability
   */
  private generateVulnerabilityTechnicalDetails(vuln: SecurityVulnerability): string {
    return `Technical implementation details for ${vuln.type} vulnerability remediation: ${vuln.recommendation}`;
  }

  /**
   * Assess compliance impact
   */
  private assessComplianceImpact(vuln: SecurityVulnerability, complianceReports: ComplianceReport[]): string[] {
    const impacts: string[] = [];
    
    if (vuln.owaspCategory) {
      impacts.push('OWASP Top 10');
    }
    
    if (vuln.type === 'DATA_EXPOSURE') {
      impacts.push('PCI DSS');
    }
    
    if (vuln.type === 'INSUFFICIENT_LOGGING') {
      impacts.push('SOX');
    }
    
    return impacts;
  }

  /**
   * Format vulnerability details
   */
  private formatVulnerabilityDetails(vulnerabilities: SecurityVulnerability[]): string {
    let content = '# Technical Vulnerability Details\n\n';
    
    for (const vuln of vulnerabilities) {
      content += `## ${vuln.type} (${vuln.severity})\n`;
      content += `- **Endpoint**: ${vuln.endpoint}\n`;
      content += `- **Description**: ${vuln.description}\n`;
      content += `- **Recommendation**: ${vuln.recommendation}\n`;
      if (vuln.cweId) content += `- **CWE ID**: ${vuln.cweId}\n`;
      if (vuln.owaspCategory) content += `- **OWASP Category**: ${vuln.owaspCategory}\n`;
      if (vuln.payload) content += `- **Payload**: ${vuln.payload}\n`;
      content += '\n';
    }
    
    return content;
  }

  /**
   * Format compliance details
   */
  private formatComplianceDetails(complianceReports: ComplianceReport[]): string {
    let content = '# Compliance Assessment Details\n\n';
    
    for (const report of complianceReports) {
      content += `## ${report.framework} ${report.version}\n`;
      content += `- **Overall Status**: ${report.overallStatus}\n`;
      content += `- **Compliance Score**: ${report.complianceScore}%\n`;
      content += `- **Total Requirements**: ${report.summary.totalRequirements}\n`;
      content += `- **Passed**: ${report.summary.passedRequirements}\n`;
      content += `- **Failed**: ${report.summary.failedRequirements}\n\n`;
    }
    
    return content;
  }

  /**
   * Format risk methodology
   */
  private formatRiskMethodology(): string {
    return `
# Risk Assessment Methodology

## Risk Calculation
Risk is calculated using the formula: Risk = Impact × Likelihood

## Impact Levels
- **Critical**: System compromise, data breach, regulatory violations
- **High**: Significant operational impact, reputational damage
- **Medium**: Moderate impact, limited exposure
- **Low**: Minimal impact, easily contained

## Likelihood Levels
- **Critical**: Very likely to occur, active exploitation
- **High**: Likely to occur, known attack vectors
- **Medium**: Possible, requires some effort
- **Low**: Unlikely, requires significant effort

## Risk Matrix
| Impact \\ Likelihood | Low | Medium | High | Critical |
|---------------------|-----|--------|------|----------|
| Low | Low | Low | Medium | High |
| Medium | Low | Medium | High | Critical |
| High | Medium | High | Critical | Critical |
| Critical | High | Critical | Critical | Critical |
    `.trim();
  }

  /**
   * Format recommendations
   */
  private formatRecommendations(
    vulnerabilities: SecurityVulnerability[],
    complianceReports: ComplianceReport[]
  ): string {
    let content = '# Detailed Recommendations\n\n';
    
    // Group recommendations by priority
    const recommendations = this.generateRecommendations(vulnerabilities, complianceReports);
    const byPriority = recommendations.reduce((acc, rec) => {
      if (!acc[rec.priority]) acc[rec.priority] = [];
      acc[rec.priority].push(rec);
      return acc;
    }, {} as Record<string, SecurityRecommendation[]>);

    for (const [priority, recs] of Object.entries(byPriority)) {
      content += `## ${priority} Priority Recommendations\n\n`;
      
      for (const rec of recs) {
        content += `### ${rec.title}\n`;
        content += `- **Description**: ${rec.description}\n`;
        content += `- **Implementation**: ${rec.implementation}\n`;
        content += `- **Effort**: ${rec.estimatedEffort}\n`;
        content += `- **Cost**: ${rec.estimatedCost}\n`;
        content += `- **Timeline**: ${rec.timeline}\n`;
        content += `- **Business Justification**: ${rec.businessJustification}\n\n`;
      }
    }
    
    return content;
  }

  /**
   * Generate report ID
   */
  private generateReportId(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    return `SEC-${timestamp}-${random}`;
  }

  /**
   * Export report to various formats
   */
  exportReport(report: SecurityReport, format: 'HTML' | 'PDF' | 'JSON' | 'MARKDOWN'): string {
    switch (format) {
      case 'HTML':
        return this.exportToHtml(report);
      case 'PDF':
        return this.exportToPdf(report);
      case 'JSON':
        return JSON.stringify(report, null, 2);
      case 'MARKDOWN':
        return this.exportToMarkdown(report);
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  /**
   * Export to HTML format
   */
  private exportToHtml(report: SecurityReport): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - ${report.reportId}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .summary { background: #e8f4f8; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .vulnerability { background: #fff3cd; padding: 10px; margin: 10px 0; border-left: 4px solid #ffc107; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Report ID:</strong> ${report.reportId}</p>
        <p><strong>Generated:</strong> ${report.generatedAt.toISOString()}</p>
        <p><strong>Type:</strong> ${report.reportType}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        ${report.executiveSummary.replace(/\n/g, '<br>')}
    </div>
    
    <h2>Vulnerabilities</h2>
    ${report.vulnerabilities.map(v => `
        <div class="vulnerability ${v.severity.toLowerCase()}">
            <h3>${v.type} (${v.severity})</h3>
            <p><strong>Endpoint:</strong> ${v.endpoint}</p>
            <p><strong>Description:</strong> ${v.description}</p>
            <p><strong>Recommendation:</strong> ${v.recommendation}</p>
        </div>
    `).join('')}
</body>
</html>
    `.trim();
  }

  /**
   * Export to PDF format (placeholder)
   */
  private exportToPdf(report: SecurityReport): string {
    // This would typically use a PDF generation library
    return `PDF export not implemented. Use HTML or Markdown format.`;
  }

  /**
   * Export to Markdown format
   */
  private exportToMarkdown(report: SecurityReport): string {
    let markdown = `# Security Assessment Report\n\n`;
    markdown += `**Report ID:** ${report.reportId}\n`;
    markdown += `**Generated:** ${report.generatedAt.toISOString()}\n`;
    markdown += `**Type:** ${report.reportType}\n\n`;
    
    markdown += `## Executive Summary\n\n`;
    markdown += `${report.executiveSummary}\n\n`;
    
    markdown += `## Summary Statistics\n\n`;
    markdown += `- **Total Vulnerabilities:** ${report.summary.totalVulnerabilities}\n`;
    markdown += `- **Critical:** ${report.summary.criticalVulnerabilities}\n`;
    markdown += `- **High:** ${report.summary.highVulnerabilities}\n`;
    markdown += `- **Medium:** ${report.summary.mediumVulnerabilities}\n`;
    markdown += `- **Low:** ${report.summary.lowVulnerabilities}\n`;
    markdown += `- **Risk Score:** ${report.summary.overallRiskScore}/100\n`;
    markdown += `- **Security Posture:** ${report.summary.securityPosture}\n\n`;
    
    markdown += `## Vulnerabilities\n\n`;
    for (const vuln of report.vulnerabilities) {
      markdown += `### ${vuln.type} (${vuln.severity})\n`;
      markdown += `- **Endpoint:** ${vuln.endpoint}\n`;
      markdown += `- **Description:** ${vuln.description}\n`;
      markdown += `- **Recommendation:** ${vuln.recommendation}\n`;
      if (vuln.cweId) markdown += `- **CWE ID:** ${vuln.cweId}\n`;
      if (vuln.owaspCategory) markdown += `- **OWASP Category:** ${vuln.owaspCategory}\n`;
      markdown += `\n`;
    }
    
    return markdown;
  }

  /**
   * Get all reports
   */
  getReports(): SecurityReport[] {
    return this.reports;
  }

  /**
   * Clear all reports
   */
  clearReports(): void {
    this.reports = [];
  }
}

export default SecurityReportGenerator;
