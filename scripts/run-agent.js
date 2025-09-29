#!/usr/bin/env node

/**
 * API Tester Agent Runner Script
 * 
 * This script demonstrates how to use the API Tester Agent programmatically
 * without Playwright test framework.
 */

const { createTestRunner, createApiTesterAgent, createTestGenerator } = require('../src/agent');
const { ApiClient } = require('../src/api/api-client');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

async function runApiTesterAgent() {
  console.log('🤖 Starting API Tester Agent Demo\n');

  try {
    // Create API client (simulating Playwright's request context)
    const mockRequest = {
      get: async (url, options) => {
        const response = await fetch(url, options);
        return {
          status: () => response.status,
          ok: () => response.ok,
          json: () => response.json(),
          text: () => response.text(),
          headers: () => Object.fromEntries(response.headers.entries())
        };
      },
      post: async (url, options) => {
        const response = await fetch(url, {
          method: 'POST',
          ...options
        });
        return {
          status: () => response.status,
          ok: () => response.ok,
          json: () => response.json(),
          text: () => response.text(),
          headers: () => Object.fromEntries(response.headers.entries())
        };
      },
      put: async (url, options) => {
        const response = await fetch(url, {
          method: 'PUT',
          ...options
        });
        return {
          status: () => response.status,
          ok: () => response.ok,
          json: () => response.json(),
          text: () => response.text(),
          headers: () => Object.fromEntries(response.headers.entries())
        };
      },
      delete: async (url, options) => {
        const response = await fetch(url, {
          method: 'DELETE',
          ...options
        });
        return {
          status: () => response.status,
          ok: () => response.ok,
          json: () => response.json(),
          text: () => response.text(),
          headers: () => Object.fromEntries(response.headers.entries())
        };
      },
      patch: async (url, options) => {
        const response = await fetch(url, {
          method: 'PATCH',
          ...options
        });
        return {
          status: () => response.status,
          ok: () => response.ok,
          json: () => response.json(),
          text: () => response.text(),
          headers: () => Object.fromEntries(response.headers.entries())
        };
      }
    };

    const apiClient = new ApiClient(mockRequest, 'https://reqres.in/api');

    // Create API specification
    const apiSpec = {
      name: 'ReqRes API Demo',
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

    // Create test runner
    const testRunner = createTestRunner(apiClient, {
      environment: 'demo',
      baseUrl: 'https://reqres.in/api',
      parallel: false,
      generateReport: true,
      reportFormat: 'markdown'
    });

    console.log('📋 Running tests from API specification...\n');

    // Run tests
    const result = await testRunner.runTestsFromSpec(apiSpec);

    console.log('\n🎯 Test Run Complete!');
    console.log(`📊 Results: ${result.passedTests}/${result.totalTests} tests passed (${result.successRate.toFixed(1)}%)`);
    console.log(`⏱️  Duration: ${(result.duration/1000).toFixed(2)}s`);

    if (result.report) {
      console.log('\n📄 Test Report:');
      console.log(result.report);
    }

    // Demonstrate individual agent components
    console.log('\n🔧 Demonstrating individual agent components...\n');

    const agent = createApiTesterAgent(apiClient);
    const testSuite = agent.generateTestSuite('/users', ['GET']);
    const agentResults = await agent.executeTestSuite(testSuite);

    console.log(`\n✅ Agent executed ${agentResults.length} tests`);

    // Demonstrate test generator
    const generator = createTestGenerator(apiSpec);
    const generatedSuites = generator.generateTestSuite();
    console.log(`\n🏗️  Generator created ${generatedSuites.length} test suites`);

    // Demonstrate API analysis
    const analysis = await agent.analyzeApi(['/users', '/users/2']);
    console.log(`\n🔍 Analysis found ${analysis.endpoints.length} endpoints`);

    console.log('\n🎉 API Tester Agent Demo completed successfully!');

  } catch (error) {
    console.error('❌ Error running API Tester Agent:', error);
    process.exit(1);
  }
}

// Run the demo if this script is executed directly
if (require.main === module) {
  runApiTesterAgent();
}

module.exports = { runApiTesterAgent };
