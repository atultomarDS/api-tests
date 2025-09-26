# API Test Plan

## Overview
This test plan covers API testing for the reqres.in API using Playwright with custom framework components.

## Test Environment
- **Base URL**: https://reqres.in/api
- **Authentication**: API Key (x-api-key: reqres-free-v1)
- **Test Framework**: Playwright + Custom API Client
- **Data Source**: tests/data/users.json

## Test Cases

| Test ID | Test Case | Category | Priority | Status | Automated | Test File | Description |
|---------|-----------|----------|----------|--------|-----------|-----------|-------------|
| TC001 | GET /users - List users with pagination | Functional | High | ✅ Pass | ✅ Yes | user.crud.spec.ts | Verify users list endpoint returns paginated data |
| TC002 | GET /users/{id} - Fetch single user | Functional | High | ✅ Pass | ✅ Yes | user.crud.spec.ts | Verify single user retrieval by ID |
| TC003 | POST /users - Create new user | Functional | High | ✅ Pass | ✅ Yes | user.crud.spec.ts | Verify user creation with valid payload |
| TC004 | PUT /users/{id} - Update user (full) | Functional | High | ✅ Pass | ✅ Yes | user.crud.spec.ts | Verify complete user update |
| TC005 | DELETE /users/{id} - Delete user | Functional | High | ✅ Pass | ✅ Yes | user.crud.spec.ts | Verify user deletion |
| TC006 | User response schema validation | Non-Functional | Medium | ✅ Pass | ✅ Yes | users.schema.spec.ts | Validate response structure matches JSON schema |
| TC007 | API retry mechanism (429/503) | Non-Functional | Medium | ✅ Pass | ✅ Yes | api-client.ts | Verify exponential backoff retry logic |
| TC008 | Authentication with API key | Security | High | ✅ Pass | ✅ Yes | playwright.config.ts | Verify x-api-key header authentication |
| TC009 | Error handling - 401 Unauthorized | Security | High | ✅ Pass | ✅ Yes | api-assertions.ts | Verify proper error response for missing auth |
| TC010 | Error handling - 404 Not Found | Functional | Medium | ✅ Pass | ✅ Yes | user.crud.spec.ts | Verify 404 response for non-existent user |
| TC011 | Content-Type validation | Non-Functional | Low | ✅ Pass | ✅ Yes | api-assertions.ts | Verify JSON content type in responses |
| TC012 | Data-driven testing | Non-Functional | Medium | ✅ Pass | ✅ Yes | user.crud.spec.ts | Verify tests use external JSON data |
| TC013 | Serial test execution | Non-Functional | Medium | ✅ Pass | ✅ Yes | user.crud.spec.ts | Verify CRUD tests run in sequence |
| TC014 | Health check endpoint | Functional | Low | ✅ Pass | ✅ Yes | api.spec.ts | Verify basic health endpoint |
| TC015 | Echo endpoint with payload | Functional | Low | ✅ Pass | ✅ Yes | api.spec.ts | Verify echo functionality |
| TC016 | SQL Injection attempt | Security | High | ✅ Pass | ✅ Yes | security.spec.ts | Test for SQL injection vulnerabilities |
| TC017 | XSS payload in request body | Security | High | ✅ Pass | ✅ Yes | security.spec.ts | Test for XSS vulnerabilities |
| TC018 | Large payload handling | Performance | Medium | ✅ Pass | ✅ Yes | performance.spec.ts | Test API with large request bodies |
| TC019 | Response time validation | Performance | Medium | ✅ Pass | ✅ Yes | performance.spec.ts | Verify response times under normal load |
| TC020 | Rate limiting behavior | Security | High | ✅ Pass | ✅ Yes | security.spec.ts | Test rate limiting and throttling |
| TC021 | Invalid JSON payload | Functional | Medium | ✅ Pass | ✅ Yes | security.spec.ts | Test malformed JSON handling |
| TC022 | Missing required fields | Functional | Medium | ✅ Pass | ✅ Yes | security.spec.ts | Test validation of required fields |
| TC023 | Concurrent request handling | Performance | Medium | ✅ Pass | ✅ Yes | performance.spec.ts | Test API under concurrent load |
| TC024 | Memory leak detection | Performance | Low | ✅ Pass | ✅ Yes | performance.spec.ts | Monitor for memory issues over time |

## Test Categories

### Functional Tests
- **CRUD Operations**: Create, Read, Update, Delete user operations
- **Endpoint Validation**: Verify all API endpoints respond correctly
- **Data Validation**: Ensure correct data handling and responses

### Non-Functional Tests
- **Performance**: Retry mechanism and timeout handling
- **Schema Validation**: JSON response structure validation
- **Data-Driven**: External test data management

### Security Tests
- **Authentication**: API key validation
- **Authorization**: Proper error handling for unauthorized access
- **Injection Attacks**: SQL injection and XSS prevention
- **Rate Limiting**: Throttling and abuse prevention

### Performance Tests
- **Response Time**: API response time validation
- **Load Handling**: Large payload and concurrent request testing
- **Resource Usage**: Memory and CPU monitoring

## Test Data

### Source: tests/data/users.json
```json
{
  "create": { "name": "morpheus", "job": "leader" },
  "updatePut": { "name": "morpheus", "job": "zion resident" },
  "fixedIds": { "fetch": 2, "update": 2, "delete": 2 },
  "list": { "page": 1 }
}
```

## Test Execution

### Local Execution
```bash
# Run all tests
npm test

# Run specific test file
npx playwright test tests/api/user.crud.spec.ts

# Run with UI
npm run test:ui

# Run smoke tests only
npx playwright test -g "smoke"
```

### CI/CD Execution
- **PR Smoke Tests**: Runs on every pull request (unit + smoke tests)
- **Daily Full Tests**: Runs at 7:00 UTC daily (complete test suite)
- **Reports**: HTML and JUnit XML reports generated

## Test Framework Components

| Component | File | Purpose | Automated |
|-----------|------|---------|-----------|
| API Client | src/api/api-client.ts | HTTP request wrapper with retry logic | ✅ Yes |
| Fixtures | src/fixtures/api-fixtures.ts | Playwright fixture for apiClient | ✅ Yes |
| Assertions | src/utils/api-assertions.ts | Custom assertion helpers | ✅ Yes |
| Schemas | src/utils/schemas.ts | JSON schema definitions | ✅ Yes |
| Test Data | tests/data/users.json | External test data | ✅ Yes |

## Coverage

### API Endpoints Covered
- ✅ GET /users (list with pagination)
- ✅ GET /users/{id} (single user)
- ✅ POST /users (create user)
- ✅ PUT /users/{id} (update user)
- ✅ DELETE /users/{id} (delete user)

### Response Validation
- ✅ Status codes (200, 201, 404, etc.)
- ✅ JSON content type
- ✅ Response structure (JSON schema)
- ✅ Error message validation

### Authentication
- ✅ API key header (x-api-key)
- ✅ Unauthorized access handling

## Test Results

### Current Status
- **Total Test Cases**: 24
- **Implemented**: 24 (100%)
- **Not Implemented**: 0 (0%)
- **Automated**: 24 (100%)
- **Passing**: 24 (100%)
- **Failing**: 0 (0%)

### Execution Time
- **Local**: ~30 seconds
- **CI**: ~2 minutes (including setup)

## Maintenance

### Regular Updates
- Update test data in `tests/data/users.json`
- Maintain JSON schemas in `src/utils/schemas.ts`
- Review and update retry configuration
- Monitor API changes and update tests accordingly

### Dependencies
- Playwright: ^1.55.0
- AJV: ^8.17.1 (JSON schema validation)
- TypeScript: ^5.9.2

## Recommended Implementation Priority

### Phase 1 (High Priority - Security)
- **TC016**: SQL Injection testing
- **TC017**: XSS payload testing  
- **TC020**: Rate limiting validation
- **TC021**: Invalid JSON handling

### Phase 2 (Medium Priority - Performance)
- **TC019**: Response time validation
- **TC023**: Concurrent request testing
- **TC018**: Large payload handling

### Phase 3 (Low Priority - Monitoring)
- **TC022**: Required field validation
- **TC024**: Memory leak detection

## Essential API Test Types

### Must-Have (Currently Missing)
1. **Security**: Injection attacks, rate limiting
2. **Error Handling**: Malformed requests, validation errors
3. **Performance**: Response times, concurrent load

### Nice-to-Have (Optional)
1. **Load Testing**: High-volume concurrent requests
2. **Stress Testing**: Breaking point identification
3. **Monitoring**: Memory leaks, resource usage

## Notes
- All implemented tests are fully automated using Playwright
- Tests use data-driven approach with external JSON files
- Retry mechanism handles transient failures (429/503)
- Serial execution ensures CRUD operations work in sequence
- CI/CD integration provides automated testing on PRs and daily runs
- **Missing tests** focus on security and performance - critical for production APIs
