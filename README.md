# API Tests

Short, focused Playwright API test suite with helpers, fixtures, retries and schema validation.

## Setup
1. Install dependencies: `npm i`
2. (Optional) Install browsers/tools: `npx playwright install --with-deps | cat`
3. Create `.env` from example: `cp env.example .env`

## .env Configuration

### For Reqres Tests (.env)
- BASE_URL: Base URL for your API under test.
- API_TOKEN: Optional bearer token for Authorization.
- REQRES_BASE_URL: Base URL for reqres tests (default `https://reqres.in/api`).
- X_API_KEY: API key for reqres (default `reqres-free-v1`).
- API_RETRY_MAX: Max retries for 429/503 (default `2`).
- API_RETRY_BASE_MS: Base delay ms for exponential backoff (default `300`).

### For Iron MCB Tests (.env.iron)
- BASE_URL: Iron MCB API base URL.
- API_TOKEN: Iron MCB bearer token.
- IRON_ENVIRONMENT: Environment (staging/production).
- IRON_CLIENT_ID: OAuth client ID.
- IRON_CLIENT_SECRET: OAuth client secret.
- IRON_TEST_CUSTOMER_ID: Test customer UUID.
- IRON_TEST_ACCOUNT_ID: Test account UUID.

Examples:
```bash
# Reqres .env
BASE_URL=https://reqres.in/api
X_API_KEY=reqres-free-v1

# Iron MCB .env.iron  
BASE_URL=https://api.ironmcb.com
API_TOKEN=your_iron_bearer_token
IRON_ENVIRONMENT=staging
```

## Run tests
- Full suite: `npm test`
- Reqres tests: `npm run test:reqres`
- Iron MCB tests: `npm run test:iron`
- UI mode: `npm run test:ui`
- UI Reqres: `npm run test:ui:reqres`
- UI Iron: `npm run test:ui:iron`
- Smoke subset:
  - by file: `npx playwright test tests/api/api.spec.ts`
  - by name: `npx playwright test -g "health|schema"`

## Reports
- HTML: `reports/html/index.html` (open via `npm run report`)
- JUnit: `reports/junit/results.xml`

## Notables
- Retries (429/503): configured via `API_RETRY_MAX` and `API_RETRY_BASE_MS`.
- Key files:
  - `src/api/api-client.ts` — API client wrapper with retries
  - `src/fixtures/api-fixtures.ts` — exposes `apiClient`
  - `src/utils/api-assertions.ts` — common assertions
  - `src/utils/schemas.ts` — JSON schemas
  - `tests/api/*` — CRUD and schema tests
