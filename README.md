# API Tests

Short, focused Playwright API test suite with helpers, fixtures, retries and schema validation.

## Setup
1. Install dependencies: `npm i`
2. (Optional) Install browsers/tools: `npx playwright install --with-deps | cat`
3. Create `.env` from example: `cp env.example .env`

## .env
- BASE_URL: Base URL for your API under test.
- API_TOKEN: Optional bearer token for Authorization.
- REQRES_BASE_URL: Base URL for reqres tests (default `https://reqres.in/api`).
- API_RETRY_MAX: Max retries for 429/503 (default `2`).
- API_RETRY_BASE_MS: Base delay ms for exponential backoff (default `300`).

Example:
```
BASE_URL=https://api.example.com
API_TOKEN=
REQRES_BASE_URL=https://reqres.in/api
API_RETRY_MAX=2
API_RETRY_BASE_MS=300
```

## Run tests
- Full suite: `npm test`
- UI mode: `npm run test:ui`
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
