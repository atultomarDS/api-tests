import { test, expect } from '../../src/fixtures/api-fixtures';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { userSchema } from '../../src/utils/schemas';

test.describe('User schema validation (reqres.in)', () => {
  test('GET /users/2 matches user schema', async ({ apiClient }) => {
    // Fetch base URL from environment variable or config, and use it here
    const baseUrl = process.env.REQRES_BASE_URL || 'https://reqres.in/api';
    const res = await apiClient.get(`${baseUrl}/users/2`);
    await expect(res.ok()).toBeTruthy();
    const json = await res.json();

    // reqres wraps user object in { data: {...}, support: {...} }
    const user = json.data;

    const ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(ajv);
    const validate = ajv.compile(userSchema as any);
    const valid = validate(user);

    if (!valid) {
      const errors = validate.errors?.map(e => `${e.instancePath || '/'} ${e.message}`).join('\n');
      // Use Playwright expect for final assertion
      expect(valid, `Schema validation failed:\n${errors}`).toBeTruthy();
    } else {
      expect(valid).toBeTruthy();
    }
  });
});


