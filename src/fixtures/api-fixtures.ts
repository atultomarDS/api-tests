import { test as base, APIRequestContext } from '@playwright/test';
import { ApiClient } from '../api/api-client';

type ApiFixtures = {
  apiClient: ApiClient;
};

export const test = base.extend<ApiFixtures>({
  apiClient: async ({ request, baseURL }, use) => {
    const client = new ApiClient(request as APIRequestContext, baseURL);
    await use(client);
  },
});

export const expect = test.expect;


