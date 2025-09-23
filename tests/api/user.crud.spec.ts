import { test, expect } from '../../src/fixtures/api-fixtures';
import data from '../data/users.json';
import { expectOk, expectJson, expectFailure } from '../../src/utils/api-assertions';

type User = {
  id: string | number;
  name?: string; // reqres create returns name/job; fetch returns first_name/last_name/email
  job?: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  [key: string]: any;
};

// function randomEmail(prefix = 'user'): string {
//   const suffix = Math.random().toString(36).slice(2, 8);
//   return `${prefix}.${suffix}@example.com`;
// }

test.describe.serial('User CRUD', () => {
  let userId: string | number | undefined;

  test('create user', async ({ apiClient }) => {
    const createPayload = data.create;
    const createRes = await apiClient.post('/users', createPayload, {
      headers: { 'Content-Type': 'application/json' },
    });
    await expectOk(createRes, [200, 201]);
    const created = await expectJson<User>(createRes);
    expect(created.id).toBeTruthy();
    expect(created.name).toBe(createPayload.name);
    expect(created.job).toBe(createPayload.job);
    userId = created.id;
  });

  test('fetch user', async ({ apiClient }) => {
    const fetchRes = await apiClient.get(`/users/${data.fixedIds.fetch}`);
    await expectOk(fetchRes, 200);
    const fetched = await expectJson<{ data: User }>(fetchRes);
    expect(fetched.data.id).toBe(data.fixedIds.fetch);
  });

  test('update user (PUT)', async ({ apiClient }) => {
    const updatePayload = { name: 'morpheus', job: 'zion resident' };
    const updateRes = await apiClient.put(`/users/2`, updatePayload, {
      headers: { 'Content-Type': 'application/json' },
    });
    await expectOk(updateRes, [200]);
    const updated = await expectJson<User>(updateRes);
    expect(updated.name).toBe(updatePayload.name);
    expect(updated.job).toBe(updatePayload.job);
  });

  test('delete user', async ({ apiClient }) => {
    if (!userId) throw new Error('No userId available to delete');
    const deleteRes = await apiClient.delete(`/users/${userId}`);
    await expectOk(deleteRes, [200, 204]);
    const fetchAfterDeleteRes = await apiClient.get(`/users/${userId}`);
    // reqres returns 404 for user not found
    await expectFailure(fetchAfterDeleteRes, { status: [404] });
  });
});

test.describe('Users list', () => {
  test('GET /users?page=1 lists users', async ({ apiClient }) => {
    const res = await apiClient.get('/users', { params: { page: data.list.page } });
    await expectOk(res, 200);
    const body = await expectJson<{ page: number; data: User[] }>(res);
    expect(body.page).toBe(data.list.page);
    expect(Array.isArray(body.data)).toBeTruthy();
  });
});


