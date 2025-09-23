import { APIResponse, expect } from '@playwright/test';

export async function expectOk(response: APIResponse, status: number | number[] = 200) {
  const statuses = Array.isArray(status) ? status : [status];
  const actual = response.status();
  expect.soft(statuses, 'expected success status code').toContain(actual);
  expect.soft(response.ok(), `response not ok (status ${actual})`).toBeTruthy();
}

export async function expectJson<T = unknown>(response: APIResponse): Promise<T> {
  const contentType = response.headers()['content-type'] || '';
  expect.soft(contentType).toMatch(/application\/json/i);
  return (await response.json()) as T;
}

export async function expectFailure(
  response: APIResponse,
  opts: { status?: number | number[]; messageIncludes?: string | RegExp } = {}
) {
  const actual = response.status();
  const statuses = Array.isArray(opts.status) ? opts.status : opts.status ? [opts.status] : undefined;
  if (statuses) {
    expect.soft(statuses, 'expected failure status code').toContain(actual);
  } else {
    expect.soft(actual).toBeGreaterThanOrEqual(400);
  }

  // try to parse error body if JSON and optionally check message
  const contentType = response.headers()['content-type'] || '';
  if (opts.messageIncludes) {
    try {
      if (/application\/json/i.test(contentType)) {
        const body = (await response.json()) as any;
        const message: string = body?.message ?? body?.error ?? JSON.stringify(body);
        if (typeof opts.messageIncludes === 'string') {
          expect.soft(message).toContain(opts.messageIncludes);
        } else {
          expect.soft(message).toMatch(opts.messageIncludes);
        }
      } else {
        const text = await response.text();
        if (typeof opts.messageIncludes === 'string') {
          expect.soft(text).toContain(opts.messageIncludes);
        } else {
          expect.soft(text).toMatch(opts.messageIncludes);
        }
      }
    } catch {
      // ignore parse errors, still validate status
    }
  }
}


