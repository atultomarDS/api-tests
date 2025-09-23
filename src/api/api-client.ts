import { APIRequestContext, APIResponse } from '@playwright/test';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface RequestOptions {
  headers?: Record<string, string>;
  params?: Record<string, string | number | boolean | null | undefined>;
  data?: unknown;
  timeoutMs?: number;
}

export class ApiClient {
  private readonly request: APIRequestContext;
  private readonly baseURL?: string;
  private readonly retryMax: number;
  private readonly retryBaseMs: number;

  constructor(request: APIRequestContext, baseURL?: string) {
    this.request = request;
    this.baseURL = baseURL;
    const envRetryMax = Number(process.env.API_RETRY_MAX);
    const envRetryBase = Number(process.env.API_RETRY_BASE_MS);
    this.retryMax = Number.isFinite(envRetryMax) && envRetryMax >= 0 ? envRetryMax : 2;
    this.retryBaseMs = Number.isFinite(envRetryBase) && envRetryBase >= 0 ? envRetryBase : 300;
  }

  url(path: string): string {
    if (/^https?:\/\//i.test(path)) return path;
    if (!this.baseURL) return path;
    const trimmedBase = this.baseURL.replace(/\/$/, '');
    const trimmedPath = path.replace(/^\//, '');
    return `${trimmedBase}/${trimmedPath}`;
  }

  private withQuery(url: string, params?: RequestOptions['params']): string {
    if (!params) return url;
    const query = Object.entries(params)
      .filter(([, v]) => v !== undefined && v !== null)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
      .join('&');
    if (!query) return url;
    return url.includes('?') ? `${url}&${query}` : `${url}?${query}`;
  }

  private mergeHeaders(headers?: Record<string, string>): Record<string, string> | undefined {
    if (!headers) return undefined;
    // Normalize header keys to preserve case-insensitive matching
    const normalized: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      normalized[key] = value;
    }
    return normalized;
  }

  private async doRequestOnce(method: HttpMethod, url: string, options: RequestOptions): Promise<APIResponse> {
    const headers = this.mergeHeaders(options.headers);
    const timeout = options.timeoutMs;
    switch (method) {
      case 'GET':
        return this.request.get(url, { headers, timeout });
      case 'DELETE':
        return this.request.delete(url, { headers, timeout });
      case 'POST':
        return this.request.post(url, { headers, data: options.data, timeout });
      case 'PUT':
        return this.request.put(url, { headers, data: options.data, timeout });
      case 'PATCH':
        return this.request.patch(url, { headers, data: options.data, timeout });
      default:
        throw new Error(`Unsupported method: ${method}`);
    }
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  async requestMethod(method: HttpMethod, path: string, options: RequestOptions = {}): Promise<APIResponse> {
    const url = this.withQuery(this.url(path), options.params);
    let lastResponse: APIResponse | undefined;
    for (let attempt = 0; attempt <= this.retryMax; attempt++) {
      const response = await this.doRequestOnce(method, url, options);
      const status = response.status();
      if (status !== 429 && status !== 503) {
        return response;
      }
      lastResponse = response;
      if (attempt < this.retryMax) {
        const delay = this.retryBaseMs * Math.pow(2, attempt);
        await this.sleep(delay);
        continue;
      }
      return response;
    }
    // Should not reach here, but TypeScript needs a return.
    if (!lastResponse) {
      throw new Error('Request failed without response');
    }
    return lastResponse;
  }

  get(path: string, options?: RequestOptions) {
    return this.requestMethod('GET', path, options);
  }
  delete(path: string, options?: RequestOptions) {
    return this.requestMethod('DELETE', path, options);
  }
  post(path: string, data?: unknown, options?: Omit<RequestOptions, 'data'>) {
    return this.requestMethod('POST', path, { ...options, data });
  }
  put(path: string, data?: unknown, options?: Omit<RequestOptions, 'data'>) {
    return this.requestMethod('PUT', path, { ...options, data });
  }
  patch(path: string, data?: unknown, options?: Omit<RequestOptions, 'data'>) {
    return this.requestMethod('PATCH', path, { ...options, data });
  }
}

export default ApiClient;


