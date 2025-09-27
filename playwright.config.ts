import { defineConfig } from '@playwright/test';
import * as dotenv from 'dotenv';
import * as path from 'path';

// Determine environment from command line or default to reqres
const environment = process.env.TEST_ENV || 'reqres';

// Load environment-specific .env file
const envFile = environment === 'iron' ? '.env.iron' : '.env';
dotenv.config({ path: path.resolve(__dirname, envFile) });

const baseURL = process.env.BASE_URL || (environment === 'iron' ? 'https://api.ironmcb.com' : 'https://reqres.in/api');

export default defineConfig({
  testDir: 'tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'reports/html', open: 'never' }],
    ['junit', { outputFile: 'reports/junit/results.xml' }]
  ],
  use: {
    baseURL,
    extraHTTPHeaders: {
      // Only send Authorization if explicitly enabled (avoid 401s on public APIs like reqres)
      ...((process.env.API_TOKEN && process.env.USE_AUTH === 'true')
        ? { Authorization: `Bearer ${process.env.API_TOKEN}` }
        : {}),
      // Support reqres (or other) API key via env
      ...(process.env.X_API_KEY ? { 'x-api-key': process.env.X_API_KEY } : {}),
    },
  },
});
