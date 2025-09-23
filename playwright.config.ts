import { defineConfig } from '@playwright/test';
import * as dotenv from 'dotenv';
import * as path from 'path';

// Load environment variables from .env if present
dotenv.config({ path: path.resolve(__dirname, '.env') });

const baseURL = process.env.BASE_URL || 'https://reqres.in/api';

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
      ...(process.env.API_TOKEN ? { Authorization: `Bearer ${process.env.API_TOKEN}` } : {}),
      // Support reqres (or other) API key via env
      ...(process.env.X_API_KEY ? { 'x-api-key': process.env.X_API_KEY } : {}),
    },
  },
});
