import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testMatch: '*.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  expect: { timeout: 10000 },
  reporter: 'list',
  outputDir: '../test-results/web',
  use: {
    browserName: 'chromium',
    headless: true,
    viewport: { width: 390, height: 844 },
    contextOptions: { reducedMotion: 'reduce' },
    launchOptions: {
      executablePath: process.env.CF_BROWSER_EXECUTABLE || undefined,
      env: { ...process.env, ...(process.env.CF_BROWSER_FONTCONFIG ? { FONTCONFIG_FILE: process.env.CF_BROWSER_FONTCONFIG } : {}) },
    },
    screenshot: 'only-on-failure',
    trace: 'off', // Auth responses and fictional passkey credentials stay out of artifacts.
  },
});
