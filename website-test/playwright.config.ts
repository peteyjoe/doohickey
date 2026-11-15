import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  reporter: 'list',
  use: {
    ...devices['Desktop Chrome'],
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined },
  },
  webServer: {
    command: 'npm run build && node .output/server/index.mjs',
    url: 'http://127.0.0.1:3111',
    env: { PORT: '3111', HOST: '127.0.0.1' },
    timeout: 120000,
    reuseExistingServer: !process.env.CI,
  },
})
