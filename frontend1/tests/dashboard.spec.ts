import { expect, test, type Page } from '@playwright/test'

const metrics = {
  processed_events: 0,
  alerts_generated: 0,
  events_per_second: 0,
  average_alert_latency_ms: 0,
  scenario: null,
  source_mode: 'idle',
  interface: null,
  status: 'idle',
  running: false,
  started_at: null,
  finished_at: null,
  threat_counts: {},
  error_count: 0,
  model_status: { available: false, version: 'rules-only' },
  appwrite_status: { enabled: false },
  ollama_status: { enabled: false, model: 'qwen2.5:3b-instruct', available: false },
}

async function mockBackendEndpoints(page: Page) {
  await page.route('**/api/scenarios', async route => {
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ scenarios: ['syn_flood'] }) })
  })
  await page.route('**/api/metrics', async route => {
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(metrics) })
  })
  await page.route('**/api/live/interfaces', async route => {
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ interfaces: ['lo', 'eth0'] }) })
  })
  await page.route('**/api/alerts?limit=100', async route => {
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ alerts: [] }) })
  })
  await page.route('**/api/incidents?limit=100', async route => {
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ incidents: [] }) })
  })
  await page.route('**/api/replay/start', async route => {
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ status: 'started' }) })
  })
}

test('Google login entry point opens the local dashboard without credentials', async ({ page }) => {
  await page.route('**/api/auth/session', async route => {
    await route.fulfill({ contentType: 'application/json', body: 'null' })
  })
  await mockBackendEndpoints(page)
  await page.goto('/')

  await expect(page.getByText('Continue with Google')).toBeVisible()
  await expect(page.getByText('SIH26145 / THREAT INTELLIGENCE')).toBeVisible()
  await page.getByRole('button', { name: 'Continue with Google' }).click()
  await expect(page.getByRole('heading', { name: 'Network posture' })).toBeVisible()
})

test('authenticated dashboard loads scenarios and starts a replay', async ({ page }) => {
  await page.request.post('http://127.0.0.1:8000/api/replay/stop').catch(() => undefined)
  await page.route('**/api/auth/session', async route => {
    await route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ user: { name: 'Smoke Test', email: 'smoke@example.test' } }),
    })
  })
  await mockBackendEndpoints(page)
  await page.goto('/')

  if (await page.getByRole('button', { name: 'Continue with Google' }).isVisible()) {
    await page.getByRole('button', { name: 'Continue with Google' }).click()
  }
  await expect(page.getByRole('heading', { name: 'Network posture' })).toBeVisible()
  await expect(page.getByLabel('SCENARIO')).toHaveValue('syn_flood')

  const replayRequest = page.waitForRequest('**/api/replay/start')
  await page.getByRole('button', { name: 'Start replay' }).click()
  await expect(replayRequest).resolves.toBeTruthy()
})