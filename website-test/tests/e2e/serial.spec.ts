import { readFile } from 'node:fs/promises'
import { test, expect } from '@nuxt/test-utils/playwright'
import type { Page } from '@playwright/test'

test.use({ nuxt: { host: 'http://127.0.0.1:3111' } })

// Only tests replace navigator.serial. The application always uses real Web Serial.
declare global {
  interface Window {
    serialTest: {
      writes: number[][]
      signals: boolean[]
      malformed: boolean
      unplug(): void
    }
  }
}

async function mockSerial(page: Page) {
  await page.addInitScript(() => {
    const encoder = new TextEncoder()
    const state = { writes: [] as number[][], signals: [] as boolean[], malformed: false, unplug: () => {} }
    class Port extends EventTarget {
      readable: ReadableStream<Uint8Array> | null = null
      writable: WritableStream<Uint8Array> | null = null
      controller!: ReadableStreamDefaultController<Uint8Array>
      async open() {
        this.readable = new ReadableStream({ start: controller => { this.controller = controller } })
        this.writable = new WritableStream<Uint8Array>({ write: frame => {
          state.writes.push(Array.from(frame))
          if (!state.signals.at(-1)) throw new Error('DTR was not asserted')
          if (state.malformed) { this.controller.enqueue(Uint8Array.of(0, 0)); return }
          const length = frame[0]! * 256 + frame[1]!
          if (length !== frame.length - 2) throw new Error('Bad frame length')
          const command = new TextDecoder().decode(frame.slice(2))
          const payload = encoder.encode(command === 'INFO' ? JSON.stringify({
            product: 'DOOHICKEY', firmware: '0.1.0', flash_bytes: 16777216,
            ctap_ready: false, authentication_ready: false, insecure_test_otp: false,
          }) : 'ERR AUTH_UNAVAILABLE')
          const response = new Uint8Array(payload.length + 2)
          response[0] = payload.length >>> 8
          response[1] = payload.length & 255
          response.set(payload, 2)
          this.controller.enqueue(response.slice(0, 1))
          this.controller.enqueue(response.slice(1, 8))
          this.controller.enqueue(response.slice(8))
        } })
      }
      async close() {
        if (this.readable?.locked || this.writable?.locked) throw new Error('Leaked serial stream lock')
      }
      async setSignals(signals: { dataTerminalReady: boolean }) { state.signals.push(signals.dataTerminalReady) }
      getInfo() { return { usbVendorId: 0xc0de, usbProductId: 0xd001 } }
    }
    const port = new Port()
    const api = Object.assign(new EventTarget(), { requestPort: async () => port })
    state.unplug = () => api.dispatchEvent(Object.assign(new Event('disconnect'), { port }))
    window.serialTest = state
    Object.defineProperty(navigator, 'serial', { configurable: true, value: api })
  })
}

test('connects, reads real-format INFO, displays hex, exports and clears traffic', async ({ page, goto }) => {
  const pageErrors: string[] = []
  page.on('pageerror', error => pageErrors.push(error.message))
  await mockSerial(page)
  await goto('/')
  await expect(page.getByRole('button', { name: 'Connect device', exact: true })).toBeEnabled()
  await page.screenshot({ path: '/tmp/doohickey-serial-disconnected.png', fullPage: true })
  await page.getByRole('button', { name: 'Connect device', exact: true }).click()
  await expect(page.getByText('16 MiB', { exact: true })).toBeVisible()
  await expect(page.getByText('c0de:d001', { exact: true })).toBeVisible()
  await expect(page.getByRole('log').locator('time').first()).toHaveText(/^\d{2}:\d{2}:\d{2}\.\d{3}$/)
  expect(await page.evaluate(() => window.serialTest.writes)).toEqual([[0, 4, 73, 78, 70, 79]])
  expect(await page.evaluate(() => window.serialTest.signals)).toEqual([true])
  await page.locator('[aria-label="Traffic display"]').getByRole('button', { name: 'Hex', exact: true }).click()
  await expect(page.getByRole('log').getByText('00 04 49 4e 46 4f', { exact: true })).toBeVisible()
  await page.screenshot({ path: '/tmp/doohickey-serial-connected.png', fullPage: true })

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export log', exact: true }).click()
  const download = await downloadPromise
  const exported = JSON.parse(await readFile((await download.path())!, 'utf8'))
  expect(exported.entries.some((entry: { kind: string, text: string }) => entry.kind === 'tx' && entry.text === 'INFO')).toBe(true)
  await page.getByRole('button', { name: 'Clear log', exact: true }).click()
  await expect(page.getByText('Your connection, in plain sight.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Export log', exact: true })).toBeDisabled()
  await page.getByRole('button', { name: 'Disconnect device', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Connect device', exact: true })).toBeEnabled()
  expect(await page.evaluate(() => window.serialTest.signals)).toEqual([true, false])
  expect(pageErrors).toEqual([])
})

test('custom requests report firmware rejection; hex input validates and INFO still works', async ({ page, goto }) => {
  await mockSerial(page)
  await goto('/')
  await page.getByRole('button', { name: 'Connect device', exact: true }).click()
  await expect(page.getByText('16 MiB', { exact: true })).toBeVisible()
  await page.getByLabel('Send a test message', { exact: true }).fill('BACKUP')
  await page.getByRole('button', { name: 'Send message', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('ERR AUTH_UNAVAILABLE')
  await expect(page.getByRole('button', { name: 'Disconnect device', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Dismiss error', exact: true }).click()
  await page.locator('[aria-label="Payload format"]').getByRole('button', { name: 'Hex', exact: true }).click()
  await page.getByLabel('Send a test message', { exact: true }).fill('0')
  await expect(page.getByRole('button', { name: 'Send message', exact: true })).toBeDisabled()
  await expect(page.locator('#payload-help')).toContainText('complete hexadecimal bytes')
  await page.getByLabel('Send a test message', { exact: true }).fill('49 4e 46 4f')
  await page.getByRole('button', { name: 'Send message', exact: true }).click()
  await expect(page.getByRole('alert')).toHaveCount(0)
  await expect.poll(() => page.evaluate(() => window.serialTest.writes.length)).toBe(3)
})

test('unplug and malformed frames release the connection and allow reconnect', async ({ page, goto }) => {
  await mockSerial(page)
  await goto('/')
  await page.getByRole('button', { name: 'Connect device', exact: true }).click()
  await expect(page.getByText('16 MiB', { exact: true })).toBeVisible()
  await page.evaluate(() => window.serialTest.unplug())
  await expect(page.getByRole('alert')).toContainText('unplugged')
  await expect(page.getByRole('button', { name: 'Connect device', exact: true })).toBeEnabled()
  await page.getByRole('button', { name: 'Connect device', exact: true }).click()
  await expect(page.getByText('16 MiB', { exact: true })).toBeVisible()
  await page.evaluate(() => { window.serialTest.malformed = true })
  await page.getByRole('button', { name: 'Read device info', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Invalid response length')
  await expect(page.getByRole('button', { name: 'Connect device', exact: true })).toBeEnabled()
  expect(await page.evaluate(() => window.serialTest.signals)).toEqual([true, false, true, false])
})

test('unsupported browsers receive instructions with connection disabled', async ({ page, goto }) => {
  await page.addInitScript(() => Object.defineProperty(navigator, 'serial', { value: undefined }))
  await goto('/')
  await expect(page.getByText('This browser does not support Web Serial', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Connect device', exact: true })).toBeDisabled()
})

test('small screens fit without horizontal overflow', async ({ page, goto }) => {
  await mockSerial(page)
  await page.setViewportSize({ width: 375, height: 812 })
  await goto('/')
  await page.getByRole('button', { name: 'Connect device', exact: true }).click()
  await expect(page.getByText('16 MiB', { exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: '/tmp/doohickey-serial-mobile.png', fullPage: true })
})
