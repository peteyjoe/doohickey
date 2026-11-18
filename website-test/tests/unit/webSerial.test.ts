import assert from 'node:assert/strict'
import { test } from 'node:test'
import { setImmediate } from 'node:timers/promises'
import { encodeFrame, INFO_PAYLOAD } from '../../app/utils/serialProtocol.ts'
import { SerialConnection } from '../../app/utils/webSerial.ts'
import type { ConnectionState, SerialApi, SerialEvents, SerialPort } from '../../app/utils/webSerial.ts'

class FakePort extends EventTarget implements SerialPort {
  readable: ReadableStream<Uint8Array> | null = null
  writable: WritableStream<Uint8Array> | null = null
  controller!: ReadableStreamDefaultController<Uint8Array>
  writes: Uint8Array[] = []
  signals: boolean[] = []
  closed = 0
  openError: Error | null = null
  signalError: Error | null = null
  writeError: Error | null = null
  openingGate: Promise<void> | null = null
  onWrite: ((frame: Uint8Array) => void) | null = null
  options: { baudRate: number, bufferSize: number } | null = null

  async open(options: { baudRate: number, bufferSize: number }) {
    this.options = options
    await this.openingGate
    if (this.openError) throw this.openError
    this.readable = new ReadableStream({ start: controller => { this.controller = controller } })
    this.writable = new WritableStream<Uint8Array>({ write: frame => {
      if (this.writeError) throw this.writeError
      this.writes.push(frame.slice())
      this.onWrite?.(frame)
    } })
  }

  async setSignals(signals: { dataTerminalReady: boolean }) {
    if (this.signalError) throw this.signalError
    this.signals.push(signals.dataTerminalReady)
  }

  async close() {
    assert.equal(this.readable?.locked, false)
    assert.equal(this.writable?.locked, false)
    this.closed++
  }

  getInfo() { return { usbVendorId: 0xc0de, usbProductId: 0xd001 } }
  receive(text: string) { this.controller.enqueue(encodeFrame(new TextEncoder().encode(text))) }
}

class FakeApi extends EventTarget implements SerialApi {
  port = new FakePort()
  options: unknown
  selectionError: Error | null = null
  selectionGate: Promise<void> | null = null
  async requestPort(options?: Parameters<SerialApi['requestPort']>[0]) {
    this.options = options
    await this.selectionGate
    if (this.selectionError) throw this.selectionError
    return this.port
  }
  unplug() { this.dispatchEvent(Object.assign(new Event('disconnect'), { port: this.port })) }
}

function setup(timeout = 3000) {
  const api = new FakeApi()
  const states: ConnectionState[] = []
  const errors: string[] = []
  const frames: { direction: string, payload: Uint8Array }[] = []
  const events: SerialEvents = {
    state: state => { states.push(state) }, error: error => { errors.push(error) },
    frame: (direction, payload) => { frames.push({ direction, payload }) },
    event() {}, bytes() {}, port() {},
  }
  const client = new SerialConnection(api, events, timeout)
  return { client, api, states, errors, frames }
}

test('connect filters the development device, asserts DTR, and frames requests', async () => {
  const { client, api, states, frames } = setup()
  assert.equal(await client.connect(), true)
  assert.deepEqual(api.options, { filters: [{ usbVendorId: 0xc0de, usbProductId: 0xd001 }] })
  assert.deepEqual(api.port.signals, [true])
  const request = client.request(INFO_PAYLOAD)
  await setImmediate()
  assert.deepEqual(api.port.writes, [Uint8Array.of(0, 4, 73, 78, 70, 79)])
  const response = encodeFrame(new TextEncoder().encode('{"product":"DOOHICKEY"}'))
  api.port.controller.enqueue(response.slice(0, 1))
  api.port.controller.enqueue(response.slice(1, 5))
  api.port.controller.enqueue(response.slice(5))
  assert.equal((await request).text, '{"product":"DOOHICKEY"}')
  assert.deepEqual(frames.map(frame => frame.direction), ['tx', 'rx'])
  await client.dispose()
  assert.equal(states.at(-1), 'disconnected')
  assert.deepEqual(api.port.signals, [true, false])
  assert.equal(api.port.closed, 1)
})

test('all-port selection removes the filter and respects the baud rate', async () => {
  const { client, api } = setup()
  await client.connect(9600, true)
  assert.equal(api.options, undefined)
  assert.equal(api.port.options?.baudRate, 9600)
  await client.dispose()
})

test('only one request may be in flight; firmware rejection leaves INFO usable', async () => {
  const { client, api } = setup()
  await client.connect()
  const first = client.request(INFO_PAYLOAD)
  await assert.rejects(client.request(INFO_PAYLOAD), /current request/)
  await setImmediate()
  api.port.receive('ERR AUTH_UNAVAILABLE')
  assert.equal((await first).text, 'ERR AUTH_UNAVAILABLE')
  const second = client.request(INFO_PAYLOAD)
  await setImmediate()
  api.port.receive('OK')
  assert.equal((await second).text, 'OK')
  await client.dispose()
})

test('disconnect rejects a pending request, releases locks, and allows reconnect', async () => {
  const { client, api } = setup()
  await client.connect()
  const rejected = assert.rejects(client.request(INFO_PAYLOAD), /Connection closed/)
  await client.disconnect()
  await rejected
  assert.equal(api.port.closed, 1)
  assert.equal(await client.connect(), true)
  await client.dispose()
  assert.equal(api.port.closed, 2)
})

test('unplug rejects pending I/O and reports a recoverable connection error', async () => {
  const { client, api, errors, states } = setup()
  await client.connect()
  const rejected = assert.rejects(client.request(INFO_PAYLOAD), /unplugged/)
  api.unplug()
  await rejected
  await client.disconnect()
  assert.match(errors[0]!, /unplugged/)
  assert.equal(states.at(-1), 'disconnected')
  assert.equal(api.port.closed, 1)
  await client.dispose()
})

test('response timeout closes the session so a late reply cannot match a new request', async () => {
  const { client, api, states } = setup(20)
  await client.connect()
  await assert.rejects(client.request(INFO_PAYLOAD), /No response/)
  await client.disconnect()
  assert.equal(states.at(-1), 'disconnected')
  assert.equal(api.port.closed, 1)
  await assert.rejects(client.request(INFO_PAYLOAD), /Connect a device/)
  await client.dispose()
})

test('malformed frames and firmware framing errors close the session', async () => {
  for (const reply of [Uint8Array.of(0, 0), encodeFrame(new TextEncoder().encode('ERR FRAME_TIMEOUT')), encodeFrame(new TextEncoder().encode('ERR INVALID_FRAME'))]) {
    const { client, api } = setup()
    await client.connect()
    const rejected = assert.rejects(client.request(INFO_PAYLOAD), /Reconnect/)
    api.port.controller.enqueue(reply)
    await rejected
    await client.disconnect()
    assert.equal(api.port.closed, 1)
    await client.dispose()
  }
})

test('cancelled chooser is not a connection error', async () => {
  const { client, api, states, errors } = setup()
  api.selectionError = new DOMException('Cancelled', 'NotFoundError')
  assert.equal(await client.connect(), false)
  assert.equal(states.at(-1), 'disconnected')
  assert.deepEqual(errors, [])
  assert.equal(api.port.closed, 0)
  await client.dispose()
})

test('open, signal and write failures clean up the session', async () => {
  for (const field of ['openError', 'signalError', 'writeError'] as const) {
    const { client, api, errors, states } = setup()
    api.port[field] = new Error(`Failed: ${field}`)
    const connected = await client.connect()
    if (field === 'writeError') {
      assert.equal(connected, true)
      await assert.rejects(client.request(INFO_PAYLOAD), /writeError/)
      await client.disconnect()
    }
    else assert.equal(connected, false)
    assert.equal(states.at(-1), 'disconnected')
    assert.match(errors[0]!, new RegExp(field))
    // A failed open has no streams to unlock.
    if (field !== 'openError') assert.equal(api.port.closed, 1)
    await client.dispose()
  }
})

test('disposing while the picker is open never opens the selected port', async () => {
  const { client, api } = setup()
  let release!: () => void
  api.selectionGate = new Promise<void>(resolve => { release = resolve })
  const connecting = client.connect()
  await client.dispose()
  release()
  assert.equal(await connecting, false)
  assert.equal(api.port.options, null)
  assert.equal(await client.connect(), false)
})

test('disconnect during open waits for open, skips DTR assertion and closes the port', async () => {
  const { client, api } = setup()
  let release!: () => void
  api.port.openingGate = new Promise<void>(resolve => { release = resolve })
  const connecting = client.connect()
  await setImmediate()
  const disconnecting = client.disconnect()
  release()
  assert.equal(await connecting, false)
  await disconnecting
  assert.deepEqual(api.port.signals, [false])
  assert.equal(api.port.closed, 1)
  await client.dispose()
})
