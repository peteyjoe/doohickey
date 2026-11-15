import { encodeFrame, FrameDecoder } from './serialProtocol.ts'

// Minimal structural types keep the app independent of browser-specific DOM
// declarations. All actual I/O uses the native navigator.serial implementation.
export interface SerialPort extends EventTarget {
  readable: ReadableStream<Uint8Array> | null
  writable: WritableStream<Uint8Array> | null
  open(options: { baudRate: number, bufferSize: number }): Promise<void>
  close(): Promise<void>
  setSignals(signals: { dataTerminalReady: boolean, requestToSend: boolean }): Promise<void>
  getInfo(): { usbVendorId?: number, usbProductId?: number }
}
export interface SerialApi extends EventTarget {
  requestPort(options?: { filters: { usbVendorId: number, usbProductId: number }[] }): Promise<SerialPort>
}
export type ConnectionState = 'disconnected' | 'selecting' | 'connecting' | 'connected' | 'disconnecting'
export interface Response { payload: Uint8Array, text: string, elapsedMs: number }
export interface SerialEvents {
  state(state: ConnectionState): void
  event(message: string, error?: boolean): void
  frame(direction: 'tx' | 'rx', payload: Uint8Array, elapsedMs?: number): void
  bytes(direction: 'tx' | 'rx', count: number): void
  port(info: ReturnType<SerialPort['getInfo']> | null): void
  error(message: string): void
}

export class SerialConnection {
  private api: SerialApi
  private events: SerialEvents
  private state: ConnectionState = 'disconnected'
  private port: SerialPort | null = null
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null
  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null
  private opening: Promise<void> | null = null
  private reading: Promise<void> | null = null
  private writing: Promise<void> | null = null
  private closing: Promise<void> | null = null
  private generation = 0
  private disposed = false
  private decoder = new FrameDecoder()
  private frameTimer: ReturnType<typeof setTimeout> | null = null
  private pending: {
    resolve(value: Response): void
    reject(error: Error): void
    timer: ReturnType<typeof setTimeout>
    started: number
  } | null = null
  private responseTimeoutMs: number

  constructor(api: SerialApi, events: SerialEvents, responseTimeoutMs = 3000) {
    this.api = api
    this.events = events
    this.responseTimeoutMs = responseTimeoutMs
    api.addEventListener('disconnect', this.onUnplug)
  }

  async connect(baudRate = 115200, showAllPorts = false): Promise<boolean> {
    if (this.disposed || this.state !== 'disconnected') return false
    const generation = ++this.generation
    this.setState('selecting')
    try {
      // Must stay directly in the click call chain, before any unrelated await.
      const port = await this.api.requestPort(showAllPorts ? undefined : {
        filters: [{ usbVendorId: 0xc0de, usbProductId: 0xd001 }],
      })
      if (generation !== this.generation) return false
      this.port = port
      this.setState('connecting')
      this.opening = (async () => {
        await port.open({ baudRate, bufferSize: 2048 })
        if (generation === this.generation) {
          await port.setSignals({ dataTerminalReady: true, requestToSend: false })
        }
      })()
      await this.opening
      if (generation !== this.generation) return false
      if (!port.readable || !port.writable) throw new Error('The port did not expose readable and writable streams.')
      this.decoder.reset()
      this.reader = port.readable.getReader()
      this.setState('connected')
      this.events.port(port.getInfo())
      this.events.event(`Connected at ${baudRate.toLocaleString('en-US')} baud. DTR asserted.`)
      this.reading = this.readLoop(this.reader, generation)
      return true
    }
    catch (error) {
      if (generation !== this.generation) return false
      if (error instanceof Error && error.name === 'NotFoundError' && !this.port) {
        this.events.event('Device selection cancelled.')
        this.setState('disconnected')
        return false
      }
      this.fail(error)
      if (this.closing) await this.closing
      return false
    }
  }

  request(payload: Uint8Array): Promise<Response> {
    if (this.state !== 'connected' || !this.port?.writable) return Promise.reject(new Error('Connect a device first.'))
    if (this.pending || this.writing) return Promise.reject(new Error('Wait for the current request to finish.'))
    let frame: Uint8Array
    try { frame = encodeFrame(payload) }
    catch (error) { return Promise.reject(error) }
    let writer: WritableStreamDefaultWriter<Uint8Array>
    try { writer = this.port.writable.getWriter() }
    catch (error) { this.fail(error); return Promise.reject(error) }
    const generation = this.generation
    return new Promise<Response>((resolve, reject) => {
      this.pending = {
        resolve, reject, started: performance.now(),
        timer: setTimeout(() => this.fail(new Error('No response within 3 seconds. Reconnect to avoid matching a late response to another request.')), this.responseTimeoutMs),
      }
      this.writer = writer
      this.events.frame('tx', payload.slice())
      this.writing = (async () => {
        try {
          await writer.write(frame)
          if (generation === this.generation) this.events.bytes('tx', frame.length)
        }
        catch (error) { if (generation === this.generation) this.fail(error) }
        finally {
          writer.releaseLock()
          if (this.writer === writer) this.writer = null
          this.writing = null
        }
      })()
    })
  }

  async disconnect(message = 'Disconnected.'): Promise<void> {
    if (this.closing) return this.closing
    ++this.generation
    this.setState('disconnecting')
    this.rejectPending(new Error('Connection closed.'))
    this.clearFrameTimer()
    this.decoder.reset()
    this.closing = (async () => {
      await this.opening?.catch(() => {})
      await Promise.allSettled([this.reader?.cancel(), this.writer?.abort()])
      await Promise.allSettled([this.reading, this.writing])
      const port = this.port
      if (port) {
        try { await port.setSignals({ dataTerminalReady: false, requestToSend: false }) } catch { /* unplugged */ }
        try { await port.close() } catch { /* already closed / physically removed */ }
      }
      this.port = null
      this.reader = null
      this.writer = null
      this.opening = null
      this.reading = null
      this.writing = null
      this.events.port(null)
      this.setState('disconnected')
      this.events.event(message)
    })().finally(() => { this.closing = null })
    return this.closing
  }

  async dispose(): Promise<void> {
    this.disposed = true
    this.api.removeEventListener('disconnect', this.onUnplug)
    await this.disconnect()
  }

  private setState(state: ConnectionState): void { this.state = state; this.events.state(state) }

  private onUnplug = (event: Event): void => {
    const port = (event as Event & { port?: SerialPort }).port ?? event.target
    if (port === this.port && !this.closing) this.fail(new Error('Device unplugged. Reconnect the USB cable and connect again.'))
  }

  private async readLoop(reader: ReadableStreamDefaultReader<Uint8Array>, generation: number): Promise<void> {
    try {
      while (generation === this.generation) {
        const { value, done } = await reader.read()
        if (generation !== this.generation) break
        if (done) throw new Error('The serial stream closed. Reconnect the device.')
        if (!value) continue
        this.events.bytes('rx', value.length)
        for (const payload of this.decoder.push(value, performance.now())) {
          this.receive(payload)
          if (generation !== this.generation) break
        }
        if (generation !== this.generation) break
        this.armFrameTimer()
      }
    }
    catch (error) { if (generation === this.generation) this.fail(error) }
    finally { reader.releaseLock(); if (this.reader === reader) this.reader = null }
  }

  private receive(payload: Uint8Array): void {
    const text = new TextDecoder().decode(payload)
    const pending = this.pending
    const elapsedMs = pending ? performance.now() - pending.started : undefined
    this.events.frame('rx', payload, elapsedMs)
    if (/^ERR (?:FRAME_TIMEOUT|INVALID_FRAME)/.test(text)) {
      this.fail(new Error(`${text}. Reconnect to reset the firmware's framing.`))
      return
    }
    if (pending) {
      clearTimeout(pending.timer)
      this.pending = null
      pending.resolve({ payload, text, elapsedMs: elapsedMs! })
    }
  }

  private armFrameTimer(): void {
    this.clearFrameTimer()
    const deadline = this.decoder.deadline
    if (deadline === null) return
    this.frameTimer = setTimeout(() => {
      this.frameTimer = null
      try {
        this.decoder.checkTimeout(performance.now())
        this.armFrameTimer() // Re-arm if the browser woke just before the deadline.
      }
      catch (error) { this.fail(error) }
    }, Math.max(1, Math.ceil(deadline - performance.now())))
  }

  private clearFrameTimer(): void { if (this.frameTimer) clearTimeout(this.frameTimer); this.frameTimer = null }
  private rejectPending(error: Error): void {
    if (!this.pending) return
    clearTimeout(this.pending.timer)
    this.pending.reject(error)
    this.pending = null
  }
  private fail(error: unknown): void {
    if (this.closing) return
    const message = error instanceof Error ? error.message : String(error)
    this.events.error(message)
    this.events.event(message, true)
    this.rejectPending(new Error(message))
    void this.disconnect('Connection released.').catch(() => {})
  }
}
