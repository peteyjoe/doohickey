// Talks to the DoohicKEY over Web Serial using the backup protocol.
// Sections marked "proposed" in the protocol notes (export/import) need new firmware.
// If the firmware doesn't know a command it answers UNKNOWN_CMD and the page says so.
import { cobsEncode, cobsDecode } from './cobs.js'

const CMD = {
  HELLO: 0x01, STATUS: 0x02, ECHO: 0x03,
  EXPORT_BEGIN: 0x20, EXPORT_CHUNK: 0x21, EXPORT_END: 0x22, ABORT: 0x2f,
  IMPORT_BEGIN: 0x30, IMPORT_CHUNK: 0x31, IMPORT_END: 0x32,
}

export const BACKUP_ERR = {
  UNKNOWN_CMD: 0x0001, BAD_REQUEST: 0x0002, BAD_PIN: 0x0004, LOCKED_OUT: 0x0005,
  BAD_SEQUENCE: 0x0010, NO_TRANSFER: 0x0011, BUSY: 0x0012, TOO_LARGE: 0x0013,
  BAD_BLOB: 0x0014, HASH_MISMATCH: 0x0015, USER_DENIED: 0x0016,
}

const MAX_MESSAGE = 512 // decoded message, header included, either direction
const MAX_BLOB = 16 * 1024 * 1024 // sanity cap so a buggy device can't make us allocate gigabytes
const enc = new TextEncoder()

export class DeviceError extends Error {
  constructor(code, details = '', attemptsLeft = null) {
    super(`device error 0x${code.toString(16).padStart(4, '0')}${details ? ': ' + details : ''}`)
    this.code = code // branch on this, never on the text
    this.details = details
    this.attemptsLeft = attemptsLeft
  }
}
export class DeviceTimeout extends Error {
  constructor() { super('The device did not answer in time') }
}

// 1-byte length + bytes, used for the PIN and the blob password
function field(bytes) {
  if (bytes.length > 255) throw new Error('That value is too long (255 bytes max)')
  return concat([Uint8Array.of(bytes.length), bytes])
}
function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let off = 0
  for (const p of parts) { out.set(p, off); off += p.length }
  return out
}
function u32(n) {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, true) // little-endian
  return b
}
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i])
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
}

export class BackupDevice {
  constructor(port) {
    this.port = port
    this.nextId = 1
    this.keepReading = false
    this.reader = null
    this.loop = null
    this.frame = []
    this.pending = null
    this.queue = Promise.resolve() // one request at a time
    this.onLost = null // called if the device goes away while we are connected
  }

  async open() {
    await this.port.open({ baudRate: 115200 }) // baud rate is ignored by the firmware
    try {
      await this.port.setSignals({ dataTerminalReady: true }) // without DTR the firmware ignores us
    } catch (e) {
      await this.port.close().catch(() => {})
      throw e
    }
    this.keepReading = true
    this.loop = this._readLoop()
  }

  // The notes describe a freeze caused by the outer loop restarting forever on Disconnect.
  // Fix: a keepReading flag, break when the reader says done, and close() waits for this loop.
  async _readLoop() {
    while (this.port.readable && this.keepReading) {
      this.reader = this.port.readable.getReader()
      let done = false
      try {
        while (true) {
          const r = await this.reader.read()
          if (r.done) { done = true; break }
          if (r.value) this._feed(r.value)
        }
      } catch (e) {
        this._fail(e) // non-fatal read error: fail the waiting request, keep going
      } finally {
        this.reader.releaseLock()
        this.reader = null
      }
      if (done) break
      await new Promise((r) => setTimeout(r, 50)) // never spin without yielding
    }
    if (this.keepReading) { // we did not ask for this: the device went away
      this.keepReading = false
      this._fail(new Error('The device disconnected'))
      this.onLost?.()
    }
  }

  async close() {
    this.keepReading = false
    try { await this.reader?.cancel() } catch {}
    await this.loop // wait until the read loop has released the stream
    try { await this.port.close() } catch {}
    this._fail(new Error('Disconnected'))
  }

  _feed(chunk) {
    for (const b of chunk) {
      if (b === 0) {
        if (this.frame.length) this._onFrame(Uint8Array.from(this.frame))
        this.frame = []
      } else if (this.frame.length < 2 * MAX_MESSAGE) {
        this.frame.push(b)
      }
    }
  }

  _onFrame(raw) {
    let msg = null
    try { msg = cobsDecode(raw) } catch {}
    // a frame the device could not decode comes back as plain text: "ERR ..."
    const asText = (bytes) => new TextDecoder().decode(bytes)
    for (const candidate of [msg, raw]) {
      if (candidate && asText(candidate).startsWith('ERR')) {
        this._fail(new Error('Device protocol error: ' + asText(candidate)))
        return
      }
    }
    if (!msg || msg.length < 3) return
    const id = msg[0] | (msg[1] << 8)
    if (this.pending && this.pending.id === id) {
      clearTimeout(this.pending.timer)
      const p = this.pending
      this.pending = null
      p.resolve(msg)
    } // replies with another id are stale (e.g. after a timeout) and are ignored
  }

  _fail(err) {
    if (!this.pending) return
    clearTimeout(this.pending.timer)
    const p = this.pending
    this.pending = null
    p.reject(err)
  }

  request(cmd, payload = new Uint8Array(0), { timeout = 2000 } = {}) {
    const p = this.queue.then(() => this._send(cmd, payload, timeout))
    this.queue = p.catch(() => {})
    return p
  }

  async _send(cmd, payload, timeout) {
    if (!this.keepReading || !this.port.writable) throw new Error('Not connected')
    const id = this.nextId
    this.nextId = (this.nextId + 1) & 0xffff
    const msg = concat([Uint8Array.of(id & 0xff, id >> 8, cmd), payload])
    if (msg.length > MAX_MESSAGE) throw new Error('Message is too big for the device')

    const reply = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending = null; reject(new DeviceTimeout()) }, timeout)
      this.pending = { id, resolve, reject, timer }
    })
    reply.catch(() => {}) // avoid an unhandled rejection if the write below throws first

    const writer = this.port.writable.getWriter()
    try {
      await writer.write(concat([cobsEncode(msg), Uint8Array.of(0)]))
    } catch (e) {
      this._fail(e)
      throw e
    } finally {
      writer.releaseLock()
    }

    const m = await reply
    const status = m[2]
    const body = m.subarray(3)
    if (status === 0) return body
    if (status === 2) throw new DeviceError(BACKUP_ERR.BAD_REQUEST) // old firmware: bad request
    if (body.length < 2) throw new DeviceError(BACKUP_ERR.UNKNOWN_CMD) // old firmware: unknown command
    const code = body[0] | (body[1] << 8)
    let i = 2
    let attemptsLeft = null
    if (code === BACKUP_ERR.BAD_PIN && body.length > 2) { attemptsLeft = body[2]; i = 3 }
    throw new DeviceError(code, new TextDecoder().decode(body.subarray(i)), attemptsLeft)
  }

  // exports may be retried with the same seq (the notes allow it), so retry on a timeout only
  async _chunkWithRetry(seq) {
    for (let attempt = 0; ; attempt++) {
      try { return await this.request(CMD.EXPORT_CHUNK, u32(seq)) }
      catch (e) { if (!(e instanceof DeviceTimeout) || attempt >= 2) throw e }
    }
  }

  async hello() {
    const b = await this.request(CMD.HELLO)
    return { major: b[0], minor: b[1] }
  }

  async status() {
    const b = await this.request(CMD.STATUS) // [locked][credential_count u16]; the locked byte may be dropped
    if (b.length >= 3) return { count: b[1] | (b[2] << 8) }
    if (b.length === 2) return { count: b[0] | (b[1] << 8) }
    return { count: null }
  }

  async abort() {
    try { await this.request(CMD.ABORT) } catch {}
  }

  // Device -> website. Returns { blob, version }. Needs a button press on the key.
  async exportBackup({ pin, password }, onProgress = () => {}) {
    // long timeout: the device waits for the button (30 s). Ours is longer so its USER_DENIED arrives first.
    const begin = await this.request(
      CMD.EXPORT_BEGIN,
      concat([field(enc.encode(pin)), field(enc.encode(password))]),
      { timeout: 40000 },
    )
    if (begin.length < 7) throw new Error('Unexpected reply from the device')
    const dv = new DataView(begin.buffer, begin.byteOffset, begin.byteLength)
    const total = dv.getUint32(0, true)
    const version = begin[6] // chunk size (bytes 4-5) is chosen by the firmware; we just read what comes back
    if (total === 0) throw new Error('The device reported an empty backup')
    if (total > MAX_BLOB) throw new DeviceError(BACKUP_ERR.TOO_LARGE)

    try {
      const blob = new Uint8Array(total)
      let got = 0
      let seq = 0
      onProgress(0, total)
      while (got < total) {
        const body = await this._chunkWithRetry(seq)
        if (body.length < 5) throw new Error('The device sent an empty chunk')
        const echoed = new DataView(body.buffer, body.byteOffset, 4).getUint32(0, true)
        if (echoed !== seq) throw new DeviceError(BACKUP_ERR.BAD_SEQUENCE)
        const data = body.subarray(4)
        if (got + data.length > total) throw new Error('The device sent more data than it announced')
        blob.set(data, got)
        got += data.length
        seq++
        onProgress(got, total)
      }
      const deviceHash = await this.request(CMD.EXPORT_END)
      if (!same(deviceHash, await sha256(blob))) throw new DeviceError(BACKUP_ERR.HASH_MISMATCH)
      return { blob, version }
    } catch (e) {
      await this.abort()
      throw e
    }
  }

  // Website -> device. Nothing is applied until IMPORT_END succeeds. No button press needed.
  async importBackup({ pin, password, blob }, onProgress = () => {}) {
    if (blob.length === 0 || blob.length > MAX_BLOB) throw new DeviceError(BACKUP_ERR.TOO_LARGE)
    const begin = await this.request(
      CMD.IMPORT_BEGIN,
      concat([field(enc.encode(pin)), field(enc.encode(password)), u32(blob.length), await sha256(blob)]),
    )
    if (begin.length < 2) throw new Error('Unexpected reply from the device')
    // 3 header bytes + 4 seq bytes leave 505 for data in a 512-byte message
    const chunkSize = Math.min(new DataView(begin.buffer, begin.byteOffset, begin.byteLength).getUint16(0, true), MAX_MESSAGE - 7)
    if (chunkSize < 1) throw new Error('The device gave an invalid chunk size')

    try {
      let seq = 0
      onProgress(0, blob.length, 'sending')
      for (let off = 0; off < blob.length; off += chunkSize) {
        await this.request(CMD.IMPORT_CHUNK, concat([u32(seq), blob.subarray(off, off + chunkSize)]))
        seq++
        onProgress(Math.min(off + chunkSize, blob.length), blob.length, 'sending')
      }
      onProgress(blob.length, blob.length, 'verifying')
      await this.request(CMD.IMPORT_END, new Uint8Array(0), { timeout: 40000 }) // device checks hash, decrypts, verifies
    } catch (e) {
      await this.abort()
      throw e
    }
  }
}

// Plain-English text for every error the page can hit.
export function backupErrorMessage(e) {
  if (e instanceof DeviceTimeout) return 'The key did not answer in time.'
  if (e instanceof DeviceError) {
    switch (e.code) {
      case BACKUP_ERR.UNKNOWN_CMD: return "This firmware doesn't support backup yet. Flash a version with backup support and try again."
      case BACKUP_ERR.BAD_REQUEST: return 'The key rejected the request as malformed.'
      case BACKUP_ERR.BAD_PIN: return e.attemptsLeft == null ? 'Wrong PIN.' : `Wrong PIN. ${e.attemptsLeft} attempt${e.attemptsLeft === 1 ? '' : 's'} left.`
      case BACKUP_ERR.LOCKED_OUT: return 'Too many wrong PINs. The key is locked out.'
      case BACKUP_ERR.BAD_SEQUENCE: return 'Data arrived out of order. Try again.'
      case BACKUP_ERR.NO_TRANSFER: return 'The key has no transfer in progress. Start again.'
      case BACKUP_ERR.BUSY: return 'The key is already in a transfer. Unplug it, plug it back in, and try again.'
      case BACKUP_ERR.TOO_LARGE: return 'The backup is too large for the key.'
      case BACKUP_ERR.BAD_BLOB: return "Couldn't open that backup. The password is wrong, the file is from an unsupported version, or it is damaged."
      case BACKUP_ERR.HASH_MISMATCH: return "The data didn't arrive intact. Try again."
      case BACKUP_ERR.USER_DENIED: return "The button wasn't pressed in time. Try again and press it when asked."
      default: return `The key returned an error (0x${e.code.toString(16).padStart(4, '0')}).`
    }
  }
  if (e?.name === 'NotFoundError') return 'No device selected.'
  if (e?.name === 'NetworkError' || e?.name === 'InvalidStateError') return "Couldn't open the port. Close any other program using the key (like a serial monitor) and try again."
  return e?.message || 'Something went wrong.'
}