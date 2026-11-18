/** Firmware wire format: u16 big-endian length, then 1..1040 payload bytes. */
export const MAX_FRAME_SIZE = 1040
export const FRAME_TIMEOUT_MS = 2000
export const INFO_PAYLOAD = new TextEncoder().encode('INFO')

export function encodeFrame(payload: Uint8Array): Uint8Array {
  if (payload.length === 0 || payload.length > MAX_FRAME_SIZE) {
    throw new Error(`Payload must contain 1–${MAX_FRAME_SIZE} bytes.`)
  }
  const frame = new Uint8Array(payload.length + 2)
  frame[0] = payload.length >>> 8
  frame[1] = payload.length & 0xff
  frame.set(payload, 2)
  return frame
}

export function parseHex(text: string): Uint8Array {
  const compact = text.replace(/\s/g, '')
  if (!/^(?:[0-9a-f]{2})+$/i.test(compact)) {
    throw new Error('Enter complete hexadecimal bytes, for example: 49 4e 46 4f.')
  }
  return Uint8Array.from(compact.match(/../g)!, byte => Number.parseInt(byte, 16))
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(' ')
}

/** Packet boundaries are irrelevant. Malformed input requires a new session. */
export class FrameDecoder {
  private buffer = new Uint8Array(MAX_FRAME_SIZE + 2)
  private used = 0
  private expected = 0
  private invalid = false
  private expires: number | null = null

  get deadline(): number | null { return this.expires }

  reset(): void {
    this.buffer.fill(0)
    this.used = 0
    this.expected = 0
    this.invalid = false
    this.expires = null
  }

  checkTimeout(now: number): void {
    if (this.invalid) throw new Error('Framing is invalid. Reconnect the device.')
    if (this.expires !== null && now >= this.expires) {
      this.fail('Incomplete response frame timed out. Reconnect the device.')
    }
  }

  push(chunk: Uint8Array, now: number): Uint8Array[] {
    this.checkTimeout(now)
    const frames: Uint8Array[] = []
    for (const byte of chunk) {
      if (this.used === 0) this.expires = now + FRAME_TIMEOUT_MS
      this.buffer[this.used++] = byte
      if (this.used === 2) {
        const length = this.buffer[0]! * 256 + this.buffer[1]!
        if (length === 0 || length > MAX_FRAME_SIZE) {
          this.fail(`Invalid response length (${length}). Reconnect the device.`)
        }
        this.expected = length + 2
      }
      if (this.expected > 0 && this.used === this.expected) {
        frames.push(this.buffer.slice(2, this.used))
        this.buffer.fill(0)
        this.used = 0
        this.expected = 0
        this.expires = null
      }
    }
    return frames
  }

  private fail(message: string): never {
    this.reset()
    this.invalid = true
    throw new Error(message)
  }
}

export interface DeviceInfo {
  product: string
  firmware: string
  flash_bytes: number
  ctap_ready: boolean
  authentication_ready: boolean
  insecure_test_otp: boolean
}

export function parseDeviceInfo(text: string): DeviceInfo {
  let value: unknown
  try { value = JSON.parse(text) }
  catch { throw new Error('INFO returned invalid JSON. Check that the selected port runs DOOHICKEY firmware.') }
  if (typeof value !== 'object' || value === null) throw new Error('Invalid device information.')
  const info = value as Record<string, unknown>
  if (typeof info.product !== 'string' || typeof info.firmware !== 'string'
    || typeof info.flash_bytes !== 'number' || !Number.isSafeInteger(info.flash_bytes) || info.flash_bytes <= 0
    || typeof info.ctap_ready !== 'boolean' || typeof info.authentication_ready !== 'boolean'
    || typeof info.insecure_test_otp !== 'boolean') {
    throw new Error('INFO response is missing expected firmware fields.')
  }
  return info as unknown as DeviceInfo
}
