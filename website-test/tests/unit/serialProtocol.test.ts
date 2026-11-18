import assert from 'node:assert/strict'
import { test } from 'node:test'
import { encodeFrame, FrameDecoder, INFO_PAYLOAD, MAX_FRAME_SIZE, parseDeviceInfo, parseHex, toHex } from '../../app/utils/serialProtocol.ts'

test('INFO matches the firmware wire format; length counts UTF-8 bytes', () => {
  assert.equal(toHex(encodeFrame(INFO_PAYLOAD)), '00 04 49 4e 46 4f')
  assert.equal(toHex(encodeFrame(new TextEncoder().encode('é'))), '00 02 c3 a9')
})

test('encoder enforces the firmware size limits', () => {
  assert.throws(() => encodeFrame(new Uint8Array()), /1–1040/)
  assert.throws(() => encodeFrame(new Uint8Array(1041)), /1–1040/)
  assert.deepEqual(encodeFrame(new Uint8Array(MAX_FRAME_SIZE)).slice(0, 2), Uint8Array.of(4, 16))
})

test('decoder handles every possible split of a response', () => {
  const frame = encodeFrame(INFO_PAYLOAD)
  for (let split = 0; split <= frame.length; split++) {
    const decoder = new FrameDecoder()
    const decoded = [...decoder.push(frame.slice(0, split), 10), ...decoder.push(frame.slice(split), 11)]
    assert.deepEqual(decoded, [INFO_PAYLOAD])
    assert.equal(decoder.deadline, null)
  }
})

test('decoder handles coalesced frames and a maximum-length frame byte by byte', () => {
  const decoder = new FrameDecoder()
  const frame = encodeFrame(INFO_PAYLOAD)
  assert.deepEqual(decoder.push(new Uint8Array([...frame, ...frame]), 1), [INFO_PAYLOAD, INFO_PAYLOAD])
  const payload = new Uint8Array(MAX_FRAME_SIZE).fill(0xab)
  const result: Uint8Array[] = []
  for (const byte of encodeFrame(payload)) result.push(...decoder.push(Uint8Array.of(byte), 2))
  assert.deepEqual(result, [payload])
})

test('invalid headers quarantine the decoder until explicitly reset', () => {
  for (const header of [Uint8Array.of(0, 0), Uint8Array.of(4, 17), Uint8Array.of(255, 255)]) {
    const decoder = new FrameDecoder()
    assert.throws(() => decoder.push(header, 1), /Invalid response length/)
    assert.throws(() => decoder.push(encodeFrame(INFO_PAYLOAD), 2), /Framing is invalid/)
    decoder.reset()
    assert.deepEqual(decoder.push(encodeFrame(INFO_PAYLOAD), 3), [INFO_PAYLOAD])
  }
})

test('partial-frame timeout starts at the first header byte and does not slide', () => {
  const decoder = new FrameDecoder()
  decoder.push(Uint8Array.of(0), 100)
  assert.equal(decoder.deadline, 2100)
  decoder.push(Uint8Array.of(4, 73), 2099)
  assert.equal(decoder.deadline, 2100)
  assert.throws(() => decoder.checkTimeout(2100), /timed out/)
  assert.throws(() => decoder.push(Uint8Array.of(78, 70, 79), 2101), /Framing is invalid/)
})

test('hex accepts whitespace and case, rejects incomplete or ambiguous input', () => {
  assert.deepEqual(parseHex('49 4E\n46\t4f'), INFO_PAYLOAD)
  assert.deepEqual(parseHex('494e464f'), INFO_PAYLOAD)
  for (const input of ['', ' ', '0', '4gg4', '0x49', '49,4e']) assert.throws(() => parseHex(input), /hexadecimal/)
})

test('INFO validates data before displaying device capabilities', () => {
  const info = { product: 'DOOHICKEY', firmware: '0.1.0', flash_bytes: 16777216, ctap_ready: false, authentication_ready: false, insecure_test_otp: true }
  assert.deepEqual(parseDeviceInfo(JSON.stringify(info)), info)
  assert.throws(() => parseDeviceInfo('ERR AUTH_UNAVAILABLE'), /invalid JSON/)
  for (const value of [null, [], {}, { ...info, flash_bytes: -1 }, { ...info, flash_bytes: 1.5 }, { ...info, ctap_ready: 'false' }]) {
    assert.throws(() => parseDeviceInfo(JSON.stringify(value)))
  }
})
