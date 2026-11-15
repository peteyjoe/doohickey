// COBS framing, as described in the RP2350 Backup Protocol notes.
// On the wire a message is COBS-encode(message) followed by one 0x00 byte.

export function cobsEncode(data) {
  const out = [0] // out[codeIdx] gets patched with the block length
  let codeIdx = 0
  let code = 1
  for (const b of data) {
    if (b === 0) {
      out[codeIdx] = code
      codeIdx = out.length
      out.push(0)
      code = 1
    } else {
      out.push(b)
      code++
      if (code === 0xff) { // a full 254-byte block
        out[codeIdx] = code
        codeIdx = out.length
        out.push(0)
        code = 1
      }
    }
  }
  out[codeIdx] = code
  return Uint8Array.from(out)
}

export function cobsDecode(buf) {
  const out = []
  let i = 0
  while (i < buf.length) {
    const code = buf[i]
    if (code === 0) throw new Error('COBS: unexpected zero byte')
    if (i + code > buf.length) throw new Error('COBS: frame is truncated')
    for (let j = 1; j < code; j++) out.push(buf[i + j])
    i += code
    if (code !== 0xff && i < buf.length) out.push(0) // a short block means a zero followed
  }
  return Uint8Array.from(out)
}