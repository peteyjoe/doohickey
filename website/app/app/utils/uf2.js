// turns a .uf2 file into a list of { addr, data } chunks
export function parseUf2(buffer) {
  const view = new DataView(buffer)
  const blocks = []
  for (let off = 0; off + 512 <= buffer.byteLength; off += 512) {
    // every block starts and ends with magic numbers, skip anything that doesn't
    if (view.getUint32(off, true) !== 0x0A324655) continue
    if (view.getUint32(off + 4, true) !== 0x9E5D5157) continue
    if (view.getUint32(off + 508, true) !== 0x0AB16F30) continue
    const flags = view.getUint32(off + 8, true)
    const addr = view.getUint32(off + 12, true)   // where in flash this chunk goes
    const size = view.getUint32(off + 16, true)   // payload size (normally 256)
    const family = view.getUint32(off + 28, true) // which chip this block is for
    // flag 0x2000 = family field is valid. Only keep RP2040 / RP2350 flash blocks
    const ok = [0xE48BFF56, 0xE48BFF59, 0xE48BFF5A, 0xE48BFF5B]
    if ((flags & 0x2000) && !ok.includes(family)) continue
    blocks.push({ addr, data: new Uint8Array(buffer, off + 32, size) })
  }
  if (!blocks.length) throw new Error('No valid UF2 blocks found in that file')
  return blocks
}