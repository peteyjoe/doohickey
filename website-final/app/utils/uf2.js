// Reject the entire image before any erase; never silently skip invalid blocks.
export function parseUf2(buffer) {
  if (!buffer.byteLength || buffer.byteLength % 512)
    throw Error("Invalid UF2 length");
  const v = new DataView(buffer),
    blocks = [],
    addresses = new Set(),
    count = buffer.byteLength / 512;
  for (let off = 0; off < buffer.byteLength; off += 512) {
    if (
      v.getUint32(off, true) !== 0x0a324655 ||
      v.getUint32(off + 4, true) !== 0x9e5d5157 ||
      v.getUint32(off + 508, true) !== 0x0ab16f30
    )
      throw Error("Invalid UF2 block");
    const flags = v.getUint32(off + 8, true),
      addr = v.getUint32(off + 12, true),
      size = v.getUint32(off + 16, true),
      family = v.getUint32(off + 28, true);
    if (
      flags !== 0x2000 ||
      family !== 0xe48bff59 ||
      size !== 256 ||
      addr % 256 ||
      addr < 0x10000000 ||
      addr + size > 0x10300000 ||
      addresses.has(addr) ||
      v.getUint32(off + 20, true) !== off / 512 ||
      v.getUint32(off + 24, true) !== count
    )
      throw Error("Unsupported, duplicate, or unsafe UF2 block");
    addresses.add(addr);
    blocks.push({
      addr,
      data: new Uint8Array(buffer.slice(off + 32, off + 32 + size)),
    });
  }
  return blocks;
}
