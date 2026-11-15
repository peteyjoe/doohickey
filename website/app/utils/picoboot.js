const MAGIC = 0x431fd10b // marks every PICOBOOT command

export class Picoboot {
  constructor(device) { this.dev = device; this.token = 1 }

  async open() {
    const dev = this.dev
    await dev.open()
    if (dev.configuration === null) await dev.selectConfiguration(1)
    // PICOBOOT is the vendor-specific interface (class 0xff), find it and its two endpoints
    for (const iface of dev.configuration.interfaces) {
      const alt = iface.alternates[0]
      if (alt.interfaceClass === 0xff) {
        this.iface = iface.interfaceNumber
        for (const ep of alt.endpoints) {
          if (ep.direction === 'out') this.epOut = ep.endpointNumber
          else this.epIn = ep.endpointNumber
        }
      }
    }
    if (this.iface === undefined) throw new Error('PICOBOOT interface not found')
    await dev.claimInterface(this.iface)
    // control request 0x41 = reset the interface to a clean state
    await dev.controlTransferOut({ requestType: 'vendor', recipient: 'interface', request: 0x41, value: 0, index: this.iface })
  }

  // builds + sends one 32-byte command, then the data phase, then the ack
  async cmd(id, argBytes, args, dataOut = null) {
    const buf = new ArrayBuffer(32)
    const v = new DataView(buf)
    v.setUint32(0, MAGIC, true)
    v.setUint32(4, this.token++, true)         // unique id for this command
    v.setUint8(8, id)                          // which command
    v.setUint8(9, argBytes)                    // how many bytes of args are used
    v.setUint32(12, dataOut ? dataOut.byteLength : 0, true) // data length that follows
    args.forEach((a, i) => v.setUint32(16 + i * 4, a, true))
    await this.dev.transferOut(this.epOut, buf)
    if (dataOut) await this.dev.transferOut(this.epOut, dataOut)
    // ack = zero-length packet; commands with no read data are acked on the IN side
    await this.dev.transferIn(this.epIn, 64)
  }

  // control request 0x42 = ask the board what happened (0 = OK), handy for debugging
  async status() {
    const r = await this.dev.controlTransferIn({ requestType: 'vendor', recipient: 'interface', request: 0x42, value: 0, index: this.iface }, 16)
    return r.data.getUint32(4, true)
  }

  exclusive() { return this.cmd(0x01, 1, [2]) }               // 2 = exclusive + eject drive
  erase(addr, size) { return this.cmd(0x03, 8, [addr, size]) }
  write(addr, data) { return this.cmd(0x05, 8, [addr, data.byteLength], data) }
  reboot(isRp2350) {
    return isRp2350
      ? this.cmd(0x0a, 16, [0, 100, 0, 0]) // RP2350: REBOOT2, normal boot after 100ms
      : this.cmd(0x02, 12, [0, 0, 100])    // RP2040: REBOOT (pc, sp, delay)
  }

  async flash(blocks, onProgress) {
    await this.exclusive()
    // erase each 4096-byte sector the firmware touches (once each)
    const sectors = new Set(blocks.map(b => Math.floor(b.addr / 4096) * 4096))
    for (const s of [...sectors].sort((a, b) => a - b)) await this.erase(s, 4096)
    // write the 256-byte pages in address order
    const sorted = [...blocks].sort((a, b) => a.addr - b.addr)
    for (let i = 0; i < sorted.length; i++) {
      if (sorted[i].data.length !== 256) throw new Error('Unexpected block size ' + sorted[i].data.length)
      await this.write(sorted[i].addr, sorted[i].data)
      onProgress?.(i + 1, sorted.length)
    }
  }
}