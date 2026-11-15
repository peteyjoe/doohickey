import { xchacha20poly1305 } from "@noble/ciphers/chacha";
const enc = new TextEncoder();
const concat = (...parts) => {
  const b = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    b.set(p, i);
    i += p.length;
  }
  return b;
};
const u32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const number = (b) =>
  new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true);
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
async function hmac(key, data) {
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
async function boxKey(master) {
  const k = await crypto.subtle.importKey("raw", master, "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: enc.encode("DOOHICKEY root keys v1"),
        info: enc.encode("DOOHICKEY stored secrets v1"),
      },
      k,
      256,
    ),
  );
}
async function seal(master, context, data) {
  const nonce = random(24);
  return concat(
    Uint8Array.of(1),
    nonce,
    xchacha20poly1305(await boxKey(master), nonce, enc.encode(context)).encrypt(
      data,
    ),
  );
}
async function open(master, context, data) {
  if (data[0] !== 1 || data.length < 41)
    throw Error("Invalid encrypted envelope");
  return xchacha20poly1305(
    await boxKey(master),
    data.slice(1, 25),
    enc.encode(context),
  ).decrypt(data.slice(25));
}
async function passwordKey(password, salt) {
  const k = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: 600000 },
      k,
      256,
    ),
  );
}
export function backupErrorMessage(e) {
  return e?.message || "Device operation failed";
}
export class BackupDevice {
  constructor(port) {
    this.port = port;
    this.pending = null;
    this.buffer = new Uint8Array();
    this.sequence = 0;
    this.queue = Promise.resolve();
  }
  async open() {
    await this.port.open({ baudRate: 115200 });
    await this.port.setSignals({ dataTerminalReady: true });
    this.reader = this.port.readable.getReader();
    this.reading = this.readLoop();
  }
  async readLoop() {
    try {
      while (true) {
        const { value, done } = await this.reader.read();
        if (done) break;
        this.buffer = concat(this.buffer, value);
        while (this.buffer.length >= 2) {
          const n = this.buffer[0] * 256 + this.buffer[1];
          if (!n || n > 1040) throw Error("Invalid device frame");
          if (this.buffer.length < n + 2) break;
          const frame = this.buffer.slice(2, n + 2);
          this.buffer = this.buffer.slice(n + 2);
          if (this.pending) {
            clearTimeout(this.pending.timer);
            this.pending.resolve(frame);
            this.pending = null;
          } else throw Error("Unexpected device response");
        }
      }
    } catch (e) {
      this.pending?.reject(e);
    } finally {
      this.pending = null;
      this.key?.fill(0);
      this.key = null;
      this.onLost?.();
    }
  }
  request(data) {
    const task = this.queue.then(() => this.send(data));
    this.queue = task.catch(() => {});
    return task;
  }
  async send(data) {
    if (this.failed) throw Error("Reconnect after transport failure");
    let timer;
    const response = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        this.failed = true;
        this.pending = null;
        this.key?.fill(0);
        reject(Error("Timed out; reconnect before retrying"));
      }, 45000);
      this.pending = { resolve, reject, timer };
    });
    response.catch(() => {});
    const writer = this.port.writable.getWriter();
    try {
      await writer.write(
        concat(Uint8Array.of(data.length >> 8, data.length & 255), data),
      );
    } catch (e) {
      clearTimeout(timer);
      this.pending = null;
      this.failed = true;
      throw e;
    } finally {
      writer.releaseLock();
    }
    const result = await response;
    if (new TextDecoder().decode(result.slice(0, 3)) === "ERR")
      throw Error(
        "Device denied the command. Check pairing, readiness and physical confirmation.",
      );
    return result;
  }
  async hello() {
    return JSON.parse(
      new TextDecoder().decode(await this.request(enc.encode("INFO"))),
    );
  }
  async status() {
    return this.hello();
  }
  async pair() {
    const key = random(32);
    try {
      await this.request(concat(enc.encode("PAIR"), key));
      return Array.from(key, (b) => b.toString(16).padStart(2, "0")).join("");
    } finally {
      key.fill(0);
    }
  }
  async authenticate(pairing) {
    if (!/^[a-fA-F0-9]{64}$/.test(pairing))
      throw Error("Enter the 64-character pairing key");
    const pair = Uint8Array.from(pairing.match(/../g), (h) => parseInt(h, 16));
    try {
      const challenge = await this.request(enc.encode("AUTH"));
      if (challenge.length !== 32) throw Error("Invalid challenge");
      this.key = await hmac(pair, concat(enc.encode("session"), challenge));
      const response = await this.request(
        concat(enc.encode("PROVE"), await hmac(pair, challenge)),
      );
      const plain = await open(this.key, "serial device v1", response.slice(1));
      if (
        number(plain) !== 0 ||
        new TextDecoder().decode(plain.slice(4)) !== "OK"
      )
        throw Error("Session authentication failed");
      this.sequence = 0;
    } catch (e) {
      this.key?.fill(0);
      this.key = null;
      throw e;
    } finally {
      pair.fill(0);
    }
  }
  async command(op, data = new Uint8Array()) {
    if (!this.key) throw Error("Pair and authenticate first");
    try {
      const seq = this.sequence;
      const response = await this.request(
        concat(
          Uint8Array.of(0x80),
          await seal(
            this.key,
            "serial client v1",
            concat(u32(seq), Uint8Array.of(op), data),
          ),
        ),
      );
      if (response[0] !== 0x80) throw Error("Unauthenticated response");
      const plain = await open(this.key, "serial device v1", response.slice(1));
      if (number(plain) !== seq + 1) throw Error("Invalid session sequence");
      this.sequence++;
      return plain.slice(4);
    } catch (e) {
      this.key?.fill(0);
      this.key = null;
      throw e;
    }
  }
  async exportBackup({ password }, onProgress = () => {}) {
    const salt = random(16);
    const key = await passwordKey(password, salt);
    try {
      await this.command(1, Uint8Array.of(1));
      const n = number(await this.command(2, key));
      if (n < 81 || n > 32809) throw Error("Invalid backup size");
      const blob = new Uint8Array(n + 24);
      blob.set(enc.encode("DOOHEXP1"));
      blob.set(salt, 8);
      for (let off = 0; off < n;) {
        const data = await this.command(3, u32(off));
        if (!data.length || off + data.length > n) throw Error("Invalid chunk");
        blob.set(data, 24 + off);
        off += data.length;
        onProgress(off, n);
      }
      return { blob, version: 1 };
    } finally {
      key.fill(0);
    }
  }
  async importBackup({ password, blob }, onProgress = () => {}) {
    if (
      blob.length < 105 ||
      blob.length > 32833 ||
      new TextDecoder().decode(blob.slice(0, 8)) !== "DOOHEXP1"
    )
      throw Error("Unsupported backup");
    const key = await passwordKey(password, blob.slice(8, 24));
    try {
      // Validate password locally without retaining decrypted contents.
      const plain = await open(key, "backup v1", blob.slice(24));
      plain.fill(0);
      await this.command(1, Uint8Array.of(2));
      await this.command(4, concat(u32(blob.length - 24), key));
      for (let off = 24; off < blob.length; off += 800) {
        await this.command(
          5,
          concat(u32(off - 24), blob.slice(off, off + 800)),
        );
        onProgress(Math.min(off + 800, blob.length), blob.length);
      }
      onProgress(blob.length, blob.length, "verifying");
      await this.command(6);
      this.key?.fill(0);
      this.key = null;
    } finally {
      key.fill(0);
    }
  }
  async close() {
    this.onLost = null;
    this.key?.fill(0);
    this.key = null;
    await this.reader?.cancel();
    await this.reading;
    this.reader?.releaseLock();
    await this.port.close();
  }
}

// Shared pure primitives also used by the host interoperability check.
export { seal as sealEnvelope, open as openEnvelope };
