## DEPRECIATED SINCE WE AREN'T TESTING COB ANYMORE

import serial
import time

def cobs_encode(data: bytes) -> bytes:
    out, block = bytearray(), bytearray()
    for b in data:
        if b == 0:
            out.append(len(block) + 1); out += block; block.clear()
        else:
            block.append(b)
            if len(block) == 254:
                out.append(255); out += block; block.clear()
    out.append(len(block) + 1); out += block
    out.append(0)
    return bytes(out)

def cobs_decode(frame: bytes) -> bytes:  # frame without trailing 0x00
    out, i = bytearray(), 0
    while i < len(frame):
        code = frame[i]; i += 1
        out += frame[i:i + code - 1]; i += code - 1
        if code != 255 and i < len(frame):
            out.append(0)
    return bytes(out)

ser = serial.Serial("/dev/ttyACM0", 115200, timeout=1)  # opening asserts DTR

def roundtrip(payload: bytes) -> bytes:
    ser.write(cobs_encode(payload))
    reply = ser.read_until(b"\x00")
    return cobs_decode(reply[:-1])

cases = {
    "hello": b"hello",
    "single zero": b"\x00",
    "zeros": b"\x00\x00\x00",
    "mixed": b"a\x00b\x00\x00c",
    "254 nonzero": bytes([1]) * 254,
    "255 nonzero": bytes([1]) * 255,
    "300 bytes": bytes(range(1, 256)) + bytes(range(1, 46)),
    "all 512": bytes([i % 256 for i in range(512)]),
}
for name, p in cases.items():
    got = roundtrip(p)
    print(("PASS" if got == p else "FAIL"), name, len(p))

print("oversize ->", roundtrip(b"A" * 600))  # expect b'ERR overflow'
ser.write(b"\x05\x01\x02\x00")                 # malformed: code says 4 bytes follow, only 2
print("malformed ->", cobs_decode(ser.read_until(b"\x00")[:-1]))  # expect b'ERR bad frame'

# Two frames in one write -> two replies
ser.write(cobs_encode(b"one") + cobs_encode(b"two"))
print("coalesced ->", cobs_decode(ser.read_until(b"\x00")[:-1]),
                      cobs_decode(ser.read_until(b"\x00")[:-1]))  # expect b'one' b'two'

# One frame split across two writes, with a pause in between
f = cobs_encode(b"split me across writes")
ser.write(f[:5]); ser.flush(); time.sleep(0.2); ser.write(f[5:])
print("split ->", cobs_decode(ser.read_until(b"\x00")[:-1]))  # expect the original text

# Garbage, then a valid frame: the reader should resync at the delimiter
ser.write(b"\xff\xff\x00")
print("garbage ->", cobs_decode(ser.read_until(b"\x00")[:-1]))  # expect b'ERR bad frame'
print("after garbage ->", roundtrip(b"still alive"))