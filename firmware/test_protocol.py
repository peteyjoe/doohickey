import struct
import serial

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

def request(req_id: int, cmd: int, payload: bytes = b"") -> tuple[int, int, bytes]:
    ser.write(cobs_encode(struct.pack("<HB", req_id, cmd) + payload))
    r = cobs_decode(ser.read_until(b"\x00")[:-1])
    rid, st = struct.unpack("<HB", r[:3])
    return rid, st, r[3:]

print("HELLO  ->", request(0x1234, 0x01))        # (0x1234, 0, b'\x01\x00\x01')
print("STATUS ->", request(2, 0x02))             # (2, 0, b'\x01\x00\x00')
print("ECHO   ->", request(3, 0x03, b"hi\x00!")) # (3, 0, b'hi\x00!')
print("UNKNOWN->", request(4, 0x7F))             # (4, 1, b'')
ser.write(cobs_encode(b"\x01"))                  # 1 byte: too short
print("SHORT  ->", cobs_decode(ser.read_until(b"\x00")[:-1]))  # b'\x00\x00\x02'