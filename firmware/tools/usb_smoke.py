#!/usr/bin/env python3
"""On-device composite USB test. Uses hidapi and optionally pyserial; no writes to flash/OTP."""
import argparse
import json
import os
import struct
import time


def reports(channel, command, payload):
    if len(payload) > 1024:
        raise ValueError("message exceeds firmware transport limit")
    first = struct.pack(">IBH", channel, command | 0x80, len(payload)) + payload[:57]
    yield first.ljust(64, b"\0")
    for sequence, offset in enumerate(range(57, len(payload), 59)):
        yield (struct.pack(">IB", channel, sequence) + payload[offset:offset + 59]).ljust(64, b"\0")


def send_hid(device, channel, command, payload):
    for packet in reports(channel, command, payload):
        # hidapi requires the report-ID byte even when the device has no IDs.
        device.write(b"\0" + packet)


def receive_hid(device, channel, command):
    deadline = time.monotonic() + 3
    expected_sequence = 0
    payload = None
    length = 0
    while time.monotonic() < deadline:
        packet = bytes(device.read(64, timeout_ms=100))
        if not packet:
            continue
        if len(packet) != 64:
            raise RuntimeError("short HID report")
        if struct.unpack(">I", packet[:4])[0] != channel:
            continue
        if packet[4] & 0x80:
            if packet[4] == 0xBF:
                raise RuntimeError(f"CTAPHID error: 0x{packet[7]:02x}")
            if packet[4] == 0xBB:  # Keepalive, not a final response.
                continue
            if packet[4] != command | 0x80 or payload is not None:
                raise RuntimeError("unexpected HID response")
            length = struct.unpack(">H", packet[5:7])[0]
            if length > 1024:
                raise RuntimeError("oversized HID response")
            payload = bytearray(packet[7:])
        else:
            if payload is None or packet[4] != expected_sequence:
                raise RuntimeError("invalid HID continuation sequence")
            expected_sequence += 1
            payload.extend(packet[5:])
        if payload is not None and len(payload) >= length:
            return bytes(payload[:length])
    raise TimeoutError("HID response timed out")


def check_hid(vid, pid):
    import hid
    devices = [d for d in hid.enumerate(vid, pid)
               if d.get("usage_page") == 0xF1D0 and d.get("usage") == 1]
    if not devices:
        raise RuntimeError("FIDO HID interface not found; check IDs and hidraw permissions")
    device = hid.device()
    try:
        device.open_path(devices[0]["path"])
        nonce = os.urandom(8)
        send_hid(device, 0xFFFFFFFF, 0x06, nonce)
        response = receive_hid(device, 0xFFFFFFFF, 0x06)
        if len(response) < 17 or response[:8] != nonce or response[12] != 2:
            raise RuntimeError("invalid INIT response")
        channel = struct.unpack(">I", response[8:12])[0]
        if channel in (0, 0xFFFFFFFF) or response[16] != 0x0C:
            raise RuntimeError("unexpected channel/capabilities")
        payload = bytes(range(200))
        send_hid(device, channel, 0x01, payload)
        if receive_hid(device, channel, 0x01) != payload:
            raise RuntimeError("fragmented PING mismatch")
        send_hid(device, channel, 0x10, b"\x04")
        response = receive_hid(device, channel, 0x10)
        if response != b"\x27":
            raise RuntimeError("expected OperationDenied from the unfinished CTAP backend")
        print("HID: INIT, fragmented PING, and explicit CTAP backend denial passed")
    finally:
        device.close()


def read_exact(port, count):
    data = bytearray()
    deadline = time.monotonic() + 3
    while len(data) < count and time.monotonic() < deadline:
        data.extend(port.read(count - len(data)))
    if len(data) != count:
        raise TimeoutError("CDC response timed out")
    return bytes(data)


def check_serial(name):
    import serial
    with serial.Serial(name, 115200, timeout=0.25, write_timeout=2) as port:
        port.dtr = True
        port.reset_input_buffer()
        port.write(b"\0\x04INFO")
        length = struct.unpack(">H", read_exact(port, 2))[0]
        if not 1 <= length <= 1040:
            raise RuntimeError("invalid CDC response length")
        info = json.loads(read_exact(port, length))
        if info.get("product") != "DOOHICKEY" or info.get("flash_bytes") not in (4194304, 16777216):
            raise RuntimeError("unexpected device information")
        print("CDC:", json.dumps(info, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vid", type=lambda value: int(value, 0), default=0xC0DE)
    parser.add_argument("--pid", type=lambda value: int(value, 0), default=0xD001)
    parser.add_argument("--serial", help="CDC port, e.g. /dev/ttyACM0, /dev/cu.usbmodem..., or COM5")
    parser.add_argument("--skip-hid", action="store_true", help="test only the supplied serial port")
    args = parser.parse_args()
    if args.skip_hid and not args.serial:
        parser.error("--skip-hid requires --serial")
    if not args.skip_hid:
        check_hid(args.vid, args.pid)
    if args.serial:
        check_serial(args.serial)


if __name__ == "__main__":
    main()
