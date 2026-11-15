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


def check_ctap(device):
    """Exercise the development discovery profile using independent wire fixtures."""
    nonce = os.urandom(8)
    send_hid(device, 0xFFFFFFFF, 0x06, nonce)
    response = receive_hid(device, 0xFFFFFFFF, 0x06)
    if len(response) != 17 or response[:8] != nonce or response[12] != 2:
        raise RuntimeError("invalid INIT response")
    channel = struct.unpack(">I", response[8:12])[0]
    if channel in (0, 0xFFFFFFFF) or response[16] != 0x0C:
        raise RuntimeError("unexpected channel/capabilities")
    payload = bytes(range(200))
    send_hid(device, channel, 0x01, payload)
    if receive_hid(device, channel, 0x01) != payload:
        raise RuntimeError("fragmented PING mismatch")

    # Status OK and canonical GetInfo map, including no advertised PIN/UV or
    # extensions. This is a fixed development profile, not FIDO conformance.
    expected_info = bytes.fromhex(
        "00 a5 01 81 68 4649444f5f325f30 03 50 444f4f4849434b45592d444556303031"
        " 04 a3 62 726b f4 62 7570 f4 64 706c6174 f4 05 19 0400 09 81 63 757362"
    )
    assertion = b"\x02\xa2\x01\x6bexample.com\x02\x58\x20" + bytes(32)
    # A valid unknown member makes the CBOR request span several HID reports.
    fragmented_assertion = b"\x02\xa3" + assertion[2:] + b"\x18\x63\x59\x01\x00" + bytes(range(256))
    checks = [
        (b"\x04", expected_info),
        (b"\x04\xa0", b"\x03"),  # Unexpected parameters: InvalidLength.
        (b"\x01\xa2\x01\x00\x01\x01", b"\x12"),  # Duplicate key.
        (b"\x01\xa0", b"\x14"),  # MissingParameter.
        (b"\x01\xf6", b"\x11"),  # CborUnexpectedType.
        (b"\x01\xa1\x18\x63\x81\x81\x81\x81\x00", b"\x12"),  # Five levels.
        (b"\x01\xa1\x18\x63\x98\x21" + bytes(33), b"\x39"),  # Collection bound.
        (b"\x01\xa1\x18\x63\xc0\x00", b"\x12"),  # Tag in unknown field.
        (b"\xff", b"\x01"),  # InvalidCommand.
        (assertion, b"\x01"),  # Valid request, credential handler not implemented.
        (fragmented_assertion, b"\x01"),
        (b"\x04", expected_info),  # Recovery after malformed/unsupported inputs.
    ]
    for request, expected in checks:
        send_hid(device, channel, 0x10, request)
        response = receive_hid(device, channel, 0x10)
        if response != expected:
            raise RuntimeError(f"CTAP command {request[0]:02x}: unexpected response {response.hex()}")
    print("HID: INIT, fragmented PING, GetInfo, bounded decoding, error responses and recovery passed")


def check_hid(vid, pid):
    import hid
    devices = [d for d in hid.enumerate(vid, pid)
               if d.get("usage_page") == 0xF1D0 and d.get("usage") == 1]
    if not devices:
        raise RuntimeError("FIDO HID interface not found; check IDs and hidraw permissions")
    device = hid.device()
    try:
        device.open_path(devices[0]["path"])
        check_ctap(device)
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
