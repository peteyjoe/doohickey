#!/usr/bin/env python3
"""Validate a firmware-only ELF update; never access USB or program a device."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

FLASH_BASE = 0x10000000
STORAGE_OFFSET = 3 * 1024 * 1024


def check_image(image: bytes, flash_mb: int) -> dict:
    if len(image) < 52 or image[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected a 32-bit little-endian ELF")
    kind, machine = struct.unpack_from("<HH", image, 16)
    if (kind, machine) != (2, 40):
        raise ValueError("Expected an ARM executable")
    phoff = struct.unpack_from("<I", image, 28)[0]
    phsize, phcount = struct.unpack_from("<HH", image, 42)
    if phsize != 32 or not phcount or phoff + phsize * phcount > len(image):
        raise ValueError("Invalid program headers")
    segments = []
    descriptors = []
    for index in range(phcount):
        ptype, offset, _, address, size, memory_size, _, _ = struct.unpack_from(
            "<8I", image, phoff + index * phsize
        )
        if ptype != 1 or not size:
            continue
        if offset + size > len(image) or size > memory_size:
            raise ValueError("Invalid loadable segment")
        if not (FLASH_BASE <= address < address + size <= FLASH_BASE + STORAGE_OFFSET):
            raise ValueError("Loadable segment overlaps storage or lies outside firmware flash")
        segments.append({"offset": address - FLASH_BASE, "length": size})
        data = image[offset:offset + size]
        start = 0
        while (found := data.find(b"DOOHUPD1", start)) != -1:
            descriptors.append(data[found:found + 64])
            start = found + 8
    if not segments or len(descriptors) != 1 or len(descriptors[0]) != 64:
        raise ValueError("Missing or ambiguous embedded update descriptor")
    descriptor = descriptors[0]
    version_bytes = descriptor[8:40].rstrip(b"\0")
    version = version_bytes.decode("ascii")
    if version != "0.2.0" or descriptor[8:40] != version_bytes.ljust(32, b"\0"):
        raise ValueError("Unsupported firmware release")
    flash_size, storage_start = struct.unpack_from("<II", descriptor, 40)
    if flash_mb not in (4, 16) or flash_size != flash_mb * 1024 * 1024 or storage_start != STORAGE_OFFSET:
        raise ValueError("Image geometry does not match device")
    if any(descriptor[48:]):
        raise ValueError("Ordinary updates must not contain OTP provisioning/test features")
    return {
        "product": "DOOHICKEY", "version": version,
        "flash_bytes": flash_size, "storage_offset": storage_start,
        "sha256": hashlib.sha256(image).hexdigest(), "segments": segments,
        "signed": False, "update_mode": "firmware-only-single-slot",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--flash-mb", type=int, required=True, choices=(4, 16))
    args = parser.parse_args()
    try:
        result = check_image(args.elf.read_bytes(), args.flash_mb)
    except (ValueError, OSError, struct.error) as error:
        parser.exit(1, f"Update rejected: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
