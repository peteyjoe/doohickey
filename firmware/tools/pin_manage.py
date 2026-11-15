#!/usr/bin/env python3
"""Manage a physical DOOHICKEY PIN using python-fido2. PINs are prompted privately.
Setting/changing the PIN writes device state. status is read-only.
"""
import argparse
from getpass import getpass
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["status", "set", "change"])
    args = parser.parse_args()
    devices = list(CtapHidDevice.list_devices())
    try:
        matches = [d for d in devices if d.descriptor.vid == 0xc0de and d.descriptor.pid == 0xd001]
        if len(matches) != 1:
            raise RuntimeError("Connect exactly one DOOHICKEY native USB device")
        ctap = Ctap2(matches[0])
        helper = ClientPin(ctap)
        if args.operation == "status":
            retries, temporary = helper.get_pin_retries()
            print(f"PIN configured: {ctap.info.options.get('clientPin')}; attempts left: {retries}; temporary block: {bool(temporary)}")
            return
        current = getpass("Current PIN: ") if args.operation == "change" else None
        new = getpass("New PIN: ")
        if new != getpass("Confirm new PIN: "):
            raise ValueError("PINs differ; no device change made")
        if current is None:
            helper.set_pin(new)
        else:
            helper.change_pin(current, new)
        print("PIN updated successfully. Existing credentials are retained.")
    finally:
        for device in devices:
            device.close()


if __name__ == "__main__":
    main()
