#!/usr/bin/env python3
"""Independent python-fido2 credential test. Registration writes one test credential.

Save the public fixture outside the repository; reuse it after a firmware update.
Requires fido2 (2.x). No private keys are exported. Real UP is required unless
--silent is selected for an assertion (preflight only, not WebAuthn login).
"""
import argparse
import json
from getpass import getpass
from fido2.ctap2.pin import ClientPin
import os
from pathlib import Path
from threading import Event, Timer

from fido2.attestation import PackedAttestation
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.webauthn import AttestedCredentialData, CollectedClientData

RP = "doohickey.test"


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["register", "authenticate"])
    parser.add_argument("--state", required=True, type=Path, help="public credential fixture JSON")
    parser.add_argument("--silent", action="store_true", help="assertion without UP (preflight only)")
    parser.add_argument("--pin", action="store_true", help="prompt privately for the configured PIN")
    parser.add_argument("--resident", action="store_true", help="create a discoverable credential during registration")
    args = parser.parse_args()
    if args.operation == "register" and (args.silent or args.state.exists()):
        parser.error("registration requires a new state path and physical presence")
    devices = list(CtapHidDevice.list_devices())
    selected = [d for d in devices if d.descriptor.vid == 0xC0DE and d.descriptor.pid == 0xD001]
    check(len(selected) == 1, "Connect exactly one DOOHICKEY native USB device")
    device = selected[0]
    event = Event()
    timer = Timer(45, event.set)
    timer.daemon = True
    notified = False

    def keepalive(status):
        nonlocal notified
        if status == 2 and not notified:
            print("Press and release BOOTSEL now (GPIO 25 LED flashes).", flush=True)
            notified = True

    try:
        ctap = Ctap2(device)  # Strict independent canonical CBOR decoding.
        check(ctap.info.options.get("up") is True, "Operational credential profile not ready")
        pin_args = {}
        if args.pin:
            helper = ClientPin(ctap)
            permission = ClientPin.PERMISSION.MAKE_CREDENTIAL if args.operation == "register" else ClientPin.PERMISSION.GET_ASSERTION
            grant = helper.get_pin_token(getpass("Device PIN: "), permission, RP)
            # The authenticator verifies HMAC over this operation's client hash.
            pin_args = {"pin_uv_protocol": 2}
        timer.start()
        if args.operation == "register":
            client = CollectedClientData.create(
                type="webauthn.create", challenge=os.urandom(32), origin=f"https://{RP}"
            )
            if args.pin: pin_args["pin_uv_param"] = helper.protocol.authenticate(grant, client.hash)
            result = ctap.make_credential(
                client.hash, {"id": RP, "name": "DOOHICKEY test"},
                {"id": os.urandom(16), "name": "test", "displayName": "Test account"},
                [{"type": "public-key", "alg": -7}], options={"rk": args.resident, "uv": False},
                event=event, on_keepalive=keepalive, **pin_args,
            )
            check(result.fmt == "packed", "Expected packed self-attestation")
            PackedAttestation().verify(result.att_stmt, result.auth_data, client.hash)
            auth = result.auth_data
            check(auth.is_user_present() and auth.is_user_verified() == args.pin, "Unexpected UP/UV flags")
            check(auth.rp_id_hash == __import__("hashlib").sha256(RP.encode()).digest(), "RP binding failed")
            check(auth.counter == 0, "Unexpected initial signature count")
            credential = auth.credential_data
            check(credential is not None and len(credential.credential_id) == 60, "Invalid credential ID")
            data = {"format": "DOOHICKEY credential test v1", "rp_id": RP,
                    "credential_data": bytes(credential).hex(), "counter": 0, "discoverable": args.resident}
            # Exclusive creation avoids overwriting the only copy of an older ID.
            with args.state.open("x") as output:
                json.dump(data, output, indent=2)
            print("Registration and independent self-attestation verification passed; public fixture saved.")
        else:
            data = json.loads(args.state.read_text())
            check(data["format"] == "DOOHICKEY credential test v1" and data["rp_id"] == RP, "Wrong fixture")
            credential = AttestedCredentialData(bytes.fromhex(data["credential_data"]))
            client = CollectedClientData.create(
                type="webauthn.get", challenge=os.urandom(32), origin=f"https://{RP}"
            )
            if args.pin: pin_args["pin_uv_param"] = helper.protocol.authenticate(grant, client.hash)
            result = ctap.get_assertion(
                RP, client.hash, [{"type": "public-key", "id": credential.credential_id}],
                options={"up": not args.silent}, event=event, on_keepalive=keepalive, **pin_args,
            )
            check(result.credential["id"] == credential.credential_id, "Wrong credential returned")
            result.verify(client.hash, credential.public_key)
            auth = result.auth_data
            check(auth.rp_id_hash == __import__("hashlib").sha256(RP.encode()).digest(), "RP binding failed")
            check(auth.is_user_present() == (not args.silent) and auth.is_user_verified() == args.pin, "Unexpected UP/UV")
            check(auth.counter > data["counter"], "Signature counter did not advance across reopen/update")
            check(result.user is None, "Non-discoverable assertion leaked user data")
            data["counter"] = auth.counter
            temporary = args.state.with_name(args.state.name + ".tmp")
            with temporary.open("x") as output:
                json.dump(data, output, indent=2)
            temporary.replace(args.state)
            print(f"Assertion signature verified with the original public key; counter={auth.counter}, UP={auth.is_user_present()}.")
    finally:
        timer.cancel()
        for item in devices:
            item.close()


if __name__ == "__main__":
    main()
