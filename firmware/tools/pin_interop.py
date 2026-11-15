#!/usr/bin/env python3
"""Independent Yubico ClientPIN test against the host-only Rust simulator.
Usage: python tools/pin_interop.py target/x86_64-unknown-linux-gnu/debug/examples/ctap_simulator
Never accesses a physical authenticator or sets a real device PIN.
"""
import subprocess
import sys
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.hid import CAPABILITY


class Device:
    capabilities = CAPABILITY.CBOR

    def __init__(self, executable):
        self.process = subprocess.Popen([executable], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def exchange(self, line):
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()
        response = self.process.stdout.readline()
        if not response:
            raise RuntimeError("simulator exited unexpectedly")
        return bytes.fromhex(response.strip())

    def call(self, command, data=b"", event=None, on_keepalive=None):
        return self.exchange(data.hex())


device = Device(sys.argv[1])
try:
    ctap = Ctap2(device)
    client = ClientPin(ctap)
    assert client.protocol.VERSION == 2
    assert ctap.info.options["clientPin"] is False
    client.set_pin("123456")
    assert ctap.get_info().options["clientPin"] is True
    assert client.get_pin_retries()[0] == 8
    rp = "example.com"
    token = client.get_pin_token("123456", ClientPin.PERMISSION.MAKE_CREDENTIAL, rp)
    tag = client.protocol.authenticate(token, bytes(32))
    registration = ctap.make_credential(bytes(32), {"id": rp}, {"id": b"test"},
                                      [{"type": "public-key", "alg": -7}], pin_uv_param=tag, pin_uv_protocol=2)
    assert registration.auth_data.is_user_verified()
    credential = registration.auth_data.credential_data
    token = client.get_pin_token("123456", ClientPin.PERMISSION.GET_ASSERTION, rp)
    tag = client.protocol.authenticate(token, bytes([9]) * 32)
    result = ctap.get_assertion(rp, bytes([9]) * 32, [{"type": "public-key", "id": credential.credential_id}],
                                pin_uv_param=tag, pin_uv_protocol=2)
    result.verify(bytes([9]) * 32, credential.public_key)
    assert result.auth_data.is_user_verified()
    client.change_pin("123456", "654321")
    device.exchange("REBOOT")
    try:
        client.get_pin_token("123456")
        raise AssertionError("old PIN accepted")
    except CtapError as error:
        assert error.code == 0x31
    assert client.get_pin_retries()[0] == 7
    assert len(client.get_pin_token("654321")) == 32  # Legacy subcommand 5.
    assert client.get_pin_retries()[0] == 8
    print("Independent python-fido2: set/change PIN, protocol 2, scoped UV make/get, signatures, reboot, retries and legacy token passed")
finally:
    device.process.terminate()
    device.process.wait(timeout=5)
