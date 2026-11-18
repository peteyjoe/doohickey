# DOOHICKEY alpha website

The existing Nuxt landing-page design now includes firmware install/update,
serial setup/status, client pairing, encrypted backup/restore and a local
WebAuthn registration/assertion diagnostic.

```sh
npm ci
npm run dev
# Production:
npm run build
node .output/server/index.mjs
```

Use desktop Chrome/Edge on HTTPS or localhost. Web Serial and WebUSB require
explicit device selection; FIDO testing uses the browser's normal WebAuthn UI.
Public `INFO` is read-only. Pairing and export/restore require physical approval.
Save the downloaded client key privately. There is no server-side secret store.

Firmware files and `manifest.json` are generated from the matching source:

```sh
cd ../firmware
python3 tools/package_alpha.py
```

Ordinary images never provision OTP. The separate first-installation checkbox
selects an image that can irreversibly create/seal the OTP master root after
physical confirmation. Neither image activates secure boot. Confirm the board's
actual 4/16 MiB flash capacity before flashing. Firmware sectors are read back;
storage at/above 3 MiB is excluded.

Backups have a 32 KiB plaintext alpha limit. Restore replaces all credentials,
clears the target PIN and client pairing, and preserves its OTP keys. Pair again
and set a new FIDO PIN afterward. Restore can roll back signature counters or
clone credentials; this is experimental recovery, not FIDO certification.

See [protocol, threat model and operational guide](../docs/alpha-serial-and-web.md).
Hardware/browser qualification is still required before calling this a tested
working alpha. This implementation has not flashed or programmed a device.
