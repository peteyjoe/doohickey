<template>
  <section class="demo" id="test">
    <div class="inner">
      <h2>Test your key</h2>
      <p>
        Register a test passkey, then sign a fresh challenge. Your browser
        handles the PIN and physical confirmation. Keep this page open between
        tests.
      </p>
      <button :disabled="busy" @click="register">Register test passkey</button
      ><button :disabled="busy || !credential" @click="authenticate">
        Test assertion
      </button>
      <p aria-live="polite">{{ status }}</p>
    </div>
  </section>
</template>
<script setup>
const status = ref("Ready to test on this origin.");
const busy = ref(false);
const credential = shallowRef(null);
const publicKey = shallowRef(null);
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
async function register() {
  busy.value = true;
  try {
    const challenge = random(32);
    const result = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: "DOOHICKEY alpha test", id: location.hostname },
        user: { id: random(32), name: "alpha-test", displayName: "Alpha test" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          authenticatorAttachment: "cross-platform",
          residentKey: "required",
          userVerification: "preferred",
        },
        attestation: "none",
        timeout: 60000,
      },
    });
    if (!result) throw Error("Registration cancelled");
    const data = JSON.parse(
      new TextDecoder().decode(result.response.clientDataJSON),
    );
    if (
      data.origin !== location.origin ||
      data.challenge !==
        btoa(String.fromCharCode(...challenge))
          .replaceAll("+", "-")
          .replaceAll("/", "_")
          .replace(/=+$/, "") ||
      data.type !== "webauthn.create"
    )
      throw Error("Unexpected registration origin");
    const spki = result.response.getPublicKey();
    if (!spki) throw Error("Browser cannot expose the public key");
    publicKey.value = await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    credential.value = new Uint8Array(result.rawId);
    status.value =
      "Registration completed. A real resident test credential is now stored.";
  } catch (e) {
    status.value = e.message;
  } finally {
    busy.value = false;
  }
}
function rawSignature(der) {
  const b = new Uint8Array(der);
  if (b[0] !== 48) throw Error("Invalid signature");
  let p = 2;
  const out = new Uint8Array(64);
  for (let i = 0; i < 2; i++) {
    if (b[p++] !== 2) throw Error("Invalid signature");
    const n = b[p++];
    let part = b.slice(p, p + n);
    p += n;
    while (part.length > 32 && part[0] === 0) part = part.slice(1);
    if (part.length > 32) throw Error("Invalid signature");
    out.set(part, i * 32 + 32 - part.length);
  }
  return out;
}
async function authenticate() {
  busy.value = true;
  try {
    const challenge = random(32);
    const result = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: location.hostname,
        allowCredentials: [{ type: "public-key", id: credential.value }],
        userVerification: "preferred",
        timeout: 60000,
      },
    });
    const data = JSON.parse(
      new TextDecoder().decode(result.response.clientDataJSON),
    );
    const expected = btoa(String.fromCharCode(...challenge))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/, "");
    if (
      data.origin !== location.origin ||
      data.challenge !== expected ||
      data.type !== "webauthn.get"
    )
      throw Error("Challenge/origin mismatch");
    const auth = new Uint8Array(result.response.authenticatorData);
    const rp = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(location.hostname),
      ),
    );
    if (!rp.every((b, i) => b === auth[i]) || (auth[32] & 1) !== 1)
      throw Error("RP, presence or UV verification failed");
    const hash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", result.response.clientDataJSON),
    );
    const message = new Uint8Array(auth.length + 32);
    message.set(auth);
    message.set(hash, auth.length);
    if (
      !(await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey.value,
        rawSignature(result.response.signature),
        message,
      ))
    )
      throw Error("Invalid signature");
    status.value = `Signature, fresh challenge, RP and physical presence verified. User verification: ${!!(auth[32] & 4)}.`;
  } catch (e) {
    status.value = e.message;
  } finally {
    busy.value = false;
  }
}
</script>
<style scoped>
section {
  padding: 5rem 2rem;
  background: var(--left);
  color: var(--cream);
}
.inner {
  max-width: 1100px;
  margin: auto;
}
h2 {
  font-size: 2rem;
}
p {
  line-height: 1.6;
  color: var(--muted);
}
button {
  margin: 1rem 1rem 0 0;
  padding: 0.8rem 1.3rem;
  background: var(--orange);
  border: 0;
  border-radius: 6px;
  cursor: pointer;
  color: var(--left);
}
button:disabled {
  opacity: 0.4;
}
</style>
