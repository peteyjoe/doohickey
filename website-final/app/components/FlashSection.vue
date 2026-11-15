<template>
  <section id="flash" class="flash">
    <div class="inner">
      <div class="head">
        <h2>Flash your key</h2>
        <p class="lead">
          Put firmware on your DoohicKEY straight from the browser. No installs,
          no drivers. Works in Chrome or Edge.
        </p>
        <p class="tip">
          <span class="tip-dot" aria-hidden="true"></span>Hold the BOOTSEL
          button while you plug the board in.
        </p>
      </div>

      <div class="console">
        <ol class="steps">
          <!-- 1. connect -->
          <li class="step" :class="{ done: !!device }">
            <span class="num" aria-hidden="true">
              <svg
                v-if="device"
                width="16"
                height="16"
                viewBox="0 0 16 16"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path d="M3 8.5l3.2 3.2L13 4.8" />
              </svg>
              <template v-else>1</template>
            </span>
            <div class="body">
              <h3>Connect the board</h3>
              <p>
                {{
                  device
                    ? `${chip} is connected.`
                    : "Pick your board from the browser prompt."
                }}
              </p>
            </div>
            <div class="action">
              <button
                type="button"
                class="btn"
                :class="device ? 'ghost' : 'solid'"
                :disabled="busy"
                @click="connect"
              >
                {{ device ? "Reconnect" : "Connect" }}
              </button>
            </div>
          </li>

          <!-- 2. pick the firmware (served from the website, nothing to upload) -->
          <li class="step" :class="{ done: !!blocks }">
            <span class="num" aria-hidden="true">
              <svg
                v-if="blocks"
                width="16"
                height="16"
                viewBox="0 0 16 16"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path d="M3 8.5l3.2 3.2L13 4.8" />
              </svg>
              <template v-else>2</template>
            </span>
            <div class="body">
              <h3>Choose your board</h3>
              <p>
                Pick the physical flash capacity. Updates preserve storage;
                secure boot is not enabled.
              </p>
              <label class="tip"
                ><input
                  type="checkbox"
                  v-model="provision"
                  :disabled="busy"
                  @change="
                    blocks = null;
                    choice = '';
                  "
                />First installation on a blank device: allow irreversible OTP
                master-root creation after a physical three-second confirmation.
                Leave off for updates.</label
              >
              <div class="choices" role="radiogroup" aria-label="Flash size">
                <label
                  v-for="o in FIRMWARE"
                  :key="o.id"
                  class="choice"
                  :class="{ on: choice === o.id, off: busy }"
                >
                  <input
                    class="sr"
                    type="radio"
                    name="flash-size"
                    :value="o.id"
                    :checked="choice === o.id"
                    :disabled="busy"
                    @change="pick(o)"
                  />
                  <strong>{{ o.label }}</strong>
                  <small>{{ o.note }}</small>
                </label>
              </div>
            </div>
          </li>

          <!-- 3. flash -->
          <li class="step" :class="{ done: progress === 100 && !busy }">
            <span class="num" aria-hidden="true">
              <svg
                v-if="progress === 100 && !busy"
                width="16"
                height="16"
                viewBox="0 0 16 16"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path d="M3 8.5l3.2 3.2L13 4.8" />
              </svg>
              <template v-else>3</template>
            </span>
            <div class="body">
              <h3>Flash</h3>
              <p>Erases the old firmware and writes the new one.</p>
              <div
                class="bar"
                role="progressbar"
                aria-valuemin="0"
                aria-valuemax="100"
                :aria-valuenow="progress"
                aria-label="Flash progress"
              >
                <span class="fill" :style="{ width: progress + '%' }"></span>
              </div>
            </div>
            <div class="action">
              <button
                type="button"
                class="btn solid"
                :disabled="!ready"
                @click="flash"
              >
                {{ busy ? "Flashing..." : "Flash" }}
              </button>
            </div>
          </li>
        </ol>

        <p class="status" :class="tone" aria-live="polite">
          <span class="status-dot" aria-hidden="true"></span
          >{{ status || "Waiting for a board." }}
        </p>
      </div>
    </div>
  </section>
</template>

<script setup>
// the firmware files live in website/public/firmware/ and are downloaded when you pick one
const FIRMWARE = [
  {
    id: "4mb",
    label: "4 MB",
    note: "4 MB flash",
    file: "/firmware/doohickey-4mb.uf2",
  },
  {
    id: "16mb",
    label: "16 MB",
    note: "16 MB flash",
    file: "/firmware/doohickey-16mb.uf2",
  },
];

const provision = ref(false);
const status = ref("");
const tone = ref("idle"); // idle, ok, busy or error: colors the status dot
const chip = ref("");
const choice = ref(""); // id of the selected firmware
const progress = ref(0);
const busy = ref(false);
const loading = ref(false);
// shallowRef because Vue's deep proxy can break native browser objects like USBDevice
const device = shallowRef(null);
const blocks = shallowRef(null);
const ready = computed(
  () =>
    chip.value === "RP2350" &&
    !!device.value &&
    !!blocks.value &&
    !busy.value &&
    !loading.value,
); // Flash needs both
let pickToken = 0; // so a slow download of an earlier choice can't overwrite a newer one

function say(text, t = "idle") {
  status.value = text;
  tone.value = t;
}

async function connect() {
  if (!("usb" in navigator)) {
    say("No WebUSB support. Use Chrome or Edge.", "error");
    return;
  }
  try {
    device.value = await navigator.usb.requestDevice({
      filters: [{ vendorId: 0x2e8a }],
    });
    const id = device.value.productId;
    chip.value =
      id === 0x000f ? "RP2350" : id === 0x0003 ? "RP2040" : "Unknown board";
    say(`Connected: ${chip.value}`, "ok");
  } catch (err) {
    say("No device selected, or the connection failed.", "error");
  }
}

// download the chosen .uf2 from the site and parse it
async function pick(opt) {
  if (busy.value) return;
  const mine = ++pickToken;
  choice.value = opt.id;
  blocks.value = null;
  progress.value = 0;
  loading.value = true;
  say(`Loading ${opt.label} firmware...`, "busy");
  try {
    const artifactId = opt.id + (provision.value ? "-setup" : "");
    const file = provision.value
      ? opt.file.replace(".uf2", "-setup.uf2")
      : opt.file;
    const res = await fetch(file);
    if (!res.ok)
      throw new Error(
        `Couldn't download the ${opt.label} firmware (${res.status}).`,
      );
    const bytes = await res.arrayBuffer();
    const manifest = await (await fetch("/firmware/manifest.json")).json();
    const digest = Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
      (b) => b.toString(16).padStart(2, "0"),
    ).join("");
    if (manifest[artifactId]?.sha256 !== digest)
      throw Error("Firmware integrity check failed");
    const parsed = parseUf2(bytes); // from utils/uf2.js
    if (mine !== pickToken) return;
    blocks.value = parsed;
    say(`${opt.label} firmware ready (${parsed.length} blocks).`, "ok");
  } catch (err) {
    if (mine !== pickToken) return;
    blocks.value = null;
    say(err.message, "error");
  } finally {
    if (mine === pickToken) loading.value = false;
  }
}

async function flash() {
  const pb = new Picoboot(device.value); // from utils/picoboot.js
  busy.value = true;
  progress.value = 0;
  try {
    say("Opening device...", "busy");
    await pb.open();
    await pb.flash(blocks.value, (n, total) => {
      progress.value = Math.round((n / total) * 100);
      say(`Writing ${n}/${total}`, "busy");
    });
    try {
      await pb.reboot(device.value.productId === 0x000f);
    } catch {} // board disconnects as it reboots, errors here are normal
    progress.value = 100;
    say(
      "Firmware installed. Reconnect normally below. A new device needs a sealed OTP root; then release BOOTSEL, hold three seconds and release for setup. Existing devices migrate automatically.",
      "ok",
    );
  } catch (err) {
    console.error(err);
    say("Flash failed: " + err.message, "error");
  } finally {
    await device.value?.close().catch(() => {});
    busy.value = false;
  }
}
</script>

<style scoped>
.flash {
  padding: 7rem 0;
  background: var(--right);
  color: var(--cream);
}
.flash *,
.flash *::before,
.flash *::after {
  box-sizing: border-box;
}
.inner {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.5fr);
  gap: 3rem 5rem;
  align-items: start;
  max-width: 1100px;
  margin: 0 auto;
  padding: 0 2rem;
}

.head h2 {
  margin: 0 0 1.25rem;
  font-size: clamp(2rem, 4vw, 3rem);
  line-height: 1.1;
  color: var(--cream);
}
.lead {
  margin: 0 0 2rem;
  max-width: 36ch;
  font-size: 1.05rem;
  line-height: 1.7;
  color: var(--muted);
}
.tip {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin: 0;
  padding: 0.9rem 1.1rem;
  max-width: 36ch;
  background: var(--plate);
  font-size: 0.92rem;
  line-height: 1.5;
  color: var(--cream);
}
.tip-dot {
  flex: none;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--orange);
}

/* the flasher panel */
.console {
  background: var(--plate-dark);
  border: 1px solid rgba(243, 223, 199, 0.08);
}
.steps {
  margin: 0;
  padding: 0;
  list-style: none;
}
.step {
  display: grid;
  grid-template-columns: 40px minmax(0, 1fr) auto;
  gap: 0 1.25rem;
  align-items: start;
  padding: 1.75rem;
}
.step + .step {
  border-top: 1px solid rgba(243, 223, 199, 0.08);
}

.num {
  display: grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border: 1.5px solid var(--orange);
  border-radius: 50%;
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--orange);
  transition:
    background 0.2s,
    color 0.2s;
}
.step.done .num {
  background: var(--orange);
  color: var(--left);
}
.body h3 {
  margin: 0.35rem 0 0.25rem;
  font-size: 1.15rem;
  font-weight: 500;
  color: var(--cream);
}
.body p {
  margin: 0;
  font-size: 0.92rem;
  line-height: 1.55;
  color: var(--muted);
}
.action {
  padding-top: 0.2rem;
}

/* buttons: our own, so they always match the site */
.btn {
  min-width: 112px;
  padding: 0.65rem 1.25rem;
  border: 1.5px solid var(--orange);
  border-radius: 6px;
  font: inherit;
  font-size: 0.92rem;
  font-weight: 500;
  cursor: pointer;
  transition:
    background 0.2s,
    color 0.2s,
    opacity 0.2s;
}
.btn.solid {
  background: var(--orange);
  color: var(--left);
}
.btn.solid:hover:not(:disabled) {
  background: #ff7a45;
  border-color: #ff7a45;
}
.btn.ghost {
  background: transparent;
  color: var(--cream);
}
.btn.ghost:hover:not(:disabled) {
  background: var(--orange);
  color: var(--left);
}
.btn:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}
.btn:focus-visible {
  outline: 2px solid var(--cream);
  outline-offset: 3px;
}

/* firmware choice cards */
.choices {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
  margin-top: 1rem;
}
.choice {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  padding: 1rem 1.1rem;
  border: 1.5px solid rgba(243, 223, 199, 0.22);
  border-radius: 8px;
  cursor: pointer;
  transition:
    border-color 0.2s,
    background 0.2s;
}
.choice strong {
  font-size: 1.15rem;
  font-weight: 600;
  color: var(--cream);
}
.choice small {
  font-size: 0.82rem;
  color: var(--muted);
}
.choice:hover:not(.off) {
  border-color: var(--orange);
}
.choice.on {
  border-color: var(--orange);
  background: rgba(240, 100, 44, 0.08);
}
.choice.off {
  cursor: not-allowed;
  opacity: 0.6;
}
.choice:focus-within {
  outline: 2px solid var(--cream);
  outline-offset: 3px;
}
.sr {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: -1px;
  padding: 0;
  overflow: hidden;
  clip: rect(0 0 0 0);
  border: 0;
}

/* progress bar */
.bar {
  height: 6px;
  margin-top: 1rem;
  background: var(--plate);
  border-radius: 3px;
  overflow: hidden;
}
.fill {
  display: block;
  height: 100%;
  background: var(--orange);
  transition: width 0.15s linear;
}

/* status line */
.status {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  min-height: 3.25rem;
  margin: 0;
  padding: 0.9rem 1.75rem;
  border-top: 1px solid rgba(243, 223, 199, 0.08);
  background: rgba(0, 0, 0, 0.18);
  font-size: 0.92rem;
  color: var(--cream);
}
.status-dot {
  flex: none;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--muted);
}
.status.ok .status-dot {
  background: #6fcf97;
}
.status.busy .status-dot {
  background: var(--orange);
}
.status.error .status-dot {
  background: #ff7a6b;
}
.status.error {
  color: #ffb4a9;
}

@media (max-width: 900px) {
  .flash {
    padding: 4rem 0;
  }
  .inner {
    grid-template-columns: 1fr;
    gap: 2rem;
  }
  .lead,
  .tip {
    max-width: none;
  }
}
@media (max-width: 560px) {
  .step {
    grid-template-columns: 36px minmax(0, 1fr);
    padding: 1.25rem;
  }
  .action {
    grid-column: 2;
    padding-top: 1rem;
  }
  .status {
    padding: 0.9rem 1.25rem;
  }
}
@media (prefers-reduced-motion: reduce) {
  .num,
  .btn,
  .choice,
  .fill {
    transition: none;
  }
}
</style>
