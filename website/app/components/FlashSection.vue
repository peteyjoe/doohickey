<template>
  <section id="flash" class="flash">
    <div class="inner">
      <div class="head">
        <h2>Flash your key</h2>
        <p class="lead">
          Put firmware on your DoohicKEY straight from the browser. No installs, no drivers.
          Works in Chrome or Edge.
        </p>
        <p class="tip"><span class="tip-dot" aria-hidden="true"></span>Hold the BOOTSEL button while you plug the board in.</p>
      </div>

      <div class="console">
        <ol class="steps">
          <!-- 1. connect -->
          <li class="step" :class="{ done: !!device }">
            <span class="num" aria-hidden="true">
              <svg v-if="device" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3.2 3.2L13 4.8" /></svg>
              <template v-else>1</template>
            </span>
            <div class="body">
              <h3>Connect the board</h3>
              <p>{{ device ? `${chip} is connected.` : 'Pick your board from the browser prompt.' }}</p>
            </div>
            <div class="action">
              <button type="button" class="btn" :class="device ? 'ghost' : 'solid'" :disabled="busy" @click="connect">
                {{ device ? 'Reconnect' : 'Connect' }}
              </button>
            </div>
          </li>

          <!-- 2. choose firmware -->
          <li class="step" :class="{ done: !!blocks }">
            <span class="num" aria-hidden="true">
              <svg v-if="blocks" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3.2 3.2L13 4.8" /></svg>
              <template v-else>2</template>
            </span>
            <div class="body">
              <h3>Choose firmware</h3>
              <p>A .uf2 file, for example the one from your team's build.</p>
              <!-- the whole box is a label, so clicking it opens the file picker -->
              <label
                class="drop"
                :class="{ over: dragging, has: !!blocks }"
                @dragover.prevent="dragging = true"
                @dragleave="dragging = false"
                @drop.prevent="onDrop"
              >
                <input class="sr" type="file" accept=".uf2" @change="onFile" />
                <svg class="drop-icon" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 16V4M7 9l5-5 5 5M4 17v2a1 1 0 001 1h14a1 1 0 001-1v-2" /></svg>
                <span v-if="blocks" class="drop-text"><strong>{{ fileName }}</strong><small>{{ blocks.length }} blocks ready. Click to pick a different file.</small></span>
                <span v-else class="drop-text"><strong>Drop a .uf2 file here</strong><small>or click to browse</small></span>
              </label>
            </div>
          </li>

          <!-- 3. flash -->
          <li class="step" :class="{ done: progress === 100 && !busy }">
            <span class="num" aria-hidden="true">
              <svg v-if="progress === 100 && !busy" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3.2 3.2L13 4.8" /></svg>
              <template v-else>3</template>
            </span>
            <div class="body">
              <h3>Flash</h3>
              <p>Erases the old firmware and writes the new one.</p>
              <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" :aria-valuenow="progress" aria-label="Flash progress">
                <span class="fill" :style="{ width: progress + '%' }"></span>
              </div>
            </div>
            <div class="action">
              <button type="button" class="btn solid" :disabled="!ready" @click="flash">{{ busy ? 'Flashing...' : 'Flash' }}</button>
            </div>
          </li>
        </ol>

        <p class="status" :class="tone" aria-live="polite">
          <span class="status-dot" aria-hidden="true"></span>{{ status || 'Waiting for a board.' }}
        </p>
      </div>
    </div>
  </section>
</template>

<script setup>
// same flasher logic as before, now with a progress bar and drag and drop
const status = ref('')
const tone = ref('idle') // idle, ok, busy or error: colors the status dot
const chip = ref('')
const fileName = ref('')
const progress = ref(0)
const busy = ref(false)
const dragging = ref(false)
// shallowRef because Vue's deep proxy can break native browser objects like USBDevice
const device = shallowRef(null)
const blocks = shallowRef(null)
const ready = computed(() => !!device.value && !!blocks.value && !busy.value) // Flash needs both

function say(text, t = 'idle') { status.value = text; tone.value = t }

async function connect() {
  if (!('usb' in navigator)) { say('No WebUSB support. Use Chrome or Edge.', 'error'); return }
  try {
    device.value = await navigator.usb.requestDevice({ filters: [{ vendorId: 0x2e8a }] })
    const id = device.value.productId
    chip.value = id === 0x000f ? 'RP2350' : id === 0x0003 ? 'RP2040' : 'Unknown board'
    say(`Connected: ${chip.value}`, 'ok')
  } catch (err) {
    say('No device selected, or the connection failed.', 'error')
  }
}

async function loadFile(file) {
  if (!file) return
  try {
    blocks.value = parseUf2(await file.arrayBuffer()) // from utils/uf2.js
    fileName.value = file.name
    progress.value = 0
    say(`Loaded ${blocks.value.length} blocks from ${file.name}`, 'ok')
  } catch (err) {
    blocks.value = null
    fileName.value = ''
    say(err.message, 'error')
  }
}
function onFile(e) { loadFile(e.target.files[0]) }
function onDrop(e) { dragging.value = false; loadFile(e.dataTransfer.files[0]) }

async function flash() {
  const pb = new Picoboot(device.value) // from utils/picoboot.js
  busy.value = true
  progress.value = 0
  try {
    say('Opening device...', 'busy')
    await pb.open()
    await pb.flash(blocks.value, (n, total) => {
      progress.value = Math.round((n / total) * 100)
      say(`Writing ${n}/${total}`, 'busy')
    })
    try { await pb.reboot(device.value.productId === 0x000f) } catch {} // board disconnects as it reboots, errors here are normal
    progress.value = 100
    say('Done! The board is rebooting.', 'ok')
  } catch (err) {
    console.error(err)
    say('Flash failed: ' + err.message, 'error')
  } finally {
    busy.value = false
  }
}
</script>

<style scoped>
.flash { padding: 7rem 0; background: var(--right); color: var(--cream); }
.flash *, .flash *::before, .flash *::after { box-sizing: border-box; }
.inner { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.5fr); gap: 3rem 5rem; align-items: start; max-width: 1100px; margin: 0 auto; padding: 0 2rem; }

.head h2 { margin: 0 0 1.25rem; font-size: clamp(2rem, 4vw, 3rem); line-height: 1.1; color: var(--cream); }
.lead { margin: 0 0 2rem; max-width: 36ch; font-size: 1.05rem; line-height: 1.7; color: var(--muted); }
.tip { display: flex; align-items: center; gap: 0.75rem; margin: 0; padding: 0.9rem 1.1rem; max-width: 36ch; background: var(--plate); font-size: 0.92rem; line-height: 1.5; color: var(--cream); }
.tip-dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--orange); }

/* the flasher panel */
.console { background: var(--plate-dark); border: 1px solid rgba(243, 223, 199, 0.08); }
.steps { margin: 0; padding: 0; list-style: none; }
.step { display: grid; grid-template-columns: 40px minmax(0, 1fr) auto; gap: 0 1.25rem; align-items: start; padding: 1.75rem; }
.step + .step { border-top: 1px solid rgba(243, 223, 199, 0.08); }

.num { display: grid; place-items: center; width: 36px; height: 36px; border: 1.5px solid var(--orange); border-radius: 50%; font-size: 0.95rem; font-weight: 600; color: var(--orange); transition: background 0.2s, color 0.2s; }
.step.done .num { background: var(--orange); color: var(--left); }
.body h3 { margin: 0.35rem 0 0.25rem; font-size: 1.15rem; font-weight: 500; color: var(--cream); }
.body p { margin: 0; font-size: 0.92rem; line-height: 1.55; color: var(--muted); }
.action { padding-top: 0.2rem; }

/* buttons: our own, so they always match the site */
.btn { min-width: 112px; padding: 0.65rem 1.25rem; border: 1.5px solid var(--orange); border-radius: 6px; font: inherit; font-size: 0.92rem; font-weight: 500; cursor: pointer; transition: background 0.2s, color 0.2s, opacity 0.2s; }
.btn.solid { background: var(--orange); color: var(--left); }
.btn.solid:hover:not(:disabled) { background: #ff7a45; border-color: #ff7a45; }
.btn.ghost { background: transparent; color: var(--cream); }
.btn.ghost:hover:not(:disabled) { background: var(--orange); color: var(--left); }
.btn:disabled { opacity: 0.35; cursor: not-allowed; }
.btn:focus-visible, .drop:focus-within { outline: 2px solid var(--cream); outline-offset: 3px; }

/* drop zone */
.drop { display: flex; align-items: center; gap: 1rem; margin-top: 1rem; padding: 1.1rem 1.25rem; border: 1.5px dashed rgba(243, 223, 199, 0.28); border-radius: 8px; cursor: pointer; transition: border-color 0.2s, background 0.2s; }
.drop:hover, .drop.over { border-color: var(--orange); background: rgba(240, 100, 44, 0.06); }
.drop.has { border-style: solid; border-color: rgba(240, 100, 44, 0.55); }
.drop-icon { flex: none; color: var(--orange); }
.drop-text { display: flex; flex-direction: column; gap: 0.15rem; min-width: 0; }
.drop-text strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.95rem; font-weight: 500; color: var(--cream); }
.drop-text small { font-size: 0.82rem; color: var(--muted); }
.sr { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); border: 0; }

/* progress bar */
.bar { height: 6px; margin-top: 1rem; background: var(--plate); border-radius: 3px; overflow: hidden; }
.fill { display: block; height: 100%; background: var(--orange); transition: width 0.15s linear; }

/* status line */
.status { display: flex; align-items: center; gap: 0.75rem; min-height: 3.25rem; margin: 0; padding: 0.9rem 1.75rem; border-top: 1px solid rgba(243, 223, 199, 0.08); background: rgba(0, 0, 0, 0.18); font-size: 0.92rem; color: var(--cream); }
.status-dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }
.status.ok .status-dot { background: #6fcf97; }
.status.busy .status-dot { background: var(--orange); }
.status.error .status-dot { background: #ff7a6b; }
.status.error { color: #ffb4a9; }

@media (max-width: 900px) {
  .flash { padding: 4rem 0; }
  .inner { grid-template-columns: 1fr; gap: 2rem; }
  .lead, .tip { max-width: none; }
}
@media (max-width: 560px) {
  .step { grid-template-columns: 36px minmax(0, 1fr); padding: 1.25rem; }
  .action { grid-column: 2; padding-top: 1rem; }
  .status { padding: 0.9rem 1.25rem; }
}
@media (prefers-reduced-motion: reduce) {
  .num, .btn, .drop, .fill { transition: none; }
}
</style>