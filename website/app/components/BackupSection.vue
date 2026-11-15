<template>
  <section id="backup" class="backup">
    <div class="inner">
      <div class="head">
        <h2>Back up your key</h2>
        <p class="lead">
          Export your credentials to an encrypted file, or restore them onto a key.
          Everything is encrypted on the key itself. The website only ever handles the locked file.
        </p>
        <p class="tip"><span class="tip-dot" aria-hidden="true"></span>Works in Chrome or Edge. Close other programs that use the key (like a serial monitor) first.</p>
        <p class="tip"><span class="tip-dot" aria-hidden="true"></span>Your backup password is never stored. If you lose it, the backup can't be opened.</p>
      </div>

      <div class="console">
        <div class="tabs" role="tablist" aria-label="Backup mode">
          <button type="button" role="tab" class="tab" :class="{ on: mode === 'export' }" :aria-selected="mode === 'export'" :disabled="busy" @click="setMode('export')">Export</button>
          <button type="button" role="tab" class="tab" :class="{ on: mode === 'restore' }" :aria-selected="mode === 'restore'" :disabled="busy" @click="setMode('restore')">Restore</button>
        </div>

        <ol class="steps">
          <!-- 1. connect -->
          <li class="step" :class="{ done: !!dev }">
            <span class="num" aria-hidden="true">
              <svg v-if="dev" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3.2 3.2L13 4.8" /></svg>
              <template v-else>1</template>
            </span>
            <div class="body">
              <h3>Connect the key</h3>
              <p v-if="info">Firmware {{ info.fw }}<template v-if="info.count !== null"> · {{ info.count }} credential{{ info.count === 1 ? '' : 's' }} stored</template></p>
              <p v-else>Plug in the key normally (not in BOOTSEL mode), then pick it from the browser prompt.</p>
            </div>
            <div class="action">
              <button v-if="dev" type="button" class="btn ghost" :disabled="busy" @click="disconnect">Disconnect</button>
              <button v-else type="button" class="btn solid" :disabled="busy" @click="connect">Connect</button>
            </div>
          </li>

          <!-- 2. unlock -->
          <li class="step" :class="{ done: fieldsOk }">
            <span class="num" aria-hidden="true">
              <svg v-if="fieldsOk" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3.2 3.2L13 4.8" /></svg>
              <template v-else>2</template>
            </span>
            <div class="body">
              <h3>Unlock for this {{ mode === 'export' ? 'export' : 'restore' }}</h3>
              <p>The PIN approves this one action. The backup password {{ mode === 'export' ? 'locks the file.' : 'must be the one used when the backup was made.' }}</p>
              <div class="fields">
                <label class="field">
                  <span>Key PIN</span>
                  <input v-model="pin" type="password" inputmode="numeric" autocomplete="off" :disabled="busy" />
                </label>
                <label class="field">
                  <span>Backup password</span>
                  <input v-model="pw" type="password" autocomplete="off" :disabled="busy" />
                </label>
                <label v-if="mode === 'export'" class="field wide">
                  <span>Confirm backup password</span>
                  <input v-model="pw2" type="password" autocomplete="off" :disabled="busy" />
                </label>
              </div>
              <p v-if="hint" class="hint">{{ hint }}</p>
            </div>
          </li>

          <!-- 3. export or restore -->
          <li class="step" :class="{ done: finished }">
            <span class="num" aria-hidden="true">
              <svg v-if="finished" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3.2 3.2L13 4.8" /></svg>
              <template v-else>3</template>
            </span>
            <div class="body">
              <h3>{{ mode === 'export' ? 'Export backup' : 'Restore backup' }}</h3>
              <p v-if="mode === 'export'">You'll be asked to press the button on the key. The file is saved to your computer.</p>
              <template v-else>
                <p>Choose a backup file. Nothing changes on the key until the whole file checks out.</p>
                <label class="drop" :class="{ over: dragging, has: !!blob }" @dragover.prevent="dragging = true" @dragleave="dragging = false" @drop.prevent="onDrop">
                  <input class="sr" type="file" :disabled="busy" @change="onFile" />
                  <svg class="drop-icon" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 16V4M7 9l5-5 5 5M4 17v2a1 1 0 001 1h14a1 1 0 001-1v-2" /></svg>
                  <span v-if="blob" class="drop-text"><strong>{{ fileName }}</strong><small>{{ blob.length }} bytes. Click to pick a different file.</small></span>
                  <span v-else class="drop-text"><strong>Drop a backup file here</strong><small>or click to browse</small></span>
                </label>
              </template>
              <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" :aria-valuenow="progress" aria-label="Transfer progress">
                <span class="fill" :style="{ width: progress + '%' }"></span>
              </div>
            </div>
            <div class="action">
              <button type="button" class="btn solid" :disabled="!canRun" @click="mode === 'export' ? runExport() : runRestore()">
                {{ busy ? 'Working...' : mode === 'export' ? 'Export' : 'Restore' }}
              </button>
            </div>
          </li>
        </ol>

        <p class="status" :class="tone" aria-live="polite">
          <span class="status-dot" aria-hidden="true"></span>{{ status || 'Waiting for a key.' }}
        </p>
      </div>
    </div>
  </section>
</template>

<script setup>
// uses utils/cobs.js and utils/backup.js (auto-imported by Nuxt)

// Dev USB ID from the protocol notes. It "will change before release", so update it here.
const SERIAL_FILTER = { usbVendorId: 0x1209, usbProductId: 0x0001 }
// Placeholder minimum until the PM decides the real rule (open question 1 in the notes).
const MIN_PASSWORD = 12

const mode = ref('export') // export or restore
const status = ref('')
const tone = ref('idle') // idle, ok, busy or error
const busy = ref(false)
const progress = ref(0)
const finished = ref(false)
const pin = ref('')
const pw = ref('')
const pw2 = ref('')
const fileName = ref('')
const dragging = ref(false)
const info = ref(null) // { fw, count }
// shallowRef: Vue's deep proxy can break native objects like the serial port and byte arrays
const dev = shallowRef(null)
const blob = shallowRef(null)

function say(text, t = 'idle') { status.value = text; tone.value = t }

// what is still missing, shown under the fields
const hint = computed(() => {
  if (pin.value && !/^\d+$/.test(pin.value)) return 'The PIN is digits only.' // length is up to the firmware, so we don't check it
  if (mode.value === 'export') {
    if (pw.value && pw.value.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters for the backup password.`
    if (pw2.value && pw.value !== pw2.value) return "The two passwords don't match."
  }
  return ''
})
const fieldsOk = computed(() => {
  if (!/^\d+$/.test(pin.value) || !pw.value) return false
  if (mode.value === 'export') return pw.value.length >= MIN_PASSWORD && pw.value === pw2.value
  return true
})
const canRun = computed(() => !!dev.value && fieldsOk.value && !busy.value && (mode.value === 'export' || !!blob.value))

function setMode(m) {
  mode.value = m
  finished.value = false
  progress.value = 0
  say(dev.value ? 'Connected.' : '', 'idle')
}

function reset() { // back to the not-connected state
  dev.value = null
  info.value = null
  busy.value = false
  progress.value = 0
  finished.value = false
}

async function connect() {
  if (!('serial' in navigator)) { say('No Web Serial support. Use Chrome or Edge.', 'error'); return }
  let d = null
  try {
    const port = await navigator.serial.requestPort({ filters: [SERIAL_FILTER] })
    d = new BackupDevice(port)
    d.onLost = () => { reset(); say('The key was unplugged.', 'error') }
    await d.open()
    const h = await d.hello()
    let count = null
    try { count = (await d.status()).count } catch {} // STATUS is a stub today, don't fail the connection over it
    dev.value = d
    info.value = { fw: `${h.major}.${h.minor}`, count }
    say('Connected.', 'ok')
  } catch (e) {
    if (d) { d.onLost = null; await d.close().catch(() => {}) }
    say(backupErrorMessage(e), 'error')
  }
}

async function disconnect() {
  const d = dev.value
  if (!d) return
  d.onLost = null
  reset()
  await d.close()
  say('Disconnected.', 'idle')
}

function downloadFile(bytes) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }))
  const a = document.createElement('a')
  const day = new Date().toISOString().slice(0, 10)
  a.href = url
  a.download = `doohickey-backup-${day}.bak`
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

async function runExport() {
  busy.value = true
  finished.value = false
  progress.value = 0
  let ok = false
  try {
    say('Press the button on your key to approve (30 seconds)...', 'busy')
    const res = await dev.value.exportBackup({ pin: pin.value, password: pw.value }, (n, total) => {
      progress.value = Math.round((n / total) * 100)
      say(`Receiving backup ${n}/${total} bytes`, 'busy')
    })
    downloadFile(res.blob)
    finished.value = true
    ok = true
    say(`Backup saved (${res.blob.length} bytes, checked against the key's hash).`, 'ok')
  } catch (e) {
    console.error(e)
    say(backupErrorMessage(e), 'error')
  } finally {
    busy.value = false
    pin.value = '' // the PIN only covers one action
    if (ok) { pw.value = ''; pw2.value = '' } // keep the password after a failure so a typo'd PIN is a quick retry
  }
}

async function runRestore() {
  busy.value = true
  finished.value = false
  progress.value = 0
  let ok = false
  try {
    say('Starting restore...', 'busy')
    await dev.value.importBackup({ pin: pin.value, password: pw.value, blob: blob.value }, (n, total, phase) => {
      progress.value = Math.round((n / total) * 100)
      say(phase === 'verifying' ? 'The key is checking and decrypting the backup...' : `Sending backup ${n}/${total} bytes`, 'busy')
    })
    finished.value = true
    ok = true
    say('Restored. The credentials are now on the key.', 'ok')
  } catch (e) {
    console.error(e)
    say(backupErrorMessage(e), 'error')
  } finally {
    busy.value = false
    pin.value = ''
    if (ok) pw.value = ''
  }
}

async function loadFile(file) {
  if (!file) return
  blob.value = new Uint8Array(await file.arrayBuffer())
  fileName.value = file.name
  finished.value = false
  progress.value = 0
  say(`Loaded ${file.name}`, 'ok')
}
function onFile(e) { loadFile(e.target.files[0]) }
function onDrop(e) { dragging.value = false; loadFile(e.dataTransfer.files[0]) }

// close the port if the person navigates away
onBeforeUnmount(() => { dev.value?.close() })
</script>

<style scoped>
.backup { padding: 7rem 0; background: var(--left); color: var(--cream); }
.backup *, .backup *::before, .backup *::after { box-sizing: border-box; }
.inner { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.5fr); gap: 3rem 5rem; align-items: start; max-width: 1100px; margin: 0 auto; padding: 0 2rem; }

.head h2 { margin: 0 0 1.25rem; font-size: clamp(2rem, 4vw, 3rem); line-height: 1.1; color: var(--cream); }
.lead { margin: 0 0 2rem; max-width: 36ch; font-size: 1.05rem; line-height: 1.7; color: var(--muted); }
.tip { display: flex; align-items: flex-start; gap: 0.75rem; margin: 0 0 0.75rem; padding: 0.9rem 1.1rem; max-width: 36ch; background: var(--plate); font-size: 0.92rem; line-height: 1.5; color: var(--cream); }
.tip-dot { flex: none; width: 8px; height: 8px; margin-top: 0.5rem; border-radius: 50%; background: var(--orange); }

.console { background: var(--plate-dark); border: 1px solid rgba(243, 223, 199, 0.08); }
.tabs { display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid rgba(243, 223, 199, 0.08); }
.tab { padding: 1rem; border: 0; border-bottom: 2px solid transparent; background: transparent; color: var(--muted); font: inherit; font-size: 0.95rem; font-weight: 500; cursor: pointer; transition: color 0.2s, border-color 0.2s; }
.tab.on { color: var(--cream); border-bottom-color: var(--orange); }
.tab:hover:not(:disabled):not(.on) { color: var(--cream); }
.tab:disabled { cursor: not-allowed; opacity: 0.6; }
.tab:focus-visible { outline: 2px solid var(--cream); outline-offset: -4px; }

.steps { margin: 0; padding: 0; list-style: none; }
.step { display: grid; grid-template-columns: 40px minmax(0, 1fr) auto; gap: 0 1.25rem; align-items: start; padding: 1.75rem; }
.step + .step { border-top: 1px solid rgba(243, 223, 199, 0.08); }
.num { display: grid; place-items: center; width: 36px; height: 36px; border: 1.5px solid var(--orange); border-radius: 50%; font-size: 0.95rem; font-weight: 600; color: var(--orange); transition: background 0.2s, color 0.2s; }
.step.done .num { background: var(--orange); color: var(--left); }
.body h3 { margin: 0.35rem 0 0.25rem; font-size: 1.15rem; font-weight: 500; color: var(--cream); }
.body p { margin: 0; font-size: 0.92rem; line-height: 1.55; color: var(--muted); }
.action { padding-top: 0.2rem; }

.fields { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem; }
.field { display: flex; flex-direction: column; gap: 0.4rem; min-width: 0; }
.field.wide { grid-column: 1 / -1; }
.field span { font-size: 0.82rem; color: var(--muted); }
.field input { width: 100%; padding: 0.7rem 0.85rem; border: 1.5px solid rgba(243, 223, 199, 0.22); border-radius: 6px; background: var(--plate); color: var(--cream); font: inherit; font-size: 0.95rem; transition: border-color 0.2s; }
.field input:focus-visible { outline: none; border-color: var(--orange); }
.field input:disabled { opacity: 0.5; }
.body .hint { margin-top: 0.75rem; color: #ffb4a9; font-size: 0.85rem; }

.btn { min-width: 112px; padding: 0.65rem 1.25rem; border: 1.5px solid var(--orange); border-radius: 6px; font: inherit; font-size: 0.92rem; font-weight: 500; cursor: pointer; transition: background 0.2s, color 0.2s, opacity 0.2s; }
.btn.solid { background: var(--orange); color: var(--left); }
.btn.solid:hover:not(:disabled) { background: #ff7a45; border-color: #ff7a45; }
.btn.ghost { background: transparent; color: var(--cream); }
.btn.ghost:hover:not(:disabled) { background: var(--orange); color: var(--left); }
.btn:disabled { opacity: 0.35; cursor: not-allowed; }
.btn:focus-visible, .drop:focus-within { outline: 2px solid var(--cream); outline-offset: 3px; }

.drop { display: flex; align-items: center; gap: 1rem; margin-top: 1rem; padding: 1.1rem 1.25rem; border: 1.5px dashed rgba(243, 223, 199, 0.28); border-radius: 8px; cursor: pointer; transition: border-color 0.2s, background 0.2s; }
.drop:hover, .drop.over { border-color: var(--orange); background: rgba(240, 100, 44, 0.06); }
.drop.has { border-style: solid; border-color: rgba(240, 100, 44, 0.55); }
.drop-icon { flex: none; color: var(--orange); }
.drop-text { display: flex; flex-direction: column; gap: 0.15rem; min-width: 0; }
.drop-text strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.95rem; font-weight: 500; color: var(--cream); }
.drop-text small { font-size: 0.82rem; color: var(--muted); }
.sr { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); border: 0; }

.bar { height: 6px; margin-top: 1rem; background: var(--plate); border-radius: 3px; overflow: hidden; }
.fill { display: block; height: 100%; background: var(--orange); transition: width 0.15s linear; }

.status { display: flex; align-items: center; gap: 0.75rem; min-height: 3.25rem; margin: 0; padding: 0.9rem 1.75rem; border-top: 1px solid rgba(243, 223, 199, 0.08); background: rgba(0, 0, 0, 0.18); font-size: 0.92rem; color: var(--cream); }
.status-dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }
.status.ok .status-dot { background: #6fcf97; }
.status.busy .status-dot { background: var(--orange); }
.status.error .status-dot { background: #ff7a6b; }
.status.error { color: #ffb4a9; }

@media (max-width: 900px) {
  .backup { padding: 4rem 0; }
  .inner { grid-template-columns: 1fr; gap: 2rem; }
  .lead, .tip { max-width: none; }
}
@media (max-width: 560px) {
  .step { grid-template-columns: 36px minmax(0, 1fr); padding: 1.25rem; }
  .action { grid-column: 2; padding-top: 1rem; }
  .fields { grid-template-columns: 1fr; }
  .status { padding: 0.9rem 1.25rem; }
}
@media (prefers-reduced-motion: reduce) {
  .num, .btn, .drop, .fill, .tab { transition: none; }
}
</style>