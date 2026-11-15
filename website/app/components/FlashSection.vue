<template>
  <section id="flash" class="flash">
    <div class="inner">
      <h2>Flash your key</h2>
      <p class="lead">Hold BOOTSEL, plug in the board, Connect, pick your .uf2, then Flash. Chrome or Edge only.</p>
      <div class="panel">
        <UButton label="Connect" @click="connect" />
        <input class="file" type="file" accept=".uf2" @change="onFile" />
        <UButton label="Flash" :disabled="!ready" @click="flash" />
      </div>
      <p class="status" aria-live="polite">{{ status }}</p>
    </div>
  </section>
</template>

<script setup>
// same flasher logic as before, only the look changed
const status = ref('')
// shallowRef because Vue's deep proxy can break native browser objects like USBDevice
const device = shallowRef(null)
const blocks = shallowRef(null)
const ready = computed(() => device.value && blocks.value) // Flash button needs both

async function connect() {
  if (!('usb' in navigator)) { status.value = 'No WebUSB support. Use Chrome or Edge.'; return }
  try {
    device.value = await navigator.usb.requestDevice({ filters: [{ vendorId: 0x2e8a }] })
    const id = device.value.productId
    status.value = `Connected: ${id === 0x000f ? 'RP2350' : id === 0x0003 ? 'RP2040' : 'unknown'}`
  } catch (err) {
    status.value = 'No device selected, or the connection failed.'
  }
}

async function onFile(e) {
  const file = e.target.files[0]
  if (!file) return
  try {
    blocks.value = parseUf2(await file.arrayBuffer()) // from utils/uf2.js
    status.value = `Loaded ${blocks.value.length} blocks from ${file.name}`
  } catch (err) { status.value = err.message }
}

async function flash() {
  const pb = new Picoboot(device.value) // from utils/picoboot.js
  try {
    status.value = 'Opening device...'
    await pb.open()
    await pb.flash(blocks.value, (n, total) => { status.value = `Writing ${n}/${total}` })
    try { await pb.reboot(device.value.productId === 0x000f) } catch {} // board disconnects as it reboots, errors here are normal
    status.value = 'Done! The board is rebooting.'
  } catch (err) {
    console.error(err)
    status.value = 'Flash failed: ' + err.message
  }
}
</script>

<style scoped>
.flash { padding: 7rem 0; background: var(--right); color: var(--cream); }
.inner { max-width: 1100px; margin: 0 auto; padding: 0 2rem; }
h2 { margin: 0 0 1rem; font-size: clamp(2rem, 4vw, 3rem); line-height: 1.1; color: var(--cream); }
.lead { margin: 0 0 2.5rem; max-width: 60ch; color: var(--muted); }
.panel { display: flex; flex-wrap: wrap; align-items: center; gap: 1rem 1.5rem; padding: 1.75rem 2rem; background: var(--plate-dark); }
.file { font: inherit; font-size: 0.9rem; color: var(--muted); }
/* styles the "Choose File" button */
.file::file-selector-button { margin-right: 1rem; padding: 0.5rem 1rem; border: 1.5px solid var(--orange); border-radius: 6px; background: transparent; color: var(--cream); font: inherit; font-size: 0.9rem; cursor: pointer; }
.file::file-selector-button:hover { background: var(--orange); color: var(--left); }
.status { min-height: 1.6em; margin: 1.25rem 0 0; color: var(--cream); }

@media (max-width: 800px) { .flash { padding: 4rem 0; } .panel { padding: 1.25rem; } }
</style>