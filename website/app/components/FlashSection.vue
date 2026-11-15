<template>
  <section id="flash" class="flash">
    <h2>Flash your key</h2>
    <p>Hold BOOTSEL, plug in the board, Connect, pick your .uf2, then Flash. Chrome or Edge only.</p>
    <div class="row">
      <UButton label="Connect" @click="connect" />
      <input type="file" accept=".uf2" @change="onFile" />
      <UButton label="Flash" :disabled="!ready" @click="flash" />
    </div>
    <p v-if="status">{{ status }}</p>
  </section>
</template>

<script setup>
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
.flash { padding: 4rem 1rem; text-align: center; scroll-margin-top: 80px; }
.row { display: flex; gap: 1rem; justify-content: center; align-items: center; flex-wrap: wrap; margin: 1.5rem 0; }
</style>