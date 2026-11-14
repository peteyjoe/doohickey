<template>
  <section id="flash" class="flash">
    <h2>Flash your key</h2>
    <p>Hold BOOTSEL, plug in the board, then click Connect. Chrome or Edge only.</p>
    <UButton label="Connect" @click="connect" />
    <p v-if="status">{{ status }}</p>  <!-- only shows once status has text -->
  </section>
</template>

<script setup>
const status = ref('')   // text shown under the button
let device = null        // kept around for the next stages

async function connect() {
  // WebUSB only exists in Chromium browsers
  if (!('usb' in navigator)) {
    status.value = 'No WebUSB support. Use Chrome or Edge.'
    return
  }
  try {
    // opens the browser's device picker, limited to Raspberry Pi devices
    device = await navigator.usb.requestDevice({ filters: [{ vendorId: 0x2e8a }] })
    const chip = device.productId === 0x000f ? 'RP2350' : device.productId === 0x0003 ? 'RP2040' : 'unknown'
    status.value = `Connected: ${chip}`
  } catch (err) {
    status.value = 'No device selected, or the connection failed.'
  }
}
</script>

<style scoped>
.flash { padding: 4rem 1rem; text-align: center; scroll-margin-top: 80px; }
</style>