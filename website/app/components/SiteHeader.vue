<template>
  <section class="hero">
    <div class="copy">
      <h1>The DoohicKEY</h1>
      <p>A security key you can build and flash yourself. Plug it in, tap it, and you're logged in. No password.</p>
      <p class="hint">Try it: tap the gold pad on the key.</p>
    </div>

    <div class="stage">
      <!-- the key is drawn with divs and CSS, no image files -->
      <button class="key" :class="{ ok: verified }" aria-label="Tap the key to simulate a login" @click="tap">
        <span class="usb"></span>
        <span class="board">
          <span class="name">The DoohicKEY</span>
          <span class="pad"></span>
          <span class="led"></span>
        </span>
      </button>
      <p class="status" aria-live="polite">{{ verified ? "Verified. You're signed in." : 'Waiting for a tap...' }}</p>
    </div>
  </section>
</template>

<script setup>
const verified = ref(false)
function tap() {
  verified.value = true                              // LED lights up, text changes
  setTimeout(() => (verified.value = false), 2500)   // resets so people can try again
}
</script>

<style scoped>
.hero { display: grid; grid-template-columns: 1.1fr 1fr; gap: 3rem; align-items: center; max-width: 1100px; margin: 0 auto; padding: 5rem 2rem; }
.copy h1 { font-size: clamp(3.5rem, 9vw, 6.5rem); color: var(--mask); margin: 0 0 1rem; }
.copy p { font-size: 1.25rem; max-width: 34ch; margin: 0 0 1rem; }
.copy .hint { font-size: 1rem; color: var(--mask); font-weight: 500; }
.stage { display: flex; flex-direction: column; align-items: center; gap: 1.25rem; }

.key { display: flex; align-items: center; background: none; border: 0; padding: 0; cursor: pointer; }
.key:focus-visible { outline: 3px solid var(--gold); outline-offset: 8px; border-radius: 12px; }
.usb { width: 80px; height: 64px; background: var(--gold); border-radius: 8px 0 0 8px; }  /* metal USB connector */
.board { position: relative; display: flex; align-items: center; justify-content: space-between; gap: 1.5rem; width: 260px; height: 120px; padding: 0 1.5rem; background: var(--mask); color: var(--silk); border-radius: 0 28px 28px 0; }
.name { font-family: 'Chakra Petch', system-ui, sans-serif; font-weight: 700; font-size: 1.4rem; }
.pad { width: 56px; height: 56px; border-radius: 50%; background: var(--gold); border: 4px solid var(--silk); transition: transform 0.1s; }
.key:active .pad { transform: scale(0.93); }  /* pad presses in when clicked */
.led { position: absolute; top: 14px; right: 20px; width: 10px; height: 10px; border-radius: 50%; background: var(--mist); transition: all 0.2s; }
.ok .led { background: var(--gold); box-shadow: 0 0 12px var(--gold); }  /* LED glows after a tap */
.status { margin: 0; color: var(--mask); font-weight: 500; }

@media (max-width: 800px) { .hero { grid-template-columns: 1fr; padding: 3rem 1.5rem; } }
</style>