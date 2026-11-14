<template>
  <section id="how" class="how">  <!-- id must match the header link -->
    <h2>How it works</h2>
    <div class="steps">
      <!-- v-for stamps out one card per item in the steps array -->
      <div v-for="step in steps" :key="step.title" class="card">
        <h3>{{ step.title }}</h3>
        <p>{{ step.text }}</p>
      </div>
    </div>
  </section>
</template>

<script setup>
// placeholder text, get the real flow from your firmware teammates
const steps = [
  { title: '1. Register', text: 'Plug in the key and link it to your account.' },
  { title: '2. Tap to verify', text: 'Touch the key when a site asks you to log in.' },
  { title: '3. Signed in', text: 'The site verifies the key. No password needed.' },
]
</script>

<style scoped>
.how { padding: 4rem 1rem; text-align: center; scroll-margin-top: 80px; } /* leaves room for the sticky header */
.how h2 { font-size: 2rem; margin-bottom: 2rem; }
.steps { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }
.card { background: #1e293b; padding: 1.5rem; border-radius: 12px; max-width: 260px; }
</style>
