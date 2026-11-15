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
  { title: '1. Insert', text: 'Insert the key into your computer\'s USB port.' },
  { title: '2. Transfer The uf2 file', text: 'Transfer the uf2 file to the key.' },
  { title: '3. confirm', text: 'Confirm the key is recognized by your computer and ready to use.' },
]
</script>

<style scoped>
.how { padding: 4rem 1rem; text-align: center; scroll-margin-top: 80px; } /* leaves room for the sticky header */
.how h2 { font-size: 2rem; margin-bottom: 2rem; }
.steps { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }
.card { background: #1e293b; padding: 1.5rem; border-radius: 12px; max-width: 260px; }
</style>