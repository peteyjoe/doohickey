<template>
  <section id="how" class="how">
    <div class="inner">
      <h2>How it works</h2>
      <!-- <ol> = ordered list, because these really are steps in order -->
      <ol class="steps">
        <li v-for="(step, i) in steps" :key="step.title" class="step">
          <span class="num">{{ i + 1 }}</span>
          <h3>{{ step.title }}</h3>
          <p>{{ step.text }}</p>
        </li>
      </ol>
    </div>
  </section>
</template>

<script setup>
// edit the words here
const steps = [
  { title: 'Insert', text: "Insert the key into your computer's USB port." },
  { title: 'Transfer the UF2 file', text: 'Transfer the UF2 file to the key.' },
  { title: 'Confirm', text: 'Confirm the key is recognized by your computer and ready to use.' },
]
</script>

<style scoped>
.how { padding: 7rem 0; background: var(--right); color: var(--cream); }
.inner { max-width: 1100px; margin: 0 auto; padding: 0 2rem; }
h2 { margin: 0 0 3rem; font-size: clamp(2rem, 4vw, 3rem); line-height: 1.1; color: var(--cream); }
.steps { display: grid; grid-template-columns: repeat(3, 1fr); margin: 0; padding: 0; list-style: none; background: var(--plate); }
.step { padding: 2.5rem 2rem 3rem; }
.step + .step { border-left: 1px solid rgba(243, 223, 199, 0.12); } /* thin line between steps */
.num { display: block; width: 48px; margin-bottom: 1.5rem; padding-bottom: 0.6rem; border-bottom: 6px solid var(--orange); font-size: 2rem; font-weight: 600; line-height: 1; color: var(--cream); }
h3 { margin: 0 0 0.6rem; font-size: 1.2rem; font-weight: 500; color: var(--cream); }
p { margin: 0; max-width: 32ch; font-size: 0.95rem; line-height: 1.65; color: var(--muted); }

@media (max-width: 800px) {
  .how { padding: 4rem 0; }
  .steps { grid-template-columns: 1fr; }
  .step + .step { border-left: 0; border-top: 1px solid rgba(243, 223, 199, 0.12); }
}
</style>