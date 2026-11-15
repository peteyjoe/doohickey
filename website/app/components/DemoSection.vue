<template>
  <section id="demo" class="demo">  <!-- matches the header link to="#demo" -->
    <h2>Demo</h2>
    <p>See the key in action.</p>
    <!-- placeholder box, swap for a <video> or screenshot once the team has one -->
    <div class="placeholder">Demo video coming soon</div>
  </section>
</template>

<style scoped>
.demo { padding: 4rem 1rem; text-align: center; scroll-margin-top: 80px; }
.placeholder {
  max-width: 640px;
  margin: 2rem auto 0;
  padding: 6rem 1rem;
  border: 2px dashed #334155;  /* dashed border so it reads as "empty slot" */
  border-radius: 12px;
  color: #94a3b8;
}
</style>