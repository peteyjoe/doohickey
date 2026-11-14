<template>
  <section id="team" class="team">  <!-- matches the header link to="#team" -->
    <h2>Team</h2>
    <div class="members">
      <div v-for="m in members" :key="m.name" class="card">
        <h3>{{ m.name }}</h3>
        <p>{{ m.role }}</p>
      </div>
    </div>
  </section>
</template>

<script setup>
// fill in real names and roles once teammates reply
const members = [
  { name: 'Bryan', role: 'Front end' },
  { name: 'Peter', role: 'TBD' },
]
</script>

<style scoped>
.team { padding: 4rem 1rem; text-align: center; scroll-margin-top: 80px; }
.members { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; margin-top: 2rem; }
.card { background: #1e293b; padding: 1.5rem; border-radius: 12px; min-width: 200px; }
</style>