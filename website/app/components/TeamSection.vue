<template>
  <section id="team" class="team">
    <div class="inner">
      <h2>Team</h2>
      <ul class="members">
        <li v-for="m in members" :key="m.name" class="member">
          <span class="name">{{ m.name }}</span>
          <span class="role">{{ m.role }}</span>
        </li>
      </ul>
    </div>
  </section>
</template>

<script setup>
// add or change people here
const members = [
  { name: 'Bryan Ramirez', role: 'Front end' },
  { name: 'Peter Forbes', role: 'Back end' },
  { name: 'Joshua Klepinger', role: 'Full stack' },
  { name: 'Isreal Estrada', role: 'System Designer' },
]
</script>

<style scoped>
.team { padding: 7rem 0 6rem; background: var(--left); color: var(--cream); }
.inner { max-width: 1100px; margin: 0 auto; padding: 0 2rem; }
h2 { margin: 0 0 3rem; font-size: clamp(2rem, 4vw, 3rem); line-height: 1.1; color: var(--cream); }
/* auto-fit = as many columns as fit, wraps on small screens */
.members { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 2rem; margin: 0; padding: 0; list-style: none; }
.member { display: flex; flex-direction: column; gap: 0.3rem; padding-top: 1.25rem; border-top: 2px solid var(--orange); }
.name { font-size: 1.25rem; font-weight: 500; color: var(--cream); }
.role { font-size: 0.95rem; color: var(--muted); }

@media (max-width: 800px) { .team { padding: 4rem 0; } }
</style>