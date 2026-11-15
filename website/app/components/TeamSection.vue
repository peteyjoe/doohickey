<template>
  <section id="team" class="team">
    <div class="inner">
      <h2>Team</h2>
      <p class="lead">The people behind The DoohicKEY, built at SunHacks 2026.</p>

      <ul class="members">
        <li v-for="m in members" :key="m.name" class="card">
          <div class="portrait">
            <!-- shows a photo if you add one, otherwise the initials -->
            <img v-if="m.photo" :src="m.photo" :alt="m.name" />
            <span v-else class="initials" aria-hidden="true">{{ initials(m.name) }}</span>
          </div>
          <div class="info">
            <span class="name">{{ m.name }}</span>
            <span class="role">{{ m.role }}</span>
          </div>
        </li>
      </ul>
    </div>
  </section>
</template>

<script setup>
// add or change people here.
// To use a photo, put the image in website/public/team/ and add photo: '/team/bryan.jpg'
const members = [
  { name: 'Bryan Ramirez', role: 'Front end' },
  { name: 'Peter Forbes', role: 'Back end' },
  { name: 'Joshua Klepinger', role: 'Full stack' },
  { name: 'Isreal Estrada', role: '3D Artist' },
]

// "Bryan Ramirez" becomes "BR"
function initials(name) {
  return name.split(' ').map((w) => w[0]).join('').slice(0, 2).toUpperCase()
}
</script>

<style scoped>
.team { padding: 7rem 0 6rem; background: var(--right); color: var(--cream); }
.team *, .team *::before, .team *::after { box-sizing: border-box; }
.inner { max-width: 1100px; margin: 0 auto; padding: 0 2rem; }
h2 { margin: 0 0 1rem; font-size: clamp(2rem, 4vw, 3rem); line-height: 1.1; color: var(--cream); }
.lead { margin: 0 0 3rem; color: var(--muted); }

/* auto-fit = as many columns as fit, wraps on small screens */
.members { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin: 0; padding: 0; list-style: none; }
.card { overflow: hidden; background: var(--plate); border: 1px solid rgba(243, 223, 199, 0.08); transition: transform 0.2s, border-color 0.2s; }
.card:hover { transform: translateY(-4px); border-color: rgba(240, 100, 44, 0.6); }

.portrait { position: relative; display: grid; place-items: center; aspect-ratio: 1 / 0.85; background: linear-gradient(145deg, var(--plate), var(--plate-dark)); }
.portrait::after { content: ''; position: absolute; left: 0; bottom: 0; width: 56px; height: 6px; background: var(--orange); } /* small orange tab, same as the hero */
.portrait img { width: 100%; height: 100%; object-fit: cover; }
.initials { display: grid; place-items: center; width: 112px; height: 112px; border: 2px solid var(--orange); border-radius: 50%; font-size: 2.4rem; font-weight: 600; letter-spacing: 0.02em; color: var(--cream); }

.info { display: flex; flex-direction: column; gap: 0.25rem; padding: 1.25rem 1.5rem 1.5rem; }
.name { font-size: 1.2rem; font-weight: 500; color: var(--cream); }
.role { font-size: 0.95rem; color: var(--muted); }

@media (max-width: 800px) { .team { padding: 4rem 0; } }
@media (prefers-reduced-motion: reduce) {
  .card { transition: none; }
  .card:hover { transform: none; }
}
</style>