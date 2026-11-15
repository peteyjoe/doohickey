<template>
  <section id="about" class="about">
    <div class="inner">
      <h2>About us</h2>

      <div class="intro">
        <p class="statement">Our goal is to bring security, affordability, and portability together in one key.</p>
        <p class="body">
          Strong account security shouldn't depend on how much you can spend or what you have to carry.
          The DoohicKEY is a FIDO2 security key for anyone who lives online: social media, banking and
          investing, and the two-factor logins on every student app.
        </p>
      </div>

      <ul class="pillars">
        <li v-for="p in pillars" :key="p.title" class="pillar">
          <h3>{{ p.title }}</h3>
          <p>{{ p.text }}</p>
        </li>
      </ul>

      <p class="origin">Built for SunHacks 2026.</p>
    </div>
  </section>
</template>

<script setup>
// edit the words here
const pillars = [
  {
    title: 'Security',
    text: "Your login is proven by a key you hold, not a password someone can steal. A FIDO2 key only answers the real site, so a look-alike login page gets nothing.",
  },
  {
    title: 'Affordability',
    text: "Hardware keys can be expensive. We built ours on the RP2350, a low-cost microcontroller, so protecting your accounts doesn't take a big budget.",
  },
  {
    title: 'Portability',
    text: "It's small enough for a keychain. Plug it into a computer with a USB port, tap it, and you're signed in. No phone or app needed.",
  },
]
</script>

<style scoped>
.about { padding: 7rem 0 6rem; background: var(--left); color: var(--cream); }
.inner { max-width: 1100px; margin: 0 auto; padding: 0 2rem; }
h2 { margin: 0 0 3rem; font-size: clamp(2rem, 4vw, 3rem); line-height: 1.1; color: var(--cream); }

/* big statement on the left, supporting paragraph on the right */
.intro { display: grid; grid-template-columns: 1.1fr 1fr; gap: 3rem 5rem; align-items: end; margin-bottom: 5rem; }
.statement { margin: 0; max-width: 24ch; font-size: clamp(1.6rem, 2.8vw, 2.4rem); font-weight: 500; line-height: 1.25; color: var(--cream); }
.body { margin: 0; max-width: 48ch; font-size: 1.05rem; line-height: 1.7; color: var(--muted); }

/* three pillars, thin line on top of each */
.pillars { display: grid; grid-template-columns: repeat(3, 1fr); gap: 2.5rem; margin: 0; padding: 0; list-style: none; }
.pillar { padding-top: 1.5rem; border-top: 1px solid rgba(243, 223, 199, 0.22); }
h3 { margin: 0 0 0.75rem; font-size: 1.3rem; font-weight: 500; color: var(--cream); }
.pillar p { margin: 0; max-width: 36ch; font-size: 0.97rem; line-height: 1.7; color: var(--muted); }

.origin { margin: 4rem 0 0; font-size: 0.85rem; color: var(--muted); }

@media (max-width: 800px) {
  .about { padding: 4rem 0; }
  .intro { grid-template-columns: 1fr; gap: 1.5rem; margin-bottom: 3rem; }
  .pillars { grid-template-columns: 1fr; gap: 2rem; }
  .origin { margin-top: 3rem; }
}
</style>