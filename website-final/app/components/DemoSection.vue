<template>
  <section id="demo" class="demo">
    <div class="inner">
      <h2>Demo</h2>
      <p class="lead">See the key in action.</p>
      <!-- the file lives in public/video/demo.mp4, so the URL is /video/demo.mp4 -->
      <video class="player" src="/video/demo.mp4" controls playsinline preload="metadata"></video>
    </div>
  </section>
</template>

<style scoped>
.demo { padding: 7rem 0; background: var(--left); color: var(--cream); }
.inner { max-width: 1100px; margin: 0 auto; padding: 0 2rem; }
h2 { margin: 0 0 1rem; font-size: clamp(2rem, 4vw, 3rem); line-height: 1.1; color: var(--cream); }
.lead { margin: 0 0 2.5rem; color: var(--muted); }
/* max-height keeps a tall phone video from taking over the whole page */
.player { display: block; width: 100%; max-height: 75vh; background: var(--plate-dark); object-fit: contain; }

@media (max-width: 800px) { .demo { padding: 4rem 0; } }
</style>