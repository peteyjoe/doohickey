<template>
  <section class="stage">
    <!-- giant ghost word on the right panel, decoration only -->
    <div class="ghost" aria-hidden="true">Doohic<br />KEY</div>

    <!-- this top bar replaces SiteHeader.vue -->
    <header class="bar">
      <a class="brand" href="#">The DoohicKEY<span>.</span></a>
      <nav class="links" aria-label="Main">
        <a href="#about">About</a>
        <a href="#how">How it works</a>
        <a href="#demo">Demo</a>
        <a href="#flash">Flash</a>
        <a href="#team">Team</a>
      </nav>
    </header>

    <h1 class="headline">The<br />DoohicKEY</h1>

    <!-- center: a chrome padlock drawn in code (no image file needed).
         To use a photo instead, delete the <svg> and add:
         <img class="lock" src="/lock.png" alt="Padlock" />  (file goes in public/) -->
    <div class="piece">
      <div class="product">
        <svg class="lock" viewBox="0 0 400 480" role="img" aria-label="A chrome padlock">
          <defs>
            <!-- brushed steel for the shackle -->
            <linearGradient id="dk-steel" x1="0" x2="1" y1="0" y2="0">
              <stop offset="0" stop-color="#4f555f" />
              <stop offset="0.22" stop-color="#c3c8d0" />
              <stop offset="0.42" stop-color="#f4f6f9" />
              <stop offset="0.64" stop-color="#99a0aa" />
              <stop offset="1" stop-color="#363a42" />
            </linearGradient>
            <!-- dark chrome for the lock body -->
            <linearGradient id="dk-body" x1="0" x2="1" y1="0" y2="1">
              <stop offset="0" stop-color="#5a606a" />
              <stop offset="0.35" stop-color="#2b2f36" />
              <stop offset="0.7" stop-color="#16181d" />
              <stop offset="1" stop-color="#0d0e11" />
            </linearGradient>
            <!-- bright edge on the top-left, orange bounce light at the bottom-right -->
            <linearGradient id="dk-rim" x1="0" x2="1" y1="0" y2="1">
              <stop offset="0" stop-color="#f2f4f8" />
              <stop offset="0.35" stop-color="#7b828c" />
              <stop offset="0.7" stop-color="#23262b" />
              <stop offset="1" stop-color="#f0642c" stop-opacity="0.65" />
            </linearGradient>
            <linearGradient id="dk-face" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stop-color="#3a3f47" />
              <stop offset="1" stop-color="#14161a" />
            </linearGradient>
            <linearGradient id="dk-sheen" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stop-color="#fff" stop-opacity="0.2" />
              <stop offset="1" stop-color="#fff" stop-opacity="0" />
            </linearGradient>
            <radialGradient id="dk-glow">
              <stop offset="0" stop-color="#f0642c" stop-opacity="0.5" />
              <stop offset="1" stop-color="#f0642c" stop-opacity="0" />
            </radialGradient>
            <filter id="dk-blur" x="-30%" y="-300%" width="160%" height="700%">
              <feGaussianBlur stdDeviation="8" />
            </filter>
          </defs>

          <!-- soft shadow on the floor -->
          <ellipse cx="200" cy="462" rx="120" ry="12" fill="#000" opacity="0.6" filter="url(#dk-blur)" />

          <!-- shackle (the U-shaped bar), drawn first so the body covers its feet -->
          <path d="M128 232 V152 A72 72 0 0 1 272 152 V232" fill="none" stroke="url(#dk-steel)" stroke-width="36" />
          <path d="M119 232 V152 A81 81 0 0 1 281 152 V232" fill="none" stroke="#fff" stroke-opacity="0.18" stroke-width="3" />

          <!-- body -->
          <rect x="60" y="190" width="280" height="250" rx="40" fill="url(#dk-body)" stroke="url(#dk-rim)" stroke-width="3" />
          <rect x="74" y="204" width="252" height="222" rx="30" fill="url(#dk-face)" stroke="#fff" stroke-opacity="0.08" />
          <rect x="84" y="212" width="232" height="64" rx="22" fill="url(#dk-sheen)" />
          <circle cx="200" cy="322" r="100" fill="url(#dk-glow)" />

          <!-- keyhole -->
          <path
            d="M214 321.9 L226 376 Q227 382 220 382 H180 Q173 382 174 376 L186 321.9 A26 26 0 1 1 214 321.9 Z"
            fill="#07080a"
            stroke="#f0642c"
            stroke-opacity="0.8"
            stroke-width="1.5"
          />
        </svg>
      </div>
    </div>

    <a class="next" href="#about" aria-label="Scroll to about us">
      <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M12 4v16M5 13l7 7 7-7" />
      </svg>
    </a>

    <div class="note left">
      <h2>Your login, in your pocket.</h2>
      <p>An open-source FIDO2 security key built on the RP2350. Plug it in, tap it, and you're signed in. No password.</p>
    </div>

    <div class="note right">
      <div>
        <h2>See it work.</h2>
        <p>Watch the demo, or flash firmware onto a board right from your browser.</p>
      </div>
      <a class="play" href="#demo" aria-label="Go to the demo">
        <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><path d="M3 1.5v11l9-5.5z" fill="currentColor" /></svg>
      </a>
    </div>

    <footer class="foot">
      <a class="cta" href="#flash"><span class="cta-bar"></span>Flash your key</a>
      <span class="credit">Built at SunHacks 2026</span>
    </footer>
  </section>
</template>

<style scoped>
/* colors come from main.css (:root), so every section matches */
.stage {
  --h: clamp(380px, 62vh, 600px); /* size of the center area */

  position: relative;
  isolation: isolate;
  overflow: hidden;
  display: grid;
  grid-template-columns: 1fr minmax(240px, 420px) 1fr;
  grid-template-rows: auto 1fr auto auto;
  min-height: 100vh;
  min-height: 100svh;
  background: linear-gradient(90deg, var(--left) 50%, var(--right) 50%); /* the split panels */
  color: var(--cream);
}
.stage *, .stage *::before, .stage *::after { box-sizing: border-box; } /* padding counts inside the width */
.stage a { color: inherit; text-decoration: none; }
.stage a:focus-visible { outline: 2px solid var(--orange); outline-offset: 6px; border-radius: 4px; }

.ghost {
  position: absolute; z-index: -1; left: 50%; top: 2%;
  font-size: clamp(7rem, 19vw, 20rem); font-weight: 600; line-height: 0.86;
  color: var(--ghost); white-space: nowrap; user-select: none; pointer-events: none;
}

/* top bar */
.bar { grid-column: 1 / -1; grid-row: 1; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px 32px; padding: 28px 56px; }
.brand { font-weight: 600; font-size: 1.05rem; }
.brand span { color: var(--orange); }
.links { display: flex; flex-wrap: wrap; gap: 8px 32px; font-size: 0.9rem; color: var(--muted); }
.links a:hover { color: var(--cream); }

/* headline */
.headline { grid-column: 1; grid-row: 2; align-self: center; margin: 0; padding: 0 0 0 72px; font-weight: 600; font-size: clamp(2.75rem, 5vw, 5rem); line-height: 1.08; letter-spacing: -0.01em; color: var(--cream); }

/* center area: the padlock */
.piece { grid-column: 2; grid-row: 2 / span 2; display: grid; place-items: center; }
.product { display: grid; place-items: center; width: 100%; height: var(--h); }
.lock { display: block; height: calc(var(--h) * 0.88); width: auto; max-width: 100%; overflow: visible; }

/* scroll arrow */
.next { grid-column: 3; grid-row: 2; justify-self: end; align-self: center; padding-right: 56px; color: var(--cream); }

/* the two note blocks */
.note { align-self: end; margin-top: 2rem; }
.note h2 { margin: 0 0 0.6rem; font-weight: 500; font-size: 1.1rem; line-height: 1.3; color: var(--cream); }
.note p { margin: 0; max-width: 34ch; font-size: 0.92rem; line-height: 1.65; color: var(--muted); }
.note.left { grid-column: 1; grid-row: 3; justify-self: start; max-width: 440px; padding: 32px 40px 32px 72px; background: var(--plate); }
.note.right { grid-column: 3; grid-row: 3; justify-self: end; display: flex; align-items: center; justify-content: space-between; gap: 32px; width: min(100%, 460px); padding: 32px 56px 32px 40px; background: var(--plate-dark); }
.play { flex: none; display: grid; place-items: center; width: 46px; height: 46px; border: 1.5px solid var(--orange); border-radius: 50%; color: var(--orange); transition: background 0.2s, color 0.2s; }
.play:hover { background: var(--orange); color: var(--left); }

/* footer row */
.foot { grid-column: 1 / -1; grid-row: 4; display: flex; align-items: center; justify-content: space-between; padding: 36px 56px 28px 0; }
.cta { display: inline-flex; align-items: center; gap: 18px; font-size: 0.85rem; font-weight: 500; }
.cta-bar { display: block; width: 96px; height: 12px; background: var(--orange); }
.credit { font-size: 0.8rem; color: var(--muted); }

@media (prefers-reduced-motion: reduce) { .play { transition: none; } }

/* phones and small tablets: one column */
@media (max-width: 900px) {
  .stage { --h: clamp(260px, 38vh, 340px); grid-template-columns: 1fr; grid-template-rows: repeat(6, auto); background: var(--left); }
  .ghost, .next { display: none; }
  .bar { padding: 20px 24px; }
  .headline { grid-column: 1; grid-row: 2; padding: 1.5rem 24px 0; }
  .piece { grid-column: 1; grid-row: 3; margin: 2rem 0 0.5rem; }
  .note.left { grid-column: 1; grid-row: 4; justify-self: stretch; max-width: none; padding: 28px 24px; margin-top: 1rem; }
  .note.right { grid-column: 1; grid-row: 5; width: 100%; padding: 28px 24px; margin-top: 0; }
  .foot { grid-row: 6; padding: 28px 24px 24px 0; }
}
</style>