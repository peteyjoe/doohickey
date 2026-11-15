// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  modules: ['@nuxt/hints', '@nuxt/ui', '@nuxt/test-utils/module'],
  compatibilityDate: '2025-07-15',
  css: ['~/assets/css/main.css'],
  ui: { fonts: false },
  colorMode: { preference: 'light' },
  app: { head: { title: 'DOOHICKEY · Serial Lab', meta: [{ name: 'description', content: 'Test the DOOHICKEY USB CDC ACM connection with Web Serial.' }] } },
  devtools: { enabled: true }
})
