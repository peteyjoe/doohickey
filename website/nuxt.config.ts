export default defineNuxtConfig({
  css: ['~/assets/css/main.css'], // loads your stylesheet on every page
  modules: ['@nuxt/hints', '@nuxt/test-utils/module', '@nuxt/ui'],
  compatibilityDate: '2025-07-15',
  devtools: { enabled: true }
})
