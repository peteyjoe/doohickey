<script setup lang="ts">
import SiteHeader from '~/components/SiteHeader.vue'


</script>

<template>
  <UApp>  <!-- required wrapper for Nuxt UI -->
    <NuxtRouteAnnouncer />
    <SiteHeader />
    <HeroSection />
    <HowItWorks />
    <FlashSection />
    <TeamSection />
  </UApp>
</template>