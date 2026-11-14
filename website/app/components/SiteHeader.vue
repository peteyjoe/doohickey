<template>
  <UHeader title="Le-Key">
    <UNavigationMenu :items="items" />  <!-- default slot = center nav links -->
    <template #right>
      <UColorModeButton />  <!-- light/dark toggle, built in -->
    </template>
  </UHeader>
</template>

<script setup>
// to: '#how' jumps to an element with id="how" on the page
const items = [
  { label: 'How it works', to: '#how' },
  { label: 'Demo', to: '#demo' },
  { label: 'Team', to: '#team' },
]
</script>