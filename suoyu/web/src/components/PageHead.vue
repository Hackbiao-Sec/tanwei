<script setup>
defineProps({
  title: { type: String, default: '' },
  desc: { type: String, default: '' },
})
</script>

<template>
  <div class="page-head">
    <div class="page-head-text">
      <h2 class="page-h">{{ title }}</h2>
      <p v-if="desc" class="page-d">{{ desc }}</p>
    </div>
    <div class="page-head-actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<style scoped>
.page-head-text { min-width: 0; }
.page-h { margin: 0; font-size: 16px; font-weight: 650; letter-spacing: 0.2px; color: var(--text); }
.page-d { margin: 4px 0 0; font-size: 12px; color: var(--muted); line-height: 1.6; }
.page-head-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
</style>
