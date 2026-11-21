<script setup>
import { onMounted } from 'vue'
import { useUiStore } from '@/stores'

const ui = useUiStore()
onMounted(() => ui.boot())
</script>

<template>
  <router-view />
</template>
