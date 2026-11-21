<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'

// 只有 Electron 外壳（preload 注入 window.suoyu）才自绘窗口按钮；
// 浏览器里直接打开页面时整块不渲染，不会多出三个点不动的按钮。
const shell = typeof window !== 'undefined' ? window.suoyu : null
const enabled = Boolean(shell && shell.platform !== 'darwin')
const maximized = ref(false)
let off = null

onMounted(() => {
  if (!enabled) return
  maximized.value = Boolean(shell.isMaximized())
  off = shell.onMaximize((v) => {
    maximized.value = v
  })
})

onBeforeUnmount(() => off && off())
</script>

<template>
  <div v-if="enabled" class="winctl">
    <button class="wc-btn" type="button" title="最小化" aria-label="最小化" @click="shell.minimize()">
      <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.2 6h7.6" /></svg>
    </button>
    <button
      class="wc-btn"
      type="button"
      :title="maximized ? '向下还原' : '最大化'"
      :aria-label="maximized ? '向下还原' : '最大化'"
      @click="shell.toggleMaximize()"
    >
      <svg v-if="!maximized" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
        <rect x="2.4" y="2.4" width="7.2" height="7.2" rx="0.8" />
      </svg>
      <svg v-else width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
        <rect x="2.2" y="3.8" width="6" height="6" rx="0.8" />
        <path d="M4.4 3.4V2.2h5.4v5.4H8.4" />
      </svg>
    </button>
    <button class="wc-btn close" type="button" title="关闭" aria-label="关闭" @click="shell.close()">
      <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.6 2.6l6.8 6.8M9.4 2.6L2.6 9.4" /></svg>
    </button>
  </div>
</template>
