import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

// 构建产物直接落在后端静态目录，后端 / 只读挂载它，无需额外 nginx
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  base: './',
  build: {
    outDir: '../arlx/static',
    emptyOutDir: true,
    chunkSizeWarningLimit: 2400,
  },
  server: {
    port: 5199,
    proxy: {
      '/api': { target: 'http://127.0.0.1:5113', changeOrigin: true },
    },
  },
})
