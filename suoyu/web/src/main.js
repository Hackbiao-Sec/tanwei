import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import 'element-plus/dist/index.css'
import '@/styles/base.css'
import '@/styles/element-dark.css'
import App from './App.vue'
import router from './router'
import { useUiStore } from './stores'

// 桌面外壳（preload 注入 window.suoyu）里窗口是没有系统标题栏的，
// 顶栏要自己当拖动区、右侧要留出自绘按钮的位置，先在根节点打个标记。
if (window.suoyu) document.documentElement.classList.add('is-desktop')

// 重新构建会换掉 chunk 文件名并删掉旧文件，浏览器缓存的入口再去 import 就会 404。
// 这里整页重载一次去拿新构建；只重试一次，避免真正缺文件时反复刷新。
const CHUNK_RELOAD_KEY = 'suoyu.chunkReload'
window.addEventListener('vite:preloadError', () => {
  if (sessionStorage.getItem(CHUNK_RELOAD_KEY)) return
  sessionStorage.setItem(CHUNK_RELOAD_KEY, '1')
  window.location.reload()
})

const app = createApp(App)
const pinia = createPinia()
app.use(pinia)
app.use(router)
app.use(ElementPlus, { locale: zhCn, size: 'small', zIndex: 3000 })

useUiStore(pinia).boot()

app.mount('#app')
sessionStorage.removeItem(CHUNK_RELOAD_KEY)

// 页面长期挂着时前端可能已经被重新构建，旧 chunk 会被删掉，点菜单就白屏。
// 定期比对服务端构建号，不一致就挂一条可点的刷新提示。
function showBuildBanner() {
  if (document.getElementById('suoyu-build-banner')) return
  const bar = document.createElement('div')
  bar.id = 'suoyu-build-banner'
  bar.textContent = '前端有新构建，点这里刷新页面'
  bar.style.cssText = 'position:fixed;left:50%;top:14px;transform:translateX(-50%);z-index:99999;' +
    'padding:9px 18px;border-radius:8px;cursor:pointer;font:13px/1.4 "Microsoft YaHei",Segoe UI,sans-serif;' +
    'color:#1b1205;background:#f0b352;box-shadow:0 6px 22px rgba(0,0,0,.45)'
  bar.onclick = () => window.location.reload()
  document.body.appendChild(bar)
}

let bootBuild = null
let buildNotified = false
async function checkBuild() {
  try {
    const r = await fetch('/api/status', { cache: 'no-store' })
    const d = await r.json()
    if (!d || !d.build) return
    if (!bootBuild) { bootBuild = d.build; return }
    if (d.build !== bootBuild && !buildNotified) {
      buildNotified = true
      showBuildBanner()
    }
  } catch (e) { /* 引擎重启中，下一轮再看 */ }
}
checkBuild()
window.setInterval(checkBuild, 45000)
document.addEventListener('visibilitychange', () => { if (!document.hidden) checkBuild() })
