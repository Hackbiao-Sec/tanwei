<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { NAV } from '@/router'
import { useAuthStore, useUiStore } from '@/stores'
import { activeTasks } from '@/api/endpoints'
import Icon from '@/components/Icon.vue'
import WindowControls from '@/components/WindowControls.vue'

const auth = useAuthStore()
const ui = useUiStore()
const route = useRoute()
const router = useRouter()

const version = ref('')
// 心跳定时器要在卸载时清掉，不然换登录态后旧实例还在打接口
let timer = null
const runningCount = ref(0)
const engineOk = ref(true)
const collapsed = computed(() => ui.collapsed)

const pageTitle = computed(() => route.meta?.title || '仪表盘')
const contentEl = ref(null)
watch(
  () => route.fullPath,
  () => {
    if (contentEl.value) contentEl.value.scrollTop = 0
  },
)
const parentPath = computed(() => route.meta?.parent || '')
const parentTitle = computed(() => {
  for (const g of NAV) for (const it of g.items) if (it.path === parentPath.value) return it.title
  return ''
})

function isActive(path) {
  if (route.path === path) return true
  return parentPath.value === path
}

async function refreshBadges() {
  // 引擎状态以 /api/status 为准：任务接口偶发失败不代表引擎挂了
  try {
    const res = await fetch('/api/status')
    const data = res.ok ? await res.json() : null
    engineOk.value = Boolean(data && data.ok)
    if (data && data.version) version.value = data.version
  } catch {
    engineOk.value = false
  }
  try {
    const res = await activeTasks()
    runningCount.value = Number(res.running || 0) + Number(res.pending || 0)
  } catch {
    runningCount.value = 0
  }
}

async function boot() {
  try {
    const res = await fetch('/api/version')
    if (res.ok) version.value = (await res.json()).version || ''
  } catch {
    /* 版本号拿不到不影响使用 */
  }
  refreshBadges()
  timer = setInterval(refreshBadges, 8000)
}

async function doLogout() {
  await auth.logout()
  router.replace('/login')
}

onMounted(boot)
onBeforeUnmount(() => timer && clearInterval(timer))
</script>

<template>
  <div class="app">
    <aside class="sidebar" :class="{ mini: collapsed }">
      <div class="sidebar-brand">
        <span class="brand-mark"><Icon name="radar" :size="17" /></span>
        <span class="brand-text" v-show="!collapsed">
          <span class="brand-name">天鉴·索舆</span>
          <span class="brand-sub">SUOYU RECON</span>
        </span>
      </div>

      <nav class="sidebar-nav">
        <div v-for="g in NAV" :key="g.group" class="nav-group">
          <div class="nav-label" v-show="!collapsed">{{ g.group }}</div>
          <button
            v-for="it in g.items"
            :key="it.path"
            class="nav-item"
            :class="{ active: isActive(it.path) }"
            :title="it.title + ' · ' + it.desc"
            @click="router.push(it.path)"
          >
            <Icon :name="it.icon" :size="15" />
            <span v-show="!collapsed">{{ it.title }}</span>
            <span
              v-if="it.path === '/tasks' && runningCount && !collapsed"
              class="nav-badge live"
            >{{ runningCount }}</span>
          </button>
        </div>
      </nav>

      <div class="sidebar-foot">
        <div class="engine-pill" :class="engineOk ? 'ok' : 'err'">
          <span class="status-dot" :class="engineOk ? 'ok' : 'err'" />
          <span v-show="!collapsed">{{ engineOk ? '引擎就绪' : '引擎异常' }}</span>
          <span v-if="version && !collapsed" class="mono" style="opacity: 0.6">{{ version }}</span>
        </div>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <button class="btn ghost sm" :title="collapsed ? '展开菜单' : '收起菜单'" @click="ui.toggleCollapsed()">
          <Icon name="menu" :size="14" />
        </button>
        <div class="topbar-title">
          <span class="page-title">
            <template v-if="parentTitle">
              <span class="muted" style="font-size: 12px; font-weight: 400">{{ parentTitle }} / </span>
            </template>
            {{ pageTitle }}
          </span>
        </div>
        <div class="right flex gap-8">
          <!-- 页面自己有页头动作（刷新 / 一键收集全）时不再重复放全局按钮，否则两排同名按钮挤在一起 -->
          <button v-if="!route.meta?.ownActions" class="btn primary sm" @click="router.push('/oneclick')">
            <Icon name="bolt" :size="13" />
            <span>一键收集全</span>
          </button>
          <button class="btn sm" title="切换主题" @click="ui.toggleTheme()">
            <Icon :name="ui.theme === 'dark' ? 'sun' : 'moon'" :size="14" />
          </button>
          <div class="flex gap-6" style="padding-left: 6px; border-left: 1px solid var(--line)">
            <span class="tag cyan">{{ auth.user || 'admin' }}</span>
            <button class="btn ghost sm" title="退出登录" @click="doLogout">
              <Icon name="close" :size="13" />
            </button>
          </div>
        </div>
        <WindowControls />
      </header>

      <main ref="contentEl" class="content">
        <!-- 换路由时把内层滚动容器复位；不这样做 hash 跳转后会继承上一个页面的滚动位置 -->
        <router-view v-slot="{ Component }">
          <component :is="Component" :key="route.fullPath" />
        </router-view>
      </main>
    </div>
  </div>
</template>
