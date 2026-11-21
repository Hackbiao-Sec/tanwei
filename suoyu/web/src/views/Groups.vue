<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { groups, diff as fetchDiff } from '@/api/endpoints'

const router = useRouter()
const keyword = ref('')
const mode = ref('root')
const items = ref([])
const changes = ref({})
const loading = ref(false)

const sums = computed(() => items.value.reduce((s, i) => {
  s.total += i.cnt || i.total || 0
  s.web += i.web || 0
  s.applet += i.applet || 0
  s.app += i.app || 0
  return s
}, { total: 0, web: 0, applet: 0, app: 0 }))

async function loadGroups() {
  loading.value = true
  try {
    const res = await groups({
      keyword: keyword.value.trim() || undefined,
      limit: 300,
      by: mode.value === 'task' ? 'task' : undefined,
    })
    items.value = res.items || []
    if (mode.value === 'root') {
      const df = await fetchDiff().catch(() => ({ items: [] }))
      changes.value = {}
      for (const d of df.items || []) changes.value[d.root_domain] = d
    } else {
      changes.value = {}
    }
  } finally {
    loading.value = false
  }
}

function switchMode(m) {
  if (mode.value === m) return
  mode.value = m
  loadGroups()
}

function openTask(g) {
  router.push({ path: `/tasks/${g.task_id}` })
}

// 带着任务 + 资产面跳资产库，看到的就是这一组的这一面
function openAssets(g, surface) {
  const q = {}
  if (g.task_id) q.task = g.task_id
  if (surface) q.surface = surface
  router.push({ path: '/assets', query: q })
}

// 根域分组没有任务限定，用根域 + 资产面定位同一簇里的这一面
function openRootAssets(root, surface) {
  const q = { root }
  if (surface) q.surface = surface
  router.push({ path: '/assets', query: q })
}

function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

const STATUS_LABEL = { done: '完成', running: '进行中', stopped: '已停', error: '失败', pending: '待跑' }

onMounted(loadGroups)
</script>

<template>
  <div class="stack">
    <PageHead
      title="资产组"
      desc="两种看法：按根域看全局资产簇，按任务看每个任务各自收进来多少；小程序 / APP / Web 分开计数"
    >
      <template #actions>
        <div class="seg">
          <button :class="{ on: mode === 'root' }" @click="switchMode('root')">按根域</button>
          <button :class="{ on: mode === 'task' }" @click="switchMode('task')">按任务</button>
        </div>
        <input
          v-model="keyword"
          class="input"
          style="width: 240px"
          :placeholder="mode === 'root' ? '搜索根域，回车查询' : '搜索任务名 / 目标 / ID'"
          @keyup.enter="loadGroups"
        />
        <button class="btn sm" @click="loadGroups"><Icon name="search" :size="13" />查询</button>
      </template>
    </PageHead>

    <div class="metric-row">
      <div class="metric">
        <span class="metric-label">{{ mode === 'root' ? 'GROUPS' : 'TASKS' }}</span>
        <span class="metric-value">{{ items.length }}</span>
        <span class="metric-foot">{{ mode === 'root' ? '根域资产组' : '有资产的任务' }}</span>
      </div>
      <div class="metric">
        <span class="metric-label">ASSETS</span>
        <span class="metric-value">{{ sums.total.toLocaleString() }}</span>
        <span class="metric-foot">组内资产合计</span>
      </div>
      <div class="metric">
        <span class="metric-label">WEB</span>
        <span class="metric-value">{{ sums.web.toLocaleString() }}</span>
        <span class="metric-foot">域名 / 站点 / 服务</span>
      </div>
      <div class="metric">
        <span class="metric-label">小程序 / APP</span>
        <span class="metric-value">{{ sums.applet }} / {{ sums.app }}</span>
        <span class="metric-foot">移动端资产</span>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <span>
          <Icon name="group" :size="13" />{{ mode === 'root' ? '根域列表' : '任务列表' }}
        </span>
        <span class="mono muted">{{ loading ? 'loading…' : items.length + (mode === 'root' ? ' groups' : ' tasks') }}</span>
      </div>
      <div class="table-wrap">
        <table class="table">
          <template v-if="mode === 'root'">
            <thead>
              <tr>
                <th>根域</th><th>资产</th><th>站点</th><th>域名</th><th>Web</th><th>小程序</th><th>APP</th>
                <th>独立 IP</th><th>最近存活</th><th>新增</th><th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="g in items" :key="g.root_domain">
                <td class="mono">
                  <span class="flex gap-6">
                    <Icon name="globe" :size="13" style="color: var(--cyan-2)" />
                    {{ g.root_domain }}
                  </span>
                </td>
                <td class="mono">{{ g.cnt }}</td>
                <td class="mono">{{ g.sites }}</td>
                <td class="mono">{{ g.domains }}</td>
                <td class="mono">
                  <a class="num-link" @click="openRootAssets(g.root_domain, 'web')">{{ g.web || 0 }}</a>
                </td>
                <td class="mono">
                  <a class="num-link" :class="{ dim: !g.applet }" @click="openRootAssets(g.root_domain, 'applet')">{{ g.applet || 0 }}</a>
                </td>
                <td class="mono">
                  <a class="num-link" :class="{ dim: !g.app }" @click="openRootAssets(g.root_domain, 'app')">{{ g.app || 0 }}</a>
                </td>
                <td class="mono">{{ g.ips }}</td>
                <td class="mono muted">{{ fmtTime(g.last_seen) }}</td>
                <td>
                  <span v-if="changes[g.root_domain]?.new_count" class="tag warn">
                    +{{ changes[g.root_domain].new_count }}
                  </span>
                  <span v-else class="muted">—</span>
                </td>
                <td style="text-align: right">
                  <button class="btn xs" @click="router.push({ path: `/group/${g.root_domain}` })">
                    <Icon name="eye" :size="11" />查看
                  </button>
                </td>
              </tr>
              <tr v-if="!items.length && !loading">
                <td colspan="11"><div class="empty"><Icon name="group" :size="22" />还没有根域资产，先跑一个任务</div></td>
              </tr>
            </tbody>
          </template>

          <template v-else>
            <thead>
              <tr>
                <th>任务</th><th>资产</th><th>Web</th><th>小程序</th><th>APP</th><th>网段</th><th>主体/邮箱</th>
                <th>状态</th><th>最近入库</th><th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="g in items" :key="g.task_id">
                <td>
                  <div class="task-cell">
                    <span class="ellipsis">{{ g.name || g.target || g.task_id }}</span>
                    <span class="mono muted" style="font-size: 11px">{{ g.task_id }}</span>
                  </div>
                </td>
                <td class="mono">{{ g.total }}</td>
                <td class="mono">
                  <a class="num-link" @click="openAssets(g, 'web')">{{ g.web }}</a>
                </td>
                <td class="mono">
                  <a class="num-link" :class="{ dim: !g.applet }" @click="openAssets(g, 'applet')">{{ g.applet }}</a>
                </td>
                <td class="mono">
                  <a class="num-link" :class="{ dim: !g.app }" @click="openAssets(g, 'app')">{{ g.app }}</a>
                </td>
                <td class="mono">
                  <a class="num-link" :class="{ dim: !g.netblock }" @click="openAssets(g, 'netblock')">{{ g.netblock }}</a>
                </td>
                <td class="mono muted">{{ g.meta }}</td>
                <td>
                  <span class="tag" :class="g.status === 'done' ? 'ok' : g.status === 'running' ? 'cyan' : 'info'">
                    {{ STATUS_LABEL[g.status] || g.status || '-' }}
                  </span>
                </td>
                <td class="mono muted">{{ fmtTime(g.last_seen || g.updated_at) }}</td>
                <td style="text-align: right">
                  <button class="btn xs" @click="openTask(g)"><Icon name="eye" :size="11" />任务</button>
                  <button class="btn xs ghost" @click="openAssets(g, '')">资产</button>
                </td>
              </tr>
              <tr v-if="!items.length && !loading">
                <td colspan="10"><div class="empty"><Icon name="layers" :size="22" />还没有任务</div></td>
              </tr>
            </tbody>
          </template>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.task-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
  max-width: 320px;
}
.num-link {
  color: var(--cyan-2);
  cursor: pointer;
  border-bottom: 1px dashed transparent;
}
.num-link:hover {
  border-bottom-color: var(--cyan-2);
}
.num-link.dim {
  color: var(--text-3);
}
</style>
