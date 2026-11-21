<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { deleteTask, listTasks, rerunTask, stopTask } from '@/api/endpoints'

const router = useRouter()
const route = useRoute()
const items = ref([])
const loading = ref(false)
const status = ref('')
const keyword = ref('')
const scope = ref('')
let timer = null

const STATUS = [
  { key: '', label: '全部' },
  { key: 'running', label: '执行中' },
  { key: 'done', label: '已完成' },
  { key: 'stopped', label: '已停止' },
  { key: 'error', label: '异常' },
]
const SCOPE = [
  { key: '', label: '全部任务' },
  { key: 'full', label: '五段全流程' },
  { key: 'part', label: '局部任务' },
]
const statusText = { running: '执行中', done: '已完成', stopped: '已停止', error: '异常', pending: '排队中' }
const statusClass = { running: 'cyan', done: 'ok', stopped: '', error: 'err', pending: 'warn' }

// 构成图的档位：颜色全部走 token，浅色主题下才不会白字白底
const MIX = [
  { key: 'running', label: '执行中', color: 'var(--cyan)' },
  { key: 'done', label: '已完成', color: 'var(--ok-text)' },
  { key: 'error', label: '异常', color: 'var(--red)' },
  { key: 'stopped', label: '已停止', color: 'var(--muted)' },
  { key: 'pending', label: '排队中', color: 'var(--amber)' },
]

// 五段固定的图标与状态词，模块本身（有哪几段、跑没跑）全部来自后端
const MOD_ICON = { subject: 'building', domain: 'globe', space: 'radar', probe: 'server', deep: 'bug' }
const MOD_STATE = {
  done: { text: '完成', cls: 'ok' },
  running: { text: '进行中', cls: 'run' },
  partial: { text: '部分', cls: 'warn' },
  stalled: { text: '中断', cls: 'err' },
  pending: { text: '待跑', cls: '' },
  skip: { text: '未选', cls: 'skip' },
}

const shown = computed(() => {
  let list = items.value
  if (status.value) list = list.filter((t) => t.status === status.value)
  const k = keyword.value.trim().toLowerCase()
  if (k) list = list.filter((t) => `${t.name} ${t.target}`.toLowerCase().includes(k))
  if (scope.value === 'full') list = list.filter((t) => !t.partial)
  if (scope.value === 'part') list = list.filter((t) => t.partial)
  return list
})

const totals = computed(() => {
  const acc = { tasks: items.value.length, running: 0, done: 0, assets: 0 }
  for (const t of items.value) {
    if (t.status === 'running') acc.running += 1
    if (t.status === 'done') acc.done += 1
    acc.assets += Number(t?.counts?.total || 0)
  }
  return acc
})

// 状态构成：分母是全部任务，跟当前关键词/范围筛选无关，点一下才当筛选入口
const statMix = computed(() => {
  const total = items.value.length || 1
  const rows = MIX.map((m) => {
    const n = items.value.filter((t) => t.status === m.key).length
    return { ...m, n, pct: Math.round((n / total) * 100) }
  })
  const known = rows.reduce((a, r) => a + r.n, 0)
  if (known < items.value.length) {
    const n = items.value.length - known
    rows.push({ key: '__other', label: '其它', color: 'var(--muted-2)', n, pct: Math.round((n / total) * 100) })
  }
  return rows.filter((r) => r.n > 0)
})

// 环图直接用 conic-gradient，不引图表库：段间不描边，色值全部来自 token
const ringStyle = computed(() => {
  const list = statMix.value
  const total = items.value.length
  if (!total || !list.length) return { background: 'conic-gradient(var(--line-strong) 0% 100%)' }
  let acc = 0
  const stops = list.map((r) => {
    const from = acc
    acc += (r.n / total) * 100
    return `${r.color} ${from}% ${acc}%`
  })
  return { background: `conic-gradient(${stops.join(', ')})` }
})

const meta = computed(() => {
  const n = items.value.length || 0
  const part = items.value.filter((t) => t.partial).length
  return {
    full: n - part,
    part,
    avg: n ? num(Math.round(totals.value.assets / n)) : '0',
    rate: n ? Math.round((totals.value.done / n) * 100) : 0,
  }
})

function toggleStatus(key) {
  status.value = status.value === key ? '' : key
}

// 局部任务只摆它真跑的那几段；全流程任务五段全摆
function mods(t) {
  const list = t.modules || []
  if (!t.partial) return list
  const picked = list.filter((m) => (m.stages || []).length)
  return picked.length ? picked : list
}

function skippedCount(t) {
  if (!t.partial) return 0
  return (t.modules || []).filter((m) => !(m.stages || []).length).length
}

// 资产分类：只列条数大于 0 的类型，按条数从多到少
function kindChips(t) {
  const kinds = t?.counts?.kinds || {}
  const labels = t?.counts?.labels || {}
  const rows = Object.entries(kinds)
    .map(([k, v]) => ({ key: k, label: labels[k] || k, n: Number(v || 0) }))
    .filter((r) => r.n > 0)
    .sort((a, b) => b.n - a.n)
  return rows
}

function topKinds(t, max = 8) {
  return kindChips(t).slice(0, max)
}

function restKinds(t, max = 8) {
  const rows = kindChips(t)
  if (rows.length <= max) return 0
  return rows.length - max
}

function restSum(t, max = 8) {
  return kindChips(t).slice(max).reduce((a, r) => a + r.n, 0)
}

function num(n) {
  return Number(n || 0).toLocaleString()
}

async function load() {
  loading.value = true
  try {
    const res = await listTasks({ limit: 300 })
    items.value = res.items || []
  } finally {
    loading.value = false
  }
}

async function act(kind, t) {
  if (kind === 'stop') await stopTask(t.id)
  if (kind === 'rerun') {
    const res = await rerunTask(t.id)
    if (res?.task_id) return router.push(`/tasks/${res.task_id}`)
  }
  if (kind === 'del') {
    if (!confirm(`删除任务「${t.name}」？资产记录会保留。`)) return
    await deleteTask(t.id)
  }
  load()
}

function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function assetLink(t) {
  return `/assets?task_id=${t.id}`
}

watch(() => route.query.status, (v) => { status.value = v || '' })

onMounted(() => {
  status.value = route.query.status || ''
  load()
  timer = setInterval(() => {
    if (items.value.some((t) => t.status === 'running')) load()
  }, 5000)
})

onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div class="stack">
    <PageHead
      title="侦察任务"
      desc="一个任务就是一条流水线：主体 → 域名 → 测绘 → 探测 → 深挖；卡上直接看五段进度和落库资产，点任务名进详情"
    >
      <template #actions>
        <span v-if="loading" class="tag mono">加载中</span>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="13" />刷新</button>
        <button class="btn primary sm" @click="router.push('/oneclick')">
          <Icon name="bolt" :size="13" />一键收集全
        </button>
      </template>
    </PageHead>

    <div class="tk-metrics">
      <div class="tk-metric" style="--tone: var(--cyan)">
        <div class="tk-metric-top"><span>任务总数</span><Icon name="tasks" :size="13" /></div>
        <b class="tk-metric-value mono">{{ totals.tasks }}</b>
        <span class="tk-metric-foot">{{ shown.length }} 条在当前筛选里</span>
      </div>
      <div class="tk-metric" style="--tone: var(--amber)">
        <div class="tk-metric-top"><span>执行中</span><Icon name="play" :size="13" /></div>
        <b class="tk-metric-value mono">{{ totals.running }}</b>
        <span class="tk-metric-foot">{{ totals.running ? '每 5 秒自动刷新' : '现在没有在跑的任务' }}</span>
      </div>
      <div class="tk-metric" style="--tone: var(--ok-text)">
        <div class="tk-metric-top"><span>已完成</span><Icon name="check" :size="13" /></div>
        <b class="tk-metric-value mono">{{ totals.done }}</b>
        <span class="tk-metric-foot">占全部任务 {{ meta.rate }}%</span>
      </div>
      <div class="tk-metric" style="--tone: var(--violet)">
        <div class="tk-metric-top"><span>去重资产</span><Icon name="layers" :size="13" /></div>
        <b class="tk-metric-value mono">{{ num(totals.assets) }}</b>
        <span class="tk-metric-foot">同一资产多处出现只算一次</span>
      </div>
    </div>

    <div class="panel tk-board">
      <div class="panel-head">
        <span><Icon name="chart" :size="13" />任务构成</span>
        <span class="muted tk-hint">点右边任意一档按状态筛，再点一次取消</span>
      </div>
      <div class="panel-body tk-board-body">
        <div class="mix-ring" :style="ringStyle">
          <div class="mix-hole">
            <b class="mono">{{ totals.tasks }}</b>
            <span>个任务</span>
          </div>
        </div>

        <div class="mix-legend">
          <button
            v-for="m in statMix"
            :key="m.key"
            class="mix-row"
            :class="{ on: status === m.key }"
            @click="m.key === '__other' ? null : toggleStatus(m.key)"
          >
            <i class="mix-dot" :style="{ background: m.color }" />
            <span class="mix-name">{{ m.label }}</span>
            <b class="mono">{{ m.n }}</b>
            <span class="mix-pct mono">{{ m.pct }}%</span>
          </button>
          <button class="mix-row" :class="{ on: !status }" @click="status = ''">
            <i class="mix-dot all" />
            <span class="mix-name">全部</span>
            <b class="mono">{{ totals.tasks }}</b>
            <span class="mix-pct mono">100%</span>
          </button>
          <span v-if="!statMix.length" class="muted mix-empty">还没有任务，先建一个</span>
        </div>

        <div class="mix-side">
          <div class="mix-kv"><span>五段全流程</span><b class="mono">{{ meta.full }}</b></div>
          <div class="mix-kv"><span>局部任务</span><b class="mono">{{ meta.part }}</b></div>
          <div class="mix-kv"><span>平均资产 / 任务</span><b class="mono">{{ meta.avg }}</b></div>
          <div class="mix-kv"><span>完成率</span><b class="mono">{{ meta.rate }}%</b></div>
        </div>
      </div>
    </div>

    <div class="tk-filter">
      <div class="seg">
        <button v-for="s in STATUS" :key="s.key" :class="{ on: status === s.key }" @click="status = s.key">
          {{ s.label }}
        </button>
      </div>
      <div class="seg">
        <button v-for="s in SCOPE" :key="s.key" :class="{ on: scope === s.key }" @click="scope = s.key">
          {{ s.label }}
        </button>
      </div>
      <label class="tk-search">
        <Icon name="search" :size="13" />
        <input v-model="keyword" placeholder="搜任务名 / 目标" />
        <button v-if="keyword" class="tk-clear" title="清空" @click="keyword = ''">
          <Icon name="close" :size="11" />
        </button>
      </label>
      <span class="tk-count mono">{{ shown.length }} / {{ totals.tasks }}</span>
    </div>

    <div class="task-grid">
      <article v-for="t in shown" :key="t.id" class="task-card" :class="`k-${t.status}`">
        <header class="tc-head">
          <router-link class="tc-name ellipsis" :to="`/tasks/${t.id}`">{{ t.name }}</router-link>
          <span class="tag" :class="statusClass[t.status]">{{ statusText[t.status] || t.status }}</span>
          <span class="tag" :class="t.partial ? 'info' : 'cyan'">{{ t.partial ? '局部' : '全流程' }}</span>
          <div class="tc-actions">
            <button v-if="t.status === 'running'" class="btn xs" title="停止" @click="act('stop', t)">
              <Icon name="stop" :size="11" />停止
            </button>
            <button v-else class="btn xs" title="重跑" @click="act('rerun', t)">
              <Icon name="refresh" :size="11" />重跑
            </button>
            <button class="btn xs danger" title="删除" @click="act('del', t)">
              <Icon name="trash" :size="11" />
            </button>
          </div>
        </header>

        <div class="tc-meta">
          <span class="tc-chip mono ellipsis" :title="t.target || '-'">
            <Icon name="target" :size="11" />{{ t.target || '-' }}
          </span>
          <span class="tc-chip"><Icon name="clock" :size="11" />{{ fmtTime(t.created_at) }}</span>
          <span v-if="t.phase" class="tag" :class="t.status === 'running' ? 'cyan' : ''">
            {{ t.phase_module ? t.phase_module + ' · ' : '' }}{{ t.phase_label || t.phase }}
          </span>
        </div>

        <div class="tc-stages">
          <div
            v-for="m in mods(t)"
            :key="m.key"
            class="stg"
            :class="`st-${m.state}`"
            :title="`${m.label}：${MOD_STATE[m.state]?.text || m.state}`"
          >
            <div class="stg-top">
              <Icon :name="MOD_ICON[m.key] || 'dot'" :size="12" />
              <span class="stg-name ellipsis">{{ m.label }}</span>
            </div>
            <div class="stg-mid">
              <b class="mono">{{ num(m.assets) }}</b>
              <span class="stg-state">{{ MOD_STATE[m.state]?.text || m.state }}</span>
            </div>
            <span class="stg-bar"><i :style="{ width: m.state === 'skip' ? 0 : Math.max(3, m.pct || 0) + '%' }" /></span>
          </div>
        </div>

        <div class="tc-assets">
          <router-link class="tc-total" :to="assetLink(t)">
            <Icon name="layers" :size="12" />
            <b class="mono">{{ num(t?.counts?.total) }}</b> 项资产
          </router-link>
          <template v-if="kindChips(t).length">
            <span v-for="k in topKinds(t)" :key="k.key" class="kind-chip">
              {{ k.label }}<b class="mono">{{ num(k.n) }}</b>
            </span>
            <span v-if="restKinds(t)" class="kind-chip more">
              另有 <b class="mono">{{ restKinds(t) }}</b> 类共 <b class="mono">{{ num(restSum(t)) }}</b> 项
            </span>
          </template>
          <span v-else class="muted tc-none">还没有落资产</span>
        </div>

        <footer v-if="skippedCount(t)" class="tc-foot">
          局部任务：另外 {{ skippedCount(t) }} 段未选，要全量请用「重跑」或新建全流程任务
        </footer>
      </article>

      <div v-if="!shown.length && !loading" class="panel">
        <div class="empty"><Icon name="tasks" :size="22" />没有符合条件的任务</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* ── 指标卡：左侧一条色条，数字 22px，浅色主题靠 token 自动变深 ── */
.tk-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 10px;
}
.tk-metric {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 11px 13px 10px 15px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface-2);
  overflow: hidden;
}
.tk-metric::before {
  content: '';
  position: absolute;
  left: 0;
  top: 11px;
  bottom: 11px;
  width: 2px;
  border-radius: 2px;
  background: linear-gradient(180deg, var(--tone, var(--cyan)), transparent);
}
.tk-metric-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  font-size: 11.5px;
  color: var(--muted);
}
.tk-metric-top svg { color: var(--tone, var(--cyan)); opacity: 0.9; }
.tk-metric-value {
  font-size: 22px;
  font-weight: 600;
  line-height: 1.25;
  color: var(--text);
}
.tk-metric-foot { font-size: 11px; color: var(--muted-2); line-height: 1.5; }

/* ── 任务构成：环图 + 可点的档位 + 右侧小账 ── */
.tk-hint { font-size: 11px; }
.tk-board-body {
  display: grid;
  grid-template-columns: 104px minmax(210px, 300px) minmax(0, 1fr);
  gap: 16px;
  align-items: center;
}
.mix-ring {
  position: relative;
  width: 104px;
  height: 104px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  flex: 0 0 auto;
}
.mix-hole {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 76px;
  height: 76px;
  border-radius: 50%;
  background: var(--panel-solid);
  border: 1px solid var(--line-soft);
}
.mix-hole b { font-size: 19px; color: var(--text); line-height: 1.1; }
.mix-hole span { font-size: 10px; color: var(--muted); }

.mix-legend { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.mix-row {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 4px 8px;
  border: 1px solid transparent;
  border-radius: 7px;
  font-size: 12px;
  color: var(--text-2);
  text-align: left;
  cursor: pointer;
}
.mix-row:hover { background: rgba(120, 200, 220, 0.06); }
.mix-row.on { border-color: var(--line-strong); background: rgba(120, 200, 220, 0.08); color: var(--text); }
.mix-dot { width: 8px; height: 8px; border-radius: 3px; flex: 0 0 auto; }
.mix-dot.all { background: var(--line-strong); }
.mix-name { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mix-row b { font-size: 12.5px; color: var(--text); }
.mix-pct { width: 38px; text-align: right; font-size: 11px; color: var(--muted); }
.mix-empty { padding: 6px 8px; font-size: 11.5px; }

.mix-side {
  display: grid;
  grid-template-columns: repeat(2, minmax(132px, 176px));
  gap: 9px 32px;
  align-content: center;
  max-width: 410px;
  margin-left: auto;
  padding-left: 16px;
  border-left: 1px solid var(--line-soft);
}
.mix-kv {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
  font-size: 11.5px;
  color: var(--muted);
}
.mix-kv b { font-size: 13px; color: var(--text-2); }

/* ── 筛选条 ── */
.tk-filter {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.tk-search {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 30px;
  padding: 0 9px;
  min-width: 220px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface-2);
  color: var(--muted);
  cursor: text;
}
.tk-search:focus-within { border-color: var(--line-strong); }
.tk-search input {
  flex: 1 1 auto;
  min-width: 0;
  border: 0;
  background: transparent;
  color: var(--text);
  font-size: 12.5px;
  outline: none;
}
.tk-search input::placeholder { color: var(--muted-2); }
.tk-clear {
  display: grid;
  place-items: center;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  color: var(--muted);
  background: rgba(120, 200, 220, 0.1);
}
.tk-clear:hover { color: var(--text); }
.tk-count { margin-left: auto; font-size: 11.5px; color: var(--muted); }

/* ── 任务卡 ── */
.task-grid {
  display: grid;
  gap: 12px;
  grid-template-columns: repeat(auto-fill, minmax(440px, 1fr));
}
@media (min-width: 1500px) {
  .task-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

.task-card {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 9px;
  padding: 11px 13px 10px 15px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface-2);
  transition: border-color 0.16s, box-shadow 0.16s;
  min-width: 0;
  overflow: hidden;
}
/* 左边一条状态色，扫列表时先看颜色再看字 */
.task-card::before {
  content: '';
  position: absolute;
  left: 0;
  top: 11px;
  bottom: 11px;
  width: 2px;
  border-radius: 2px;
  background: var(--line-strong);
}
.task-card.k-done::before { background: var(--ok-text); }
.task-card.k-running::before { background: var(--cyan); }
.task-card.k-error::before { background: var(--red); }
.task-card.k-pending::before { background: var(--amber); }
.task-card:hover {
  border-color: var(--line-strong);
  box-shadow: 0 10px 26px -20px rgba(20, 60, 80, 0.55);
}

.tc-head { display: flex; align-items: center; gap: 6px; min-width: 0; }
.tc-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  min-width: 0;
  flex: 0 1 auto;
}
.tc-name:hover { color: var(--cyan); }
.tc-head .tag { font-size: 10.5px; height: 19px; }
.tc-actions { margin-left: auto; display: flex; gap: 4px; flex: 0 0 auto; }

.tc-meta {
  display: flex;
  align-items: center;
  gap: 5px;
  flex-wrap: wrap;
  min-width: 0;
}
.tc-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  max-width: 100%;
  font-size: 11.5px;
  color: var(--text-2);
}
.tc-chip svg { color: var(--muted-2); flex: 0 0 auto; }
.tc-chip.mono { max-width: 48%; }
.tc-meta .tag { font-size: 10.5px; height: 19px; }

/* 五段：一格一段，中间用细线隔开，比五个小方盒整齐 */
/* 只有一两段的局部任务不该撑出一条 500px 的长条，所以按内容收缩到最大卡宽 */
.tc-stages {
  display: flex;
  width: fit-content;
  max-width: 100%;
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background: rgba(120, 200, 220, 0.03);
  overflow: hidden;
}
.stg {
  --tone: var(--line-strong);
  flex: 0 1 122px;
  min-width: 84px;
  padding: 6px 8px 7px;
  border-left: 1px solid var(--line-soft);
}
.stg:first-child { border-left: 0; }
.stg.st-done { --tone: var(--ok-text); }
.stg.st-running { --tone: var(--cyan); }
.stg.st-partial { --tone: var(--amber); }
.stg.st-stalled { --tone: var(--red); }
.stg.st-skip { opacity: 0.5; }

.stg-top {
  display: flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
  font-size: 11.5px;
  color: var(--text-2);
}
.stg-top svg { flex: 0 0 auto; color: var(--tone); }
.stg-name { min-width: 0; }
.stg-mid {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 4px;
  margin-top: 2px;
}
.stg-mid b { font-size: 13px; font-weight: 600; color: var(--text); }
.stg-state { font-size: 10.5px; color: var(--tone); white-space: nowrap; }
.stg-bar {
  display: block;
  height: 3px;
  margin-top: 5px;
  border-radius: 2px;
  background: rgba(120, 200, 220, 0.12);
  overflow: hidden;
}
.stg-bar i { display: block; height: 100%; border-radius: 2px; background: var(--tone); }

/* 资产行 */
.tc-assets {
  display: flex;
  align-items: center;
  gap: 5px;
  flex-wrap: wrap;
  padding-top: 8px;
  border-top: 1px solid var(--line-soft);
}
.tc-total {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-right: 2px;
  font-size: 11.5px;
  color: var(--muted);
}
.tc-total svg { color: var(--cyan-2); }
.tc-total b { color: var(--cyan-ink); font-size: 13px; }
.tc-total:hover { color: var(--cyan); }

.kind-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  height: 20px;
  padding: 0 7px;
  border-radius: 5px;
  border: 1px solid var(--line);
  background: rgba(120, 200, 220, 0.05);
  font-size: 11px;
  color: var(--text-2);
  white-space: nowrap;
}
.kind-chip b { font-size: 11.5px; font-weight: 600; color: var(--text); }
.kind-chip.more { color: var(--muted); border-style: dashed; }
.tc-none { font-size: 11.5px; }

.tc-foot {
  font-size: 11px;
  color: var(--muted-2);
  line-height: 1.5;
}

@media (max-width: 860px) {
  .tk-board-body { grid-template-columns: 88px minmax(140px, 1fr); }
  .mix-ring { width: 88px; height: 88px; }
  .mix-hole { width: 64px; height: 64px; }
  .mix-side {
    grid-column: 1 / -1;
    display: flex;
    flex-direction: row;
    flex-wrap: wrap;
    gap: 6px 18px;
    max-width: none;
    margin-left: 0;
    padding-left: 0;
    padding-top: 10px;
    border-left: 0;
    border-top: 1px solid var(--line-soft);
  }
  .task-grid { grid-template-columns: minmax(0, 1fr); }
}
</style>
