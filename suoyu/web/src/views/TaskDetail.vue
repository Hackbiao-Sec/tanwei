<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import AssetExplorer from '@/components/task/AssetExplorer.vue'
import EquityPanel from '@/components/task/EquityPanel.vue'
import OverviewCharts from '@/components/task/OverviewCharts.vue'
import {
  getTask, listModules, stopTask, subscribeTask, taskEquity, taskLogs,
  taskStages, taskSources, taskSummary, rerunTask, rerunStages,
} from '@/api/endpoints'

const route = useRoute()
const router = useRouter()
const id = computed(() => String(route.params.id))

const task = ref(null)
const logs = ref([])
const logBox = ref(null)
const autoScroll = ref(true)
const logLevel = ref('')
const explorer = ref(null)
let closeStream = null
let poll = null

const statusText = {
  running: '执行中', done: '已完成', stopped: '已停止', error: '异常', pending: '排队中',
}
const statusClass = {
  running: 'cyan', done: 'ok', stopped: '', error: 'err', pending: 'warn',
}

// ── 类型名与阶段名：一律取后端口径，前端不另抄一份 ──
const KIND_FALLBACK = {
  url: 'URL', netblock: '网段', takeover: '子域接管', cidr: 'C 段', mailinfo: '邮件信息',
}
const modCatalog = ref({ modules: [], tail: [], kinds: [], stageLabels: {} })
const kindMap = computed(() => {
  const out = { ...KIND_FALLBACK }
  for (const k of modCatalog.value.kinds || [])
    out[k.key] = k.label
  return out
})
function kindLabel(k) {
  return kindMap.value[k] || k || '未分类'
}
const stageLabelMap = computed(() => {
  const out = { ...(modCatalog.value.stageLabels || {}) }
  for (const m of modCatalog.value.modules || []) {
    const labels = m.stage_labels || []
    ;(m.stages || []).forEach((x, i) => {
      out[x] = labels[i] || out[x] || x
    })
  }
  return out
})
function stageLabel(k) {
  return stageMap.value[k]?.label || stageLabelMap.value[k] || k
}
async function loadModCatalog() {
  try {
    const res = await listModules()
    modCatalog.value = {
      modules: res.items || [], tail: res.tail || [], kinds: res.kinds || [],
      stageLabels: res.stage_labels || {},
    }
  } catch {
    modCatalog.value = { modules: [], tail: [], kinds: [], stageLabels: {} }
  }
}

// ── 阶段明细 ──
const stages = ref([])
const stageKey = ref('')
const openIdle = reactive({})
const stageMap = computed(() => {
  const out = {}
  for (const s of stages.value)
    out[s.key] = s
  return out
})
const stageDetail = computed(() => (stageKey.value ? stageMap.value[stageKey.value] || null : null))
const stageTitle = computed(() => (stageKey.value ? stageLabel(stageKey.value) : ''))
async function loadStages() {
  try {
    const res = await taskStages(id.value)
    stages.value = res.stages || []
  } catch {
    stages.value = []
  }
}

// ── 五段进度：只画本任务真跑的段 ──
const MOD_STATE = {
  done: '已完成', running: '进行中', pending: '待跑', partial: '部分完成', stalled: '中断', skip: '本任务不跑',
}
const MOD_TAG = { done: 'ok', running: 'cyan', pending: '', partial: 'warn', stalled: 'err', skip: '' }
const modules = computed(() => task.value?.modules || [])
const taskType = computed(() => {
  const list = modules.value
  if (!list.length)
    return null
  const on = list.filter((m) => m.state !== 'skip')
  const full = on.length === list.length
  return {
    full,
    total: list.length,
    label: full ? '全收集 · 五段全跑' : `单段任务 · ${on.length}/${list.length} 段`,
    names: on.map((m) => m.label).join(' → '),
  }
})
const moduleRows = computed(() =>
  modules.value.map((m, i) => ({
    key: m.key,
    no: i + 1,
    label: m.label,
    hint: m.hint || '',
    state: m.state,
    skip: m.state === 'skip',
    stateLabel: MOD_STATE[m.state] || m.state,
    tag: MOD_TAG[m.state] || '',
    pct: m.pct || 0,
    assets: m.assets || 0,
    stages: (m.stages || []).map((x) => ({
      key: x,
      label: stageLabel(x),
      known: !!stageMap.value[x],
      count: stageMap.value[x]?.count || 0,
      assets: stageMap.value[x]?.total_assets || 0,
    })),
  })),
)
const stageGroups = computed(() => {
  const map = stageMap.value
  const claimed = new Set()
  const rowsOf = (list) => list.map((key) => {
    const d = map[key]
    return {
      key,
      label: d?.label || stageLabel(key),
      count: d?.count || 0,
      warn: d?.warn || 0,
      error: d?.error || 0,
      duration: d?.duration || 0,
      assets: d?.total_assets || 0,
      known: !!d,
    }
  })
  const chosen = new Set((modules.value || []).filter((m) => m.state !== 'skip').map((m) => m.key))
  const groups = (modCatalog.value.modules || []).map((m) => {
    for (const st of m.stages || [])
      claimed.add(st)
    const rows = rowsOf(m.stages || [])
    const on = chosen.has(m.key)
    return {
      key: m.key, label: m.label, hint: m.hint || '', rows,
      idle: !rows.some((r) => r.known),
      idleLabel: on ? '没有阶段记录' : '本任务不跑',
    }
  })
  const tail = (modCatalog.value.tail || []).map((st) => {
    claimed.add(st)
    return st
  })
  if (tail.length) {
    const rows = rowsOf(tail)
    groups.push({
      key: 'tail', label: '收尾', hint: '资产变更与汇总落库', rows,
      idle: !rows.some((r) => r.known), idleLabel: '没有阶段记录',
    })
  }
  const side = (stages.value || []).filter((x) => !claimed.has(x.key)).map((x) => ({
    key: x.key,
    label: x.label || stageLabel(x.key),
    count: x.count || 0,
    warn: x.warn || 0,
    error: x.error || 0,
    duration: x.duration || 0,
    assets: x.total_assets || 0,
    known: true,
  }))
  if (side.length)
    groups.push({ key: 'side', label: '调度与其他', hint: '目标归一、任务调度这类不属于五段的环节', rows: side, idle: false })
  return groups
})
function openStage(row) {
  stageKey.value = row.key
  initRerunForm()
}
function closeStage() {
  stageKey.value = ''
}

// ── 股权穿透（图与导出都在 EquityPanel 里）──
const equity = ref([])
async function loadEquity() {
  try {
    const res = await taskEquity(id.value)
    equity.value = res.trees || []
  } catch {
    equity.value = []
  }
}

// ── 数据渠道 ──
const channels = ref([])
const chanStages = ref([])
const chanFilter = ref('')
const chanShowIdle = ref(false)
const CHAN_ORDER = ['failed', 'quota', 'config', 'partial', 'empty', 'ok', 'skip']
const CHAN_TEXT = {
  failed: '失效', quota: '额度尽', config: '未配置', partial: '截断', empty: '无数据', ok: '可用', skip: '未启用',
}
function chanKey(c) {
  if (c.state === 'dead')
    return c.status === 'quota' ? 'quota' : 'failed'
  if (c.state === 'config')
    return 'config'
  if (c.state === 'partial')
    return 'partial'
  if (c.state === 'empty')
    return 'empty'
  if (c.state === 'skip')
    return 'skip'
  return 'ok'
}
const chanReal = computed(() => channels.value.filter(c => !c.rollup))
const chanLive = computed(() => chanReal.value.filter(c => chanKey(c) !== 'skip'))
const chanIdle = computed(() => chanReal.value.filter(c => chanKey(c) === 'skip'))
const chanBad = computed(() => chanLive.value.filter(c => chanKey(c) === 'failed').length)
const chanQuota = computed(() => chanLive.value.filter(c => chanKey(c) === 'quota').length)
const chanConfig = computed(() => chanLive.value.filter(c => chanKey(c) === 'config').length)
const chanCut = computed(() => chanLive.value.filter(c => chanKey(c) === 'partial').length)
const chanOk = computed(() => chanLive.value.filter(c => chanKey(c) === 'ok').length)
const chanEmpty = computed(() => chanLive.value.filter(c => chanKey(c) === 'empty').length)
const chanStat = computed(() => ({
  total: chanLive.value.length, ok: chanOk.value, bad: chanBad.value, quota: chanQuota.value,
  config: chanConfig.value, cut: chanCut.value, idle: chanIdle.value.length, empty: chanEmpty.value,
}))
const chanBuckets = computed(() => {
  const n = {}
  for (const c of chanReal.value) {
    const k = chanKey(c)
    n[k] = (n[k] || 0) + 1
  }
  return CHAN_ORDER.filter(k => n[k]).map(k => ({ key: k, label: CHAN_TEXT[k], count: n[k] }))
})
const shownChannels = computed(() => {
  if (chanFilter.value)
    return channels.value.filter(c => chanKey(c) === chanFilter.value)
  return chanShowIdle.value ? channels.value : channels.value.filter(c => chanKey(c) !== 'skip')
})
function chanTagClass(c) {
  const k = chanKey(c)
  return { err: k === 'failed', warn: k === 'quota' || k === 'config' || k === 'partial', ok: k === 'ok' }
}
async function loadChannels() {
  try {
    const res = await taskSources(id.value)
    channels.value = res.channels || []
    chanStages.value = res.stages || []
  } catch {
    channels.value = []
    chanStages.value = []
  }
}
const STAGE_SRC_TEXT = { quota: '额度尽', failed: '失效', config: '未配置', partial: '截断', empty: '无数据', ok: '' }
const STAGE_SRC_RANK = { empty: 1, quota: 2, failed: 2, config: 3, partial: 4 }
function shortSrc(label) {
  const parts = String(label || '').split('·')
  return parts[parts.length - 1] || label
}
const stageSources = computed(() => {
  const out = {}
  for (const st of chanStages.value) {
    const rows = (st.channels || []).filter(c => !c.rollup && chanKey(c) !== 'skip')
    if (!rows.length)
      continue
    out[st.stage] = rows
      .map((c) => {
        const k = chanKey(c)
        const tail = k === 'ok'
          ? (c.items ? `${c.items} 条` : '可用')
          : (c.items ? `${c.items} 条·${STAGE_SRC_TEXT[k] || c.status_text}` : (STAGE_SRC_TEXT[k] || c.status_text))
        const rank = k === 'ok' ? (c.items ? 0 : 1) : (STAGE_SRC_RANK[k] ?? 5)
        return { key: c.source, label: shortSrc(c.label), text: tail, cls: k, rank }
      })
      .sort((a, b) => a.rank - b.rank)
  }
  return out
})

// ── 任务统计与画像 ──
const stats = computed(() => {
  const raw = task.value?.stats ?? task.value?.stats_json
  if (raw && typeof raw === 'object')
    return raw
  try {
    return JSON.parse(raw || '{}')
  } catch {
    return {}
  }
})
const targets = computed(() => {
  const raw = task.value?.targets ?? task.value?.targets_json
  if (Array.isArray(raw))
    return raw
  if (!raw)
    return []
  try {
    return JSON.parse(raw)
  } catch {
    return []
  }
})
const summary = ref(null)
const kindStats = computed(() => {
  const rows = summary.value?.by_kind || []
  if (!rows.length)
    return stats.value
  const out = {}
  for (const r of rows)
    out[r.value] = r.count
  return out
})
const kindTotal = computed(() => Object.values(kindStats.value).reduce((n, v) => n + (v || 0), 0))
const kindCount = computed(() => Object.values(kindStats.value).filter(v => v > 0).length)
const ranModules = computed(() => moduleRows.value.filter((m) => !m.skip).length)
const outputModules = computed(
  () => moduleRows.value.filter((m) => !m.skip && (m.assets || 0) > 0).length,
)

// 概览的构成条：只画前 7 类，其余并成「其他」，避免 30 类挤成一条灰带
const KIND_COLORS = ['#34e5c8', '#4fb6ff', '#9d8cff', '#f5b544', '#4ade80', '#ff6470', '#f08a4b', '#5d7488']
const compKinds = computed(() => {
  const rows = [...(summary.value?.by_kind || [])].filter(r => r.count > 0).sort((a, b) => b.count - a.count)
  const total = rows.reduce((n, r) => n + r.count, 0) || 1
  const head = rows.slice(0, 7)
  const rest = rows.slice(7).reduce((n, r) => n + r.count, 0)
  const out = head.map((r, i) => ({
    key: r.value, label: kindLabel(r.value), count: r.count,
    pct: (r.count / total) * 100, color: KIND_COLORS[i % KIND_COLORS.length],
  }))
  if (rest)
    out.push({ key: '__other', label: `其他 ${rows.length - 7} 类`, count: rest, pct: (rest / total) * 100, color: KIND_COLORS[7] })
  return out
})
function openKind(k) {
  if (!k || k === '__other')
    return
  pane.value = 'assets'
  nextTick(() => explorer.value?.focusKind(k))
}
// 五段产出图：颜色按段固定，不跑 / 无产出也留一行，看得到缺口
const MOD_COLORS = ['#34e5c8', '#4fb6ff', '#9d8cff', '#f5b544', '#4ade80']
const moduleViz = computed(() => moduleRows.value.map((m, i) => ({
  key: m.key,
  label: m.label,
  assets: m.assets || 0,
  stateLabel: m.skip ? '本任务不跑' : m.stateLabel,
  color: m.skip ? 'rgba(120, 200, 220, .22)' : MOD_COLORS[i % MOD_COLORS.length],
})))

const barMax = computed(() => {
  const all = [...(summary.value?.by_source || []), ...(summary.value?.by_root_domain || [])]
  return Math.max(1, ...all.map((x) => x.count || 0))
})
const barWidth = (n) => `${Math.max(2, Math.round(((n || 0) / barMax.value) * 100))}%`

const stageBarMax = computed(() => {
  const d = stageDetail.value
  if (!d)
    return 1
  const all = [...(d.kinds || []), ...(d.sources || []), ...(d.ports || []), ...(d.roots || [])]
  return Math.max(1, ...all.map((x) => x.count || 0))
})
const stageBarWidth = (n) => `${Math.max(4, Math.round(((n || 0) / stageBarMax.value) * 100))}%`
function stageAssetsUrl(key) {
  return { path: '/assets', query: { task: id.value, stage: key } }
}

// ── 子模块 ──
const PANES = [
  { key: 'overview', label: '概览', icon: 'dashboard' },
  { key: 'assets', label: '资产', icon: 'layers' },
  { key: 'equity', label: '股权穿透', icon: 'flow' },
  { key: 'sources', label: '数据来源', icon: 'route' },
  { key: 'stages', label: '阶段轨迹', icon: 'chart' },
  { key: 'logs', label: '实时日志', icon: 'terminal' },
]
const pane = ref('overview')
function paneBadge(key) {
  if (key === 'assets')
    return summary.value?.total ?? 0
  if (key === 'equity')
    return equity.value.length
  if (key === 'sources')
    return chanLive.value.length
  if (key === 'stages')
    return stages.value.length
  if (key === 'logs')
    return logs.value.length
  return 0
}
function goPane(key) {
  pane.value = key
  if (key === 'logs')
    scrollBottom()
}

// ── 日志 ──
const shownLogs = computed(() => (logLevel.value ? logs.value.filter(l => l.level === logLevel.value) : logs.value))
const logCounts = computed(() => ({
  warn: logs.value.filter(l => l.level === 'warn').length,
  error: logs.value.filter(l => l.level === 'error').length,
}))

// ── 加载 ──
async function loadTask() {
  try {
    task.value = await getTask(id.value)
  } catch {
    /* 任务不存在时保持空视图 */
  }
}
async function loadLogs() {
  try {
    const res = await taskLogs(id.value, 0, 1000)
    logs.value = res.items || []
    scrollBottom()
  } catch {
    /* 后端忙或重启时这一屏先留空，流接通后日志会自己补上 */
  }
}
async function loadSummary() {
  try {
    summary.value = await taskSummary(id.value)
  } catch {
    summary.value = null
  }
}
function refreshAll() {
  loadSummary()
  loadTask()
  loadStages()
  loadChannels()
  loadEquity()
  if (pane.value === 'assets')
    explorer.value?.reload()
}
function scrollBottom() {
  if (!autoScroll.value)
    return
  nextTick(() => {
    const el = logBox.value
    if (el)
      el.scrollTop = el.scrollHeight
  })
}
function startStream() {
  closeStream?.()
  closeStream = subscribeTask(id.value, (ev) => {
    if (ev.type === 'log') {
      const row = ev.data
      if (row && row.id && !logs.value.some((l) => l.id === row.id)) {
        logs.value.push(row)
        if (logs.value.length > 3000)
          logs.value.splice(0, 500)
        scrollBottom()
      }
    } else if (ev.type === 'state') {
      if (task.value) {
        task.value.status = ev.data.status || task.value.status
        task.value.progress = ev.data.progress ?? task.value.progress
        task.value.message = ev.data.message || task.value.message
        task.value.phase = ev.data.phase || task.value.phase
        if (ev.data.stats)
          task.value.stats = ev.data.stats
      }
      if (['done', 'stopped', 'error'].includes(ev.data.status))
        refreshAll()
    }
  })
}
async function doStop() {
  await stopTask(id.value)
  await loadTask()
}
async function doRerun() {
  const res = await rerunTask(id.value)
  if (res?.task_id)
    router.push(`/tasks/${res.task_id}`)
}
const rerunStageBusy = ref('')
const RERUN_OFF = ['target_parse']
// 阶段内的细分项：勾中的才重测；全勾 = 整段照跑
const submodules = ref({})
const pickedSubs = ref([])
const rerunTargets = ref('')
const stageSubs = computed(() => submodules.value[stageKey.value] || [])
function initRerunForm() {
  pickedSubs.value = (submodules.value[stageKey.value] || []).map((s) => s.key)
  rerunTargets.value = ''
  if (!Object.keys(submodules.value).length) {
    rerunStages().then((res) => {
      submodules.value = res?.submodules || {}
      pickedSubs.value = (submodules.value[stageKey.value] || []).map((s) => s.key)
    }).catch(() => {})
  }
}
function toggleSub(key) {
  pickedSubs.value = pickedSubs.value.includes(key)
    ? pickedSubs.value.filter((k) => k !== key)
    : [...pickedSubs.value, key]
}
function toggleAllSubs(on) {
  pickedSubs.value = on ? stageSubs.value.map((s) => s.key) : []
}
async function rerunStage() {
  const key = stageKey.value
  if (!key || RERUN_OFF.includes(key))
    return
  rerunStageBusy.value = key
  try {
    const subs = stageSubs.value.map((s) => s.key)
    const partial = subs.length && pickedSubs.value.length < subs.length
    const extra = {}
    // 一项都没勾 = 整段；全勾也发整段，只勾一部分才限定
    if (partial)
      extra.modules = pickedSubs.value.map((k) => `${key}:${k}`)
    const targets = rerunTargets.value.replace(/[,，\s]+/g, ' ').trim()
    if (targets)
      extra.targets = targets.split(' ')
    const res = await rerunTask(id.value, key, extra)
    if (res?.task_id)
      router.push(`/tasks/${res.task_id}`)
  } finally {
    rerunStageBusy.value = ''
  }
}
function fmt(t) {
  const d = new Date(t * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
function fmtTime(ts) {
  if (!ts)
    return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}
async function exportCsv() {
  // 整本 xlsx：按资产类型各占一张表，审核拿到就能按表翻，不用在几万行宽表里筛
  const http = (await import('@/api/http')).default
  const res = await http.get('/api/export/xlsx', {
    params: { task_id: id.value }, responseType: 'blob', timeout: 300000,
  })
  const url = URL.createObjectURL(res instanceof Blob ? res : new Blob([res]))
  const a = document.createElement('a')
  a.href = url
  a.download = `suoyu_task_${id.value}.xlsx`
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  a.remove()
  // 立刻回收会让部分浏览器把还没写完的下载掐掉，等两秒再释放
  setTimeout(() => URL.revokeObjectURL(url), 2000)
}

onMounted(async () => {
  await Promise.all([
    loadModCatalog(), loadTask(), loadLogs(), loadSummary(),
    loadStages(), loadEquity(), loadChannels(),
  ])
  startStream()
  poll = setInterval(() => {
    if (task.value?.status === 'running') {
      loadTask()
      loadSummary()
      loadStages()
      loadChannels()
      loadEquity()
      if (pane.value === 'assets')
        explorer.value?.reload()
    }
  }, 4000)
})
onBeforeUnmount(() => {
  closeStream?.()
  clearInterval(poll)
})
</script>

<template>
  <div class="td">
    <PageHead :title="task?.name || '任务详情'" :desc="task?.target || ''">
      <template #actions>
        <button class="btn sm" @click="router.push('/tasks')">
          <Icon name="chevron" :size="12" />返回列表
        </button>
        <button class="btn sm" @click="refreshAll">
          <Icon name="refresh" :size="12" />刷新
        </button>
        <button v-if="task?.status === 'running'" class="btn sm danger" @click="doStop">
          <Icon name="stop" :size="12" />停止任务
        </button>
        <button v-else class="btn sm" @click="doRerun">
          <Icon name="play" :size="12" />重跑任务
        </button>
        <button class="btn sm" @click="exportCsv">
          <Icon name="download" :size="12" />导出资产（多表）
        </button>
      </template>
    </PageHead>

    <!-- 状态条：任务级信息固定在上，子模块只换下面的内容 -->
    <section class="hero">
      <div class="hero-top">
        <div class="hero-left">
          <span class="tag" :class="statusClass[task?.status]">{{ statusText[task?.status] || task?.status }}</span>
          <span class="hero-msg ellipsis" :title="task?.message">{{ task?.message || '还没有开始执行' }}</span>
        </div>
        <div class="hero-right">
          <span class="hero-pct mono">{{ task?.progress || 0 }}<em>%</em></span>
          <span class="hero-pct-label">总进度</span>
        </div>
      </div>
      <div class="progress hero-bar"><i :style="{ width: (task?.progress || 0) + '%' }" /></div>
      <div class="hero-type">
        <span class="tag" :class="taskType?.full ? 'ok' : 'info'">{{ taskType?.label || '任务类型未记录' }}</span>
        <span class="muted ellipsis" :title="taskType?.names">{{ taskType?.names || '' }}</span>
      </div>
      <div class="hero-mods">
        <div v-for="m in moduleRows" :key="m.key" class="mp" :class="{ skip: m.skip }">
          <span class="mp-no mono">{{ m.no }}</span>
          <span class="mp-name" :title="m.hint">
            {{ m.label }}
            <em class="mono">{{ m.skip ? '不跑' : (m.assets ? m.assets + ' 资产' : (m.state === 'done' ? '无产出' : '—')) }}</em>
          </span>
          <span class="mp-bar"><i :style="{ width: (m.skip ? 0 : m.pct) + '%' }" /></span>
          <span class="mp-pct mono">{{ m.skip ? '—' : m.pct + '%' }}</span>
          <span class="tag" :class="m.tag">{{ m.stateLabel }}</span>
        </div>
        <div v-if="!moduleRows.length" class="muted" style="font-size: 11.5px">这个任务没有分段记录</div>
      </div>
    </section>

    <!-- 子模块导航 -->
    <nav class="td-tabs">
      <button
        v-for="p in PANES" :key="p.key"
        class="td-tab" :class="{ on: pane === p.key }"
        @click="goPane(p.key)"
      >
        <Icon :name="p.icon" :size="14" />
        <span>{{ p.label }}</span>
        <b v-if="paneBadge(p.key)" class="td-badge">{{ paneBadge(p.key) }}</b>
      </button>
    </nav>

    <!-- 概览 -->
    <div v-show="pane === 'overview'" class="pane">
      <div class="ov-metrics">
        <div class="ov-card tone-cyan">
          <div class="ov-top">
            <span class="ov-label">资产合计</span>
            <span class="ov-ico"><Icon name="layers" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ kindTotal }}</span>
          <span class="ov-foot">本任务收进来的全部资产</span>
        </div>
        <div class="ov-card clickable tone-blue" @click="goPane('assets')">
          <div class="ov-top">
            <span class="ov-label">资产类型</span>
            <span class="ov-ico"><Icon name="tags" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ kindCount }}</span>
          <span class="ov-foot">按采集面归类后可筛选</span>
        </div>
        <div class="ov-card tone-violet">
          <div class="ov-top">
            <span class="ov-label">有产出的段</span>
            <span class="ov-ico"><Icon name="flow" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ outputModules }}<em class="ov-slash">/{{ ranModules }}</em></span>
          <span class="ov-foot">跑过的段里真收到资产的</span>
        </div>
        <div class="ov-card clickable tone-amber" @click="goPane('equity')">
          <div class="ov-top">
            <span class="ov-label">控股主体</span>
            <span class="ov-ico"><Icon name="flow" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ equity.length }}</span>
          <span class="ov-foot">完成穿透的股权树数量</span>
        </div>
        <div class="ov-card clickable tone-green" @click="goPane('sources')">
          <div class="ov-top">
            <span class="ov-label">可用渠道</span>
            <span class="ov-ico"><Icon name="route" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ chanStat.ok }}<em class="ov-slash">/{{ chanStat.total }}</em></span>
          <span class="ov-foot">本轮真正取到数据的外部来源</span>
        </div>
        <div class="ov-card tone-slate">
          <div class="ov-top">
            <span class="ov-label">目标数</span>
            <span class="ov-ico"><Icon name="aim" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ targets.length }}</span>
          <span class="ov-foot ellipsis" :title="targets.join(', ')">{{ targets[0] || task?.target || '—' }}</span>
        </div>
      </div>

      <OverviewCharts
        :kinds="compKinds"
        :modules="moduleViz"
        :total="kindTotal"
        :active="pane === 'overview'"
        @pick-kind="openKind"
      />

      <div class="ov-grid">
        <section class="panel">
          <div class="panel-head">
            <span><Icon name="globe" :size="13" />来源分布</span>
            <span class="mono muted" style="font-size: 11px">前 10 路</span>
          </div>
          <div class="panel-body">
            <div class="bars">
              <div v-for="s in (summary?.by_source || []).slice(0, 10)" :key="'src-' + s.value" class="bar">
                <span class="bar-key mono" :title="s.value">{{ s.value }}</span>
                <span class="bar-track"><i :style="{ width: barWidth(s.count) }" /></span>
                <span class="bar-val mono">{{ s.count }}</span>
              </div>
              <div v-if="!(summary?.by_source || []).length" class="muted" style="font-size: 12px">暂无来源标记</div>
            </div>
          </div>
        </section>
        <section class="panel">
          <div class="panel-head">
            <span><Icon name="globe" :size="13" />根域分布</span>
            <span class="mono muted" style="font-size: 11px">前 10 个</span>
          </div>
          <div class="panel-body">
            <div class="bars">
              <div v-for="r in (summary?.by_root_domain || []).slice(0, 10)" :key="'root-' + r.value" class="bar">
                <span class="bar-key mono" :title="r.value">{{ r.value }}</span>
                <span class="bar-track"><i class="alt" :style="{ width: barWidth(r.count) }" /></span>
                <span class="bar-val mono">{{ r.count }}<em v-if="r.alive"> · {{ r.alive }} 活</em></span>
              </div>
              <div v-if="!(summary?.by_root_domain || []).length" class="muted" style="font-size: 12px">暂无根域</div>
            </div>
          </div>
        </section>
      </div>

      <section class="panel">
        <div class="panel-head"><span><Icon name="list" :size="13" />任务信息</span></div>
        <div class="panel-body kv">
          <div class="kv-item"><span class="kv-k">任务 ID</span><span class="kv-v mono">{{ task?.id }}</span></div>
          <div class="kv-item"><span class="kv-k">状态</span><span class="kv-v">{{ statusText[task?.status] || task?.status || '-' }}</span></div>
          <div class="kv-item"><span class="kv-k">创建时间</span><span class="kv-v mono">{{ fmtTime(task?.created_at) }}</span></div>
          <div class="kv-item"><span class="kv-k">更新时间</span><span class="kv-v mono">{{ fmtTime(task?.updated_at) }}</span></div>
          <div class="kv-item"><span class="kv-k">任务类型</span><span class="kv-v ellipsis">{{ taskType?.label || '—' }}</span></div>
          <div class="kv-item wide"><span class="kv-k">目标</span><span class="kv-v mono ellipsis" :title="targets.join(', ')">{{ targets.join(', ') || task?.target || '—' }}</span></div>
        </div>
      </section>
    </div>

    <!-- 资产 -->
    <div v-show="pane === 'assets'" class="pane">
      <AssetExplorer
        ref="explorer"
        :task-id="id"
        :summary="summary"
        :kind-labels="kindMap"
        :active="pane === 'assets'"
      />
    </div>

    <!-- 股权穿透 -->
    <div v-show="pane === 'equity'" class="pane">
      <EquityPanel :trees="equity" :task-id="id" :active="pane === 'equity'" />
    </div>

    <!-- 数据来源 -->
    <div v-show="pane === 'sources'" class="pane">
      <div class="ov-metrics">
        <div class="ov-card tone-blue">
          <div class="ov-top">
            <span class="ov-label">本轮调用</span>
            <span class="ov-ico"><Icon name="route" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ chanStat.total }}</span>
          <span class="ov-foot">真正发出过请求的渠道</span>
        </div>
        <div class="ov-card tone-green">
          <div class="ov-top">
            <span class="ov-label">取到数据</span>
            <span class="ov-ico"><Icon name="check" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ chanStat.ok }}</span>
          <span class="ov-foot">连通并返回了内容</span>
        </div>
        <div class="ov-card tone-slate">
          <div class="ov-top">
            <span class="ov-label">有效但无数据</span>
            <span class="ov-ico"><Icon name="eye" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ chanStat.empty }}</span>
          <span class="ov-foot">渠道通着，这家没收录</span>
        </div>
        <div class="ov-card tone-amber">
          <div class="ov-top">
            <span class="ov-label">额度用尽</span>
            <span class="ov-ico"><Icon name="clock" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ chanStat.quota }}</span>
          <span class="ov-foot">登录态有效，按日恢复</span>
        </div>
        <div class="ov-card tone-red">
          <div class="ov-top">
            <span class="ov-label">失效 / 缺凭据</span>
            <span class="ov-ico"><Icon name="alert" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ chanStat.bad }}<em class="ov-slash">/{{ chanStat.config }}</em></span>
          <span class="ov-foot">左为请求失败，右为未配置</span>
        </div>
        <div class="ov-card tone-violet">
          <div class="ov-top">
            <span class="ov-label">上限截断</span>
            <span class="ov-ico"><Icon name="filter" :size="14" /></span>
          </div>
          <span class="ov-value mono">{{ chanStat.cut }}</span>
          <span class="ov-foot">被条数或总时限截住的部分</span>
        </div>
      </div>

      <section class="panel">
        <div class="panel-head">
          <span><Icon name="route" :size="13" />渠道明细</span>
          <div class="flex gap-8">
            <button v-if="chanStat.idle" class="btn xs" :class="{ primary: chanShowIdle }" @click="chanShowIdle = !chanShowIdle">
              {{ chanShowIdle ? '隐藏未启用' : `显示未启用 ${chanStat.idle}` }}
            </button>
            <button class="btn xs" @click="loadChannels"><Icon name="refresh" :size="11" />重读</button>
          </div>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="muted" style="font-size: 11px">
            「未启用」= 这轮没勾的工商来源，不参与采集、不耗额度；表格只列本轮真正发过请求的渠道。
          </div>
          <div class="chips">
            <button
              v-for="b in chanBuckets" :key="'cb-' + b.key" class="chip"
              :class="{ on: chanFilter === b.key }"
              @click="chanFilter = chanFilter === b.key ? '' : b.key"
            >{{ b.label }} <b>{{ b.count }}</b></button>
            <button v-if="chanFilter" class="btn xs ghost" @click="chanFilter = ''">
              <Icon name="close" :size="10" />清除
            </button>
          </div>
          <div class="table-wrap src-table">
            <table class="table">
              <thead><tr><th>阶段</th><th>渠道</th><th>状态</th><th>条数</th><th>调用</th><th>说明</th></tr></thead>
              <tbody>
                <tr v-for="c in shownChannels" :key="c.stage + c.source">
                  <td class="muted nowrap">{{ c.stage_label }}</td>
                  <td>
                    <span class="src-name">{{ c.label }}</span>
                    <span v-if="c.rollup" class="tag" style="margin-left: 6px">汇总</span>
                    <span class="src-slug mono">{{ c.source }}</span>
                  </td>
                  <td><span class="tag" :class="chanTagClass(c)">{{ c.status_text }}</span></td>
                  <td class="mono">{{ c.items || '-' }}</td>
                  <td class="mono muted">{{ c.calls }}</td>
                  <td class="ellipsis muted" style="max-width: 320px" :title="c.note">{{ c.note }}</td>
                </tr>
                <tr v-if="!shownChannels.length">
                  <td colspan="6">
                    <div class="empty" style="padding: 14px 0">
                      {{ chanFilter ? '这个状态下没有渠道' : '这次任务还没调用外部数据渠道' }}
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>

    <!-- 阶段轨迹 -->
    <div v-show="pane === 'stages'" class="pane">
      <section class="panel">
        <div class="panel-head">
          <span><Icon name="chart" :size="13" />阶段轨迹</span>
          <div class="flex gap-8">
            <span class="mono muted" style="font-size: 11px">{{ stages.length }} 个阶段有记录</span>
            <button class="btn xs" @click="loadStages"><Icon name="refresh" :size="11" />刷新</button>
          </div>
        </div>
        <div class="panel-body">
          <div class="muted" style="font-size: 11px; margin-bottom: 10px">
            按五段分组；一行一个阶段，点开看这一阶段的日志、告警和收进来的资产。灰色是这趟没跑到的段。
          </div>
          <div class="stg-list">
            <div v-for="g in stageGroups" :key="'sg-' + g.key" class="stg">
              <div class="stg-head">
                <span class="stg-name">{{ g.label }}</span>
                <span class="muted ellipsis" style="font-size: 11px">{{ g.hint }}</span>
                <span v-if="g.idle" class="tag">{{ g.idleLabel }}</span>
                <button v-if="g.idle" class="btn xs ghost" @click="openIdle[g.key] = !openIdle[g.key]">
                  <Icon name="chevron" :size="10" />{{ openIdle[g.key] ? '收起' : `${g.rows.length} 个阶段` }}
                </button>
              </div>
              <div class="stg-rows">
                <button
                  v-for="p in (g.idle && !openIdle[g.key] ? [] : g.rows)"
                  :key="'st-' + p.key"
                  class="stg-row" :class="{ idle: !p.known }"
                  @click="openStage(p)"
                >
                  <span class="stg-cell">
                    <span class="stg-label ellipsis">{{ p.label }}</span>
                    <span class="stg-counts mono">
                      {{ p.assets }} 资产<span class="muted"> · {{ p.count }} 日志</span>
                    </span>
                  </span>
                  <span class="stg-nums">
                    <span
                      v-for="sv in (stageSources[p.key] || []).slice(0, 4)"
                      :key="'sv-' + p.key + sv.key"
                      class="tag"
                      :class="{ err: sv.cls === 'failed', warn: ['quota', 'config', 'partial'].includes(sv.cls), ok: sv.cls === 'ok' }"
                    >{{ sv.label }} {{ sv.text }}</span>
                    <span v-if="(stageSources[p.key] || []).length > 4" class="muted" style="font-size: 11px">
                      +{{ stageSources[p.key].length - 4 }} 路
                    </span>
                    <span v-if="p.warn" class="tag warn">告警 {{ p.warn }}</span>
                    <span v-if="p.error" class="tag err">错误 {{ p.error }}</span>
                  </span>
                  <span class="stg-dur mono">{{ p.duration ? p.duration + 's' : '—' }}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>

    <!-- 日志 -->
    <div v-show="pane === 'logs'" class="pane">
      <section class="panel">
        <div class="panel-head">
          <div class="seg">
            <button :class="{ on: logLevel === '' }" @click="logLevel = ''">全部</button>
            <button :class="{ on: logLevel === 'warn' }" @click="logLevel = 'warn'">告警 {{ logCounts.warn }}</button>
            <button :class="{ on: logLevel === 'error' }" @click="logLevel = 'error'">错误 {{ logCounts.error }}</button>
          </div>
          <div class="flex gap-8">
            <span class="mono muted" style="font-size: 10.5px">{{ shownLogs.length }} / {{ logs.length }} 行</span>
            <button class="btn xs" :class="{ primary: autoScroll }" @click="autoScroll = !autoScroll; scrollBottom()">
              <Icon name="chevron" :size="11" />自动滚动
            </button>
            <button class="btn xs" @click="loadLogs"><Icon name="refresh" :size="11" />刷新</button>
          </div>
        </div>
        <div class="panel-body">
          <div ref="logBox" class="logbox logs">
            <div v-for="l in shownLogs" :key="l.id" class="logline" :class="l.level">
              <span class="lt">{{ fmt(l.ts) }}</span>
              <span class="lm">[{{ l.module }}]</span>
              <span class="lx">{{ l.msg }}</span>
            </div>
            <div v-if="!shownLogs.length" class="muted">
              {{ logs.length ? '这个级别下没有日志' : '暂无日志' }}
            </div>
          </div>
        </div>
      </section>
    </div>

    <!-- 阶段明细 -->
    <div v-if="stageKey" class="overlay" @click.self="closeStage">
      <div class="modal wide">
        <div class="modal-head">
          <Icon name="layers" :size="15" style="color: var(--cyan)" />
          <span class="flex-1 ellipsis">{{ stageTitle }}</span>
          <span class="mono muted" style="font-size: 11px">
            {{ stageDetail?.duration ? '耗时 ' + stageDetail.duration + 's' : '无耗时记录' }}
          </span>
          <button class="btn ghost sm" @click="closeStage"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body stack" style="gap: 12px">
          <!-- 重测范围：只勾阶段内的某几项 / 只对几个 host，比整段重跑省得多 -->
          <div v-if="stageKey && !RERUN_OFF.includes(stageKey)" class="rerun-box">
            <div class="flex" style="align-items: center; justify-content: space-between; gap: 8px">
              <div class="sub-title" style="margin: 0">
                重测范围
                <span class="muted" style="font-size: 11px; font-weight: 400">全勾 = 整段重跑；只留想重来的那几项就只跑它们</span>
              </div>
              <div v-if="stageSubs.length" class="flex" style="align-items: center; gap: 6px">
                <button class="btn xs ghost" @click="toggleAllSubs(true)">全选</button>
                <button class="btn xs ghost" @click="toggleAllSubs(false)">清空</button>
                <span class="mono muted" style="font-size: 10.5px">{{ pickedSubs.length }} / {{ stageSubs.length }}</span>
              </div>
            </div>
            <div v-if="stageSubs.length" class="subgrid">
              <label
                v-for="s in stageSubs" :key="'rs-' + s.key" class="subitem"
                :class="{ on: pickedSubs.includes(s.key) }" :title="s.hint || s.label"
              >
                <input type="checkbox" :checked="pickedSubs.includes(s.key)" @change="toggleSub(s.key)" />
                <span class="ellipsis">{{ s.label }}</span>
              </label>
            </div>
            <div v-else class="muted" style="font-size: 12px">这一阶段没有更细的拆分，重测就是整段。</div>
            <div class="flex" style="align-items: center; gap: 8px">
              <input
                v-model="rerunTargets" class="input flex-1"
                placeholder="只重测这几个 host / IP（逗号或空格分隔，留空 = 本任务全部）"
              />
              <button class="btn primary sm" :disabled="!!rerunStageBusy" @click="rerunStage">
                <Icon name="refresh" :size="12" />{{ rerunStageBusy ? '提交中' : '按此范围重跑' }}
              </button>
            </div>
            <div class="muted" style="font-size: 11px; line-height: 1.65">
              目标留空就吃本任务已入库的全部域名和 IP；填了只在填的这几个上重跑，结果仍并回本任务。
              细分项一项都不勾也按整段算。
            </div>
          </div>
          <div v-if="!stageDetail" class="empty" style="padding: 26px 8px">
            <Icon name="alert" :size="20" />
            <div style="margin-top: 6px">这一阶段本次运行没有留下执行记录</div>
            <div class="muted" style="font-size: 12px; margin-top: 4px; line-height: 1.7">
              流水线里这一段是固定存在的，没有记录通常是三种情况：<br />
              前置阶段没产出（比如没有子域就不会进端口扫描）、这一步没有开启、或者这一趟提前停了。<br />
              想让它跑起来，去「设置」看对应开关与数据源凭据，或者到「日志」看上一阶段为什么是空的。
            </div>
          </div>
          <div v-else class="metric-row" style="margin: 0">
            <div class="metric" style="padding: 8px 10px">
              <span class="metric-label">资产</span>
              <span class="metric-value" style="font-size: 17px">{{ stageDetail?.total_assets || 0 }}</span>
              <span class="metric-foot">这一阶段入库</span>
            </div>
            <div class="metric" style="padding: 8px 10px">
              <span class="metric-label">日志</span>
              <span class="metric-value" style="font-size: 17px">{{ stageDetail?.count || 0 }}</span>
              <span class="metric-foot">条</span>
            </div>
            <div class="metric" style="padding: 8px 10px">
              <span class="metric-label">告警</span>
              <span class="metric-value" style="font-size: 17px">{{ stageDetail?.warn || 0 }}</span>
              <span class="metric-foot">被跳过 / 限流</span>
            </div>
            <div class="metric" style="padding: 8px 10px">
              <span class="metric-label">错误</span>
              <span class="metric-value" style="font-size: 17px">{{ stageDetail?.error || 0 }}</span>
              <span class="metric-foot">异常</span>
            </div>
          </div>
          <template v-if="stageDetail">
            <div v-if="stageDetail?.total_assets" class="two-col">
              <div>
                <div class="sub-title">这一阶段收进来的类型</div>
                <div class="bars">
                  <div v-for="k in stageDetail.kinds" :key="'sk-' + k.value" class="bar">
                    <span class="bar-key">{{ kindLabel(k.value) }}</span>
                    <span class="bar-track"><i :style="{ width: stageBarWidth(k.count) }" /></span>
                    <span class="bar-val mono">{{ k.count }}</span>
                  </div>
                </div>
              </div>
              <div>
                <div class="sub-title">从哪来</div>
                <div class="bars">
                  <div v-for="s in stageDetail.sources" :key="'ss-' + s.name" class="bar">
                    <span class="bar-key mono" :title="s.name">{{ s.name }}</span>
                    <span class="bar-track"><i :style="{ width: stageBarWidth(s.count) }" /></span>
                    <span class="bar-val mono">{{ s.count }}</span>
                  </div>
                  <div v-if="!(stageDetail?.sources || []).length" class="muted" style="font-size: 12px">这一阶段资产没有来源标记</div>
                </div>
              </div>
              <div>
                <div class="sub-title">落在哪些端口</div>
                <div class="bars">
                  <div v-for="p in stageDetail.ports" :key="'sp-' + p.port" class="bar">
                    <span class="bar-key mono">:{{ p.port }}</span>
                    <span class="bar-track"><i :style="{ width: stageBarWidth(p.count) }" /></span>
                    <span class="bar-val mono">{{ p.count }}</span>
                  </div>
                  <div v-if="!(stageDetail?.ports || []).length" class="muted" style="font-size: 12px">这一阶段没有带端口的资产</div>
                </div>
              </div>
              <div>
                <div class="sub-title">涉及根域</div>
                <div class="bars">
                  <div v-for="r in stageDetail.roots" :key="'sr-' + r.name" class="bar">
                    <span class="bar-key mono" :title="r.name">{{ r.name }}</span>
                    <span class="bar-track"><i :style="{ width: stageBarWidth(r.count) }" /></span>
                    <span class="bar-val mono">{{ r.count }}</span>
                  </div>
                  <div v-if="!(stageDetail?.roots || []).length" class="muted" style="font-size: 12px">这一阶段的资产还没归到根域</div>
                </div>
              </div>
            </div>
            <div v-if="(stageDetail?.assets || []).length">
              <div class="row" style="justify-content: space-between; align-items: center; margin-bottom: 4px">
                <span class="sub-title" style="margin-bottom: 0">最近入库（显示 {{ stageDetail.assets.length }} 条）</span>
                <button class="btn xs" @click="router.push(stageAssetsUrl(stageDetail.key))">
                  <Icon name="external" :size="11" />看全部 {{ stageDetail.total_assets }} 条
                </button>
              </div>
              <div class="table-wrap" style="max-height: 260px">
                <table class="table">
                  <thead><tr><th>类型</th><th>地址</th><th>状态</th><th>指纹</th><th>来源</th></tr></thead>
                  <tbody>
                    <tr v-for="a in stageDetail.assets" :key="'sa-' + a.id">
                      <td><span class="tag">{{ kindLabel(a.kind) }}</span></td>
                      <td class="mono ellipsis" style="max-width: 340px" :title="a.url">
                        <a v-if="String(a.url).startsWith('http')" :href="a.url" target="_blank" rel="noopener">{{ a.url }}</a>
                        <span v-else>{{ a.url }}</span>
                      </td>
                      <td class="mono">{{ a.alive_text || a.status_code || '-' }}</td>
                      <td class="ellipsis" style="max-width: 180px">{{ a.fingerprint }}</td>
                      <td class="muted ellipsis" style="max-width: 120px">{{ a.sources }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
            <div v-else class="muted" style="font-size: 12px">这一阶段没有入库资产</div>
          </template>
          <div>
            <div class="sub-title">日志样本（最多 40 条，错误和告警优先）</div>
            <div class="logbox" style="height: 240px">
              <div v-for="(l, i) in stageDetail?.samples || []" :key="'sl-' + i" class="logline" :class="l.level">
                <span class="lt">{{ fmt(l.ts) }}</span>
                <span class="lm">{{ l.level }}</span>
                <span class="lx">{{ l.msg }}</span>
              </div>
              <div v-if="!(stageDetail?.samples || []).length" class="muted">这一阶段没有日志</div>
            </div>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn sm" @click="closeStage">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.td { display: flex; flex-direction: column; gap: 12px; }

/* ── 阶段重测范围 ── */
.rerun-box {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px 11px;
  border: 1px solid var(--line);
  border-radius: 10px;
  background: var(--panel-2, rgba(255, 255, 255, 0.02));
}
.subgrid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 5px;
}
.subitem {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 7px;
  border: 1px solid var(--line);
  border-radius: 7px;
  font-size: 11.5px;
  cursor: pointer;
  min-width: 0;
  color: var(--muted);
}
.subitem:hover { border-color: var(--line-2, var(--line)); color: var(--text-2); }
.subitem.on { color: var(--text); border-color: rgba(52, 229, 200, 0.38); background: rgba(52, 229, 200, 0.06); }
.subitem input { accent-color: var(--cyan); margin: 0; }

/* ── 状态条 ── */
.hero {
  position: relative;
  padding: 13px 15px 12px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background:
    radial-gradient(680px 160px at 6% -60%, rgba(52, 229, 200, 0.14), transparent 70%),
    var(--panel);
}
.hero-top { display: flex; align-items: center; justify-content: space-between; gap: 14px; }
.hero-left { display: flex; align-items: center; gap: 9px; min-width: 0; }
.hero-msg { font-size: 12px; color: var(--text-2); }
.hero-right { display: flex; align-items: baseline; gap: 7px; flex: 0 0 auto; }
.hero-pct { font-size: 20px; font-weight: 600; color: var(--cyan); line-height: 1; }
.hero-pct em { font-style: normal; font-size: 12px; color: var(--muted); margin-left: 1px; }
.hero-pct-label { font-size: 10px; color: var(--muted-2); letter-spacing: 0.6px; }
.hero-bar { margin: 9px 0 8px; height: 5px; }
.hero-type { display: flex; align-items: center; gap: 8px; min-width: 0; margin-bottom: 9px; }
.hero-mods {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 5px 16px;
}
.mp {
  display: grid;
  grid-template-columns: 17px minmax(96px, 148px) minmax(50px, 1fr) 38px auto;
  align-items: center;
  gap: 8px;
  font-size: 11.5px;
  color: var(--text-2);
}
.mp.skip { opacity: 0.42; }
.mp-no {
  width: 17px; height: 17px; border-radius: 5px;
  display: grid; place-items: center;
  font-size: 10px;
  background: rgba(120, 200, 220, 0.09);
  color: var(--muted);
}
.mp-name { color: var(--text); font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.mp-name em { font-style: normal; font-weight: 400; font-size: 10.5px; color: var(--muted); margin-left: 5px; }
.mp-bar { height: 6px; border-radius: 999px; background: rgba(120, 200, 220, 0.1); overflow: hidden; }
.mp-bar > i { display: block; height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--cyan-2), var(--cyan)); }
.mp-pct { text-align: right; color: var(--muted); font-size: 10.5px; }

/* ── 子模块导航 ── */
.td-tabs {
  display: flex;
  gap: 4px;
  padding: 4px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--panel);
  overflow-x: auto;
}
.td-tab {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  height: 34px;
  padding: 0 13px;
  border-radius: 9px;
  border: 1px solid transparent;
  color: var(--text-2);
  font-size: 12.5px;
  font-weight: 600;
  white-space: nowrap;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
}
.td-tab svg { color: var(--muted); transition: color 0.15s; }
.td-tab:hover { background: rgba(120, 200, 220, 0.07); color: var(--text); }
.td-tab.on {
  color: var(--cyan-ink);
  border-color: rgba(52, 229, 200, 0.42);
  background: linear-gradient(180deg, rgba(52, 229, 200, 0.2), rgba(52, 229, 200, 0.08));
}
.td-tab.on svg { color: var(--cyan); }
.td-badge {
  min-width: 18px;
  height: 16px;
  padding: 0 5px;
  border-radius: 5px;
  font: 600 10px/16px var(--mono);
  text-align: center;
  color: var(--muted);
  background: rgba(120, 200, 220, 0.1);
}
.td-tab.on .td-badge { color: var(--cyan-ink); background: rgba(52, 229, 200, 0.16); }

.pane { display: flex; flex-direction: column; gap: 12px; min-height: 220px; }

/* ── 概览指标卡 ── */
.ov-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(146px, 1fr)); gap: 10px; }
.ov-card {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 11px 13px 10px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background:
    radial-gradient(160px 90px at 100% 0%, var(--tone-glow, rgba(52, 229, 200, 0.08)), transparent 72%),
    var(--surface-2);
  overflow: hidden;
  transition: border-color 0.16s, background 0.16s, transform 0.16s, box-shadow 0.16s;
}
.ov-card::before {
  content: "";
  position: absolute;
  left: 0; top: 12px; bottom: 12px;
  width: 2px; border-radius: 2px;
  background: linear-gradient(180deg, var(--tone, var(--cyan)), transparent);
  opacity: 0.75;
}
.ov-card.clickable { cursor: pointer; }
.ov-card.clickable:hover {
  border-color: var(--line-strong);
  transform: translateY(-1px);
  box-shadow: 0 8px 22px -14px var(--tone, rgba(52, 229, 200, 0.5));
}
.ov-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.ov-ico {
  display: grid;
  place-items: center;
  width: 22px; height: 22px;
  border-radius: 7px;
  color: var(--tone, var(--cyan));
  background: color-mix(in srgb, var(--tone, var(--cyan)) 14%, transparent);
  border: 1px solid color-mix(in srgb, var(--tone, var(--cyan)) 26%, transparent);
}
.ov-label {
  font-family: var(--mono);
  font-size: 9.5px;
  letter-spacing: 0.8px;
  text-transform: uppercase;
  color: var(--muted-2);
}
.ov-value {
  font-size: 24px;
  font-weight: 600;
  line-height: 1.3;
  letter-spacing: -0.01em;
  font-variant-numeric: tabular-nums;
  color: var(--text);
}
.ov-slash { font-style: normal; font-size: 12px; color: var(--muted); margin-left: 1px; }
.ov-foot { font-size: 10.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tone-cyan { --tone: #34e5c8; --tone-glow: rgba(52, 229, 200, 0.1); }
.tone-blue { --tone: #4fb6ff; --tone-glow: rgba(79, 182, 255, 0.1); }
.tone-violet { --tone: #9d8cff; --tone-glow: rgba(157, 140, 255, 0.1); }
.tone-amber { --tone: #f5b544; --tone-glow: rgba(245, 181, 68, 0.1); }
.tone-green { --tone: #4ade80; --tone-glow: rgba(74, 222, 128, 0.1); }
.tone-slate { --tone: #7d93a8; --tone-glow: rgba(125, 147, 168, 0.09); }
.tone-red { --tone: #ff6470; --tone-glow: rgba(255, 100, 112, 0.1); }
html[data-theme="light"] .tone-cyan { --tone: #0e9b88; }
html[data-theme="light"] .tone-blue { --tone: #2f7ed8; }
html[data-theme="light"] .tone-violet { --tone: #7057e0; }
html[data-theme="light"] .tone-amber { --tone: #b97a10; }
html[data-theme="light"] .tone-green { --tone: #1f9d55; }
html[data-theme="light"] .tone-slate { --tone: #5a7180; }
html[data-theme="light"] .tone-red { --tone: #c62f3e; }

/* ── 分布条 ── */
.ov-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; }
.bars { display: flex; flex-direction: column; gap: 5px; }
.bar {
  display: grid;
  grid-template-columns: minmax(64px, 132px) minmax(40px, 1fr) 64px;
  align-items: center;
  gap: 9px;
  font-size: 11.5px;
  color: var(--text-2);
}
.bar-key { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-2); font-size: 11px; }
.bar-track { height: 7px; border-radius: 999px; background: rgba(120, 200, 220, 0.08); overflow: hidden; }
.bar-track i { display: block; height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--cyan-2), var(--cyan)); }
.bar-track i.alt { background: linear-gradient(90deg, #3b6fd4, #4fb6ff); }
.bar-val { text-align: right; color: var(--text-2); font-size: 11px; }
.bar-val em { font-style: normal; color: var(--cyan); }

/* ── 任务信息 ── */
.kv { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px 16px; }
.kv-item { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.kv-item.wide { grid-column: 1 / -1; }
.kv-k { font-size: 10.5px; color: var(--muted); letter-spacing: 0.4px; }
.kv-v { font-size: 12px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* ── 筛选胶囊 ── */
.chips { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 26px;
  padding: 0 10px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: rgba(120, 200, 220, 0.04);
  color: var(--text-2);
  font-size: 11.5px;
  white-space: nowrap;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
}
.chip b { font-family: var(--mono); font-size: 10px; color: var(--text); }
.chip:hover { border-color: var(--line-strong); color: var(--text); }
.chip.on { border-color: rgba(52, 229, 200, 0.5); background: rgba(52, 229, 200, 0.14); color: var(--cyan-ink); }
.chip.on b { color: var(--cyan-ink); }

/* ── 渠道表 ── */
.src-table { max-height: 460px; overflow-y: auto; border: 1px solid var(--line-soft); border-radius: 8px; }
.src-name { color: var(--text); font-weight: 550; }
.src-slug {
  margin-left: 8px;
  padding-left: 8px;
  border-left: 1px solid var(--line);
  font-size: 10.5px;
  color: var(--muted-2);
}

/* ── 阶段轨迹 ── */
.stg-list { display: flex; flex-direction: column; gap: 10px; }
.stg { display: flex; flex-direction: column; gap: 4px; }
.stg-head { display: flex; align-items: center; gap: 9px; min-height: 20px; padding: 0 2px; }
.stg-name { font-size: 12px; font-weight: 650; color: var(--text); white-space: nowrap; }
.stg-rows { display: flex; flex-direction: column; gap: 4px; }
.stg-row {
  display: grid;
  grid-template-columns: minmax(120px, 210px) minmax(120px, 1fr) 52px;
  align-items: center;
  gap: 12px;
  padding: 7px 10px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: rgba(120, 200, 220, 0.025);
  color: var(--text-2);
  font-size: 11.5px;
  text-align: left;
  transition: border-color 0.15s, background 0.15s;
}
.stg-row:hover { border-color: rgba(52, 229, 200, 0.42); background: rgba(52, 229, 200, 0.06); }
.stg-row.idle { opacity: 0.5; }
.stg-cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.stg-label { color: var(--text); font-weight: 550; }
.stg-counts { font-size: 10.5px; color: var(--text-2); }
.stg-nums { display: flex; flex-wrap: wrap; align-items: center; gap: 5px 7px; }
.stg-dur { text-align: right; color: var(--muted); font-size: 10.5px; }

/* ── 阶段弹窗内的小标题与两列 ── */
.two-col { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }
.sub-title {
  font-size: 10.5px;
  letter-spacing: 0.7px;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 6px;
}
.logs { height: 58vh; }

/* 浅底上青色半透明底会发灰，给分段/胶囊一层更实的底 */
:global(html[data-theme="light"]) .td-tab.on { background: linear-gradient(180deg, rgba(14, 155, 136, 0.16), rgba(14, 155, 136, 0.07)); }
:global(html[data-theme="light"]) .chip.on { background: rgba(14, 155, 136, 0.12); border-color: rgba(14, 155, 136, 0.4); }
:global(html[data-theme="light"]) .td-badge { background: rgba(24, 62, 82, 0.07); }
:global(html[data-theme="light"]) .td-tab.on .td-badge { background: rgba(14, 155, 136, 0.16); }
:global(html[data-theme="light"]) .comp { background: rgba(24, 62, 82, 0.06); }
:global(html[data-theme="light"]) .bar-track { background: rgba(24, 62, 82, 0.08); }
:global(html[data-theme="light"]) .mp-bar { background: rgba(24, 62, 82, 0.09); }
:global(html[data-theme="light"]) .hero { background: radial-gradient(680px 160px at 6% -60%, rgba(14, 155, 136, 0.1), transparent 70%), #ffffff; }

@media (max-width: 720px) {
  .hero-mods { grid-template-columns: 1fr; }
  .stg-row { grid-template-columns: 1fr; gap: 6px; }
  .stg-dur { text-align: left; }
  .bar { grid-template-columns: minmax(52px, 100px) minmax(30px, 1fr) 54px; }
  .td-tab { padding: 0 10px; }
}
</style>
