<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import AssetTable from '@/components/AssetTable.vue'
import {
  assetFacets, exportSheets, exportWorkbook, getTask, listAssets, listModules,
  listTasks, repairLiveness, riskOverview,
} from '@/api/endpoints'

const route = useRoute()
const router = useRouter()

const filters = reactive({
  keyword: route.query.keyword || '',
  kind: route.query.kind || '',
  root_domain: route.query.root || '',
  port: '',
  fingerprint: '',
  cdn: '',
  surface: route.query.surface || '',
  risk: route.query.risk || '',
  task_id: route.query.task || route.query.task_id || '',
  stage: route.query.stage || '',
  is_new: route.query.is_new === '1',
  order: 'last_seen DESC',
  min_ratio: 0,
})
const items = ref([])
const total = ref(0)
const offset = ref(0)
const limit = 100
const loading = ref(false)
const facets = ref({ kind: [], port: [], fingerprint: [], root_domain: [], cdn: [], surfaces: {}, labels: {} })
const risks = ref({ total: 0, buckets: [] })
const detail = ref(null)

// ── 三个视角：总览（全库一张表）/ 按任务 / 分表（子公司、ICP…一张一类） ──
const VIEWS = [
  { key: 'overview', label: '总览' },
  { key: 'tasks', label: '按任务' },
  { key: 'sheets', label: '分表' },
]
const view = ref(['overview', 'tasks', 'sheets'].includes(route.query.view) ? route.query.view : 'overview')
function setView(v) {
  view.value = v
  const q = { ...route.query }
  if (v === 'overview') delete q.view
  else q.view = v
  router.replace({ path: route.path, query: q })
  if (v === 'sheets') loadSheet()
}

// 类型中文名统一取后端一份，前端不再各存一张表
const kindLabel = ref({})
const k = (key) => kindLabel.value[key] || key || '-'
async function loadKinds() {
  try {
    const res = await listModules()
    const map = {}
    for (const it of res?.kinds || []) map[it.key] = it.label
    kindLabel.value = map
  } catch {
    /* 拿不到就显示原始 kind */
  }
}

// ── 分表：后端 EXPORT_SHEETS 就是这套分类，前端只摆卡片 ──
// 控股比例只对带持股字段的那几张表有意义，后端在 sheets 里用 ratio 标出来
const RATIO_SHEETS = new Set(['holds', 'invest', 'partner', 'branch'])
const RATIO_OPTIONS = [
  { v: 0, label: '控股比例不限' },
  { v: 50, label: '控股 ≥ 50%' },
  { v: 30, label: '控股 ≥ 30%' },
  { v: 10, label: '控股 ≥ 10%' },
]
const sheets = ref([{ key: 'all', label: '全量资产', kinds: [], count: 0 }])
const sheetKey = ref('all')
const activeSheet = computed(() => sheets.value.find((s) => s.key === sheetKey.value) || null)
const sheetKinds = computed(() => activeSheet.value?.kinds || [])
const ratioActive = computed(() => RATIO_SHEETS.has(sheetKey.value))
const ratioParam = computed(() => (ratioActive.value && filters.min_ratio ? filters.min_ratio : undefined))

// ── 分表自己的明细：独立请求 + 序号守卫 ──
// 以前点一张表会同时打两次 /api/assets（一次带 kinds、一次全量），后到的全量把结果盖掉，
// 于是「控股企业 309 条」点开变成 65,256 条。这里一次点击只发一个请求，晚到的旧响应直接丢。
const sheetItems = ref([])
const sheetTotal = ref(0)
const sheetOffset = ref(0)
const sheetLoading = ref(false)
let sheetSeq = 0

async function loadSheet(reset = true) {
  if (reset) sheetOffset.value = 0
  const seq = ++sheetSeq
  sheetLoading.value = true
  try {
    const res = await listAssets({
      keyword: filters.keyword.trim() || undefined,
      kinds: sheetKinds.value.length ? sheetKinds.value.join(',') : undefined,
      min_ratio: ratioParam.value,
      task_id: filters.task_id || undefined,
      stage: filters.stage || undefined,
      root_domain: filters.root_domain || undefined,
      is_new: filters.is_new ? 1 : undefined,
      order: filters.order,
      limit,
      offset: sheetOffset.value,
    })
    if (seq !== sheetSeq) return
    sheetItems.value = res.items || []
    sheetTotal.value = res.total || 0
  } finally {
    if (seq === sheetSeq) sheetLoading.value = false
  }
}
const sheetPages = computed(() => Math.max(1, Math.ceil(sheetTotal.value / limit)))
const sheetPage = computed(() => Math.floor(sheetOffset.value / limit) + 1)
function goSheetPage(n) {
  sheetOffset.value = (n - 1) * limit
  loadSheet(false)
}
const activeSheetNote = computed(() => {
  const s = activeSheet.value
  if (!s || !s.kinds?.length) return '库里全部类型'
  return s.kinds.map((x) => k(x)).join(' / ')
})

async function loadSheets() {
  try {
    const res = await exportSheets({
      task_id: filters.task_id || undefined,
      keyword: filters.keyword.trim() || undefined,
      ratio: filters.min_ratio || undefined,
    })
    if (res?.items?.length) sheets.value = res.items
  } catch {
    /* 拿不到就只留全量表 */
  }
}
function pickSheet(key) {
  sheetKey.value = key
  loadSheet()
}
function applyRatio() {
  loadSheets()
  loadSheet()
}

// ── 按任务：任务卡片 = 这趟侦察自己收了多少、都是什么类型 ──
const tasks = ref([])
const taskQ = ref('')
const taskRows = computed(() => {
  const q = taskQ.value.trim().toLowerCase()
  return tasks.value
    .filter((t) => (t.counts?.total || 0) > 0)
    .filter((t) => !q || `${t.name || ''} ${t.target || ''}`.toLowerCase().includes(q))
    .sort((a, b) => (b.counts?.total || 0) - (a.counts?.total || 0))
})
async function loadTasks() {
  try {
    const res = await listTasks({ limit: 300 })
    tasks.value = res?.items || []
  } catch {
    tasks.value = []
  }
}
const STATUS_LABEL = { running: '执行中', finished: '已完成', stopped: '已停止', failed: '异常', pending: '排队中' }
function drillTask(t) {
  filters.task_id = t.id
  filters.stage = ''
  setView('overview')
  router.replace({ path: route.path, query: { task: t.id } })
  loadTaskName()
  loadFacets()
  loadRisks()
  loadSheets()
  search()
}
// 任务卡里只摆前几类，剩下的折成一句，避免一排数字看花眼
function kindsOf(t) {
  const rows = Object.entries(t.counts?.kinds || {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
  return rows.map(([key, n]) => ({ key, label: k(key), n }))
}
function modsOf(t) {
  return (t.modules || []).filter((m) => m.state !== 'skip')
}

const taskName = ref('')
async function loadTaskName() {
  if (!filters.task_id) {
    taskName.value = ''
    return
  }
  try {
    const t = await getTask(filters.task_id)
    taskName.value = t?.name || ''
  } catch {
    taskName.value = ''
  }
}

const SURFACES = [
  { key: 'web', label: 'Web', icon: 'globe' },
  { key: 'applet', label: '小程序', icon: 'layers' },
  { key: 'mp', label: '公众号', icon: 'chat' },
  { key: 'app', label: 'APP', icon: 'bolt' },
  { key: 'netblock', label: '网段', icon: 'server' },
  { key: 'icp', label: '备案', icon: 'file' },
  { key: 'meta', label: '主体与邮箱', icon: 'group' },
]
// 阶段过滤的展示名；与任务详情里的阶段轨迹保持同一套中文
const STAGE_LABEL = {
  target_parse: '目标归一', enterprise: '企业主体', equity: '股权穿透', mobile: '小程序/APP',
  local_mini: '本地小程序', passive: '被动子域', space: '空间测绘', brute: '字典爆破',
  dns: 'DNS/CDN', port: '端口扫描', web: '存活探测', crawl: '站点爬虫', leak: '敏感文件',
  vhost: 'VHost碰撞', takeover: '子域接管', sibling: '旁站C段', deep: '深度挖掘',
  assetdiff: '资产变更', report: '汇总',
}
const ORDERS = [
  { v: 'last_seen DESC', label: '最近发现' },
  { v: 'first_seen DESC', label: '最新入库' },
  { v: 'host ASC', label: '地址排序' },
  { v: 'status_code DESC', label: '状态码' },
]

const pages = computed(() => Math.max(1, Math.ceil(total.value / limit)))
const page = computed(() => Math.floor(offset.value / limit) + 1)
const surfaceTotal = computed(() => Object.values(facets.value.surfaces || {}).reduce((s, n) => s + (n || 0), 0))
const riskBuckets = computed(() => (risks.value.buckets || []).filter((b) => b.count > 0))

function params() {
  return {
    keyword: filters.keyword.trim() || undefined,
    kind: filters.kind || undefined,
    root_domain: filters.root_domain || undefined,
    port: filters.port || undefined,
    cdn: filters.cdn || undefined,
    surface: filters.surface || undefined,
    risk: filters.risk || undefined,
    task_id: filters.task_id || undefined,
    stage: filters.stage || undefined,
    is_new: filters.is_new ? 1 : undefined,
    order: filters.order,
    limit,
    offset: offset.value,
  }
}

// 检索也加序号守卫：翻页快 / 换条件快时，先发的响应不能覆盖后发的
let searchSeq = 0
async function search(reset = true) {
  if (reset) offset.value = 0
  const seq = ++searchSeq
  loading.value = true
  try {
    const res = await listAssets(params())
    if (seq !== searchSeq) return
    items.value = res.items || []
    total.value = res.total || 0
  } finally {
    if (seq === searchSeq) loading.value = false
  }
}

function pick(field, value) {
  filters[field] = filters[field] === value ? '' : value
  search()
}

// 历史任务的域名 / 接口 / 端口行没探过 HTTP，状态一直是空。
// 这里按已探到的站点状态回填同主机的行，补完刷新就能看出死活。
const repairing = ref(false)
async function repairAlive() {
  repairing.value = true
  try {
    const res = await repairLiveness(filters.task_id || '')
    ElMessage.success(`已补全 ${res.updated || 0} 条资产的存活状态`)
    await search()
    loadFacets()
  } finally {
    repairing.value = false
  }
}

function pickSurface(key) {
  filters.surface = filters.surface === key ? '' : key
  search()
}

function pickRisk(key) {
  filters.risk = filters.risk === key ? '' : key
  search()
}

function clearTask() {
  filters.task_id = ''
  taskName.value = ''
  const q = { ...route.query }
  delete q.task
  delete q.task_id
  router.replace({ path: route.path, query: q })
  loadFacets()
  loadRisks()
  loadSheets()
  search()
}

function clearRoot() {
  filters.root_domain = ''
  const q = { ...route.query }
  delete q.root
  router.replace({ path: route.path, query: q })
  search()
}

// 阶段过滤挂在任务下面：同一个 host 可能是这趟 P4 收的、下趟 P6 才探到
function clearStage() {
  filters.stage = ''
  const q = { ...route.query }
  delete q.stage
  router.replace({ path: route.path, query: q })
  loadFacets()
  search()
}

function goPage(n) {
  offset.value = (n - 1) * limit
  search(false)
}

async function loadFacets() {
  try {
    facets.value = await assetFacets({ task_id: filters.task_id || undefined, stage: filters.stage || undefined })
  } catch {
    /* 分面拿不到不影响检索 */
  }
}

async function loadRisks() {
  try {
    risks.value = await riskOverview({ task_id: filters.task_id || undefined, limit: 3 })
  } catch {
    /* 脆弱面拿不到不影响检索 */
  }
}

function saveBlob(data, name) {
  const url = URL.createObjectURL(data instanceof Blob ? data : new Blob([data]))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  a.remove()
  // 立刻回收会让部分浏览器把还没写完的下载掐掉，等两秒再释放
  setTimeout(() => URL.revokeObjectURL(url), 2000)
}

// 导出整本：一张工作表一类资产，交接时不用再自己拆表
const exporting = ref(false)
async function exportAll() {
  if (exporting.value) return
  exporting.value = true
  try {
    const blob = await exportWorkbook({
      task_id: filters.task_id || undefined,
      keyword: filters.keyword.trim() || undefined,
      ratio: filters.min_ratio || undefined,
    })
    saveBlob(blob, `suoyu_资产台账_${new Date().toISOString().slice(0, 10)}.xlsx`)
  } finally {
    exporting.value = false
  }
}

// 单个任务导一本：任务卡上的「导出」直接拿这趟的全部类型分表
async function exportTask(t) {
  const blob = await exportWorkbook({ task_id: t.id })
  saveBlob(blob, `suoyu_${String(t.name || t.id).replace(/[\\/:*?"<>|]/g, '_')}.xlsx`)
}

async function exportCsv() {
  const http = (await import('@/api/http')).default
  // 导出跟屏上这张表的口径一致：表、关键字、任务、根域、控股比例都带上
  const res = await http.get('/api/export', {
    params: {
      fmt: 'csv',
      sheet: sheetKey.value || 'all',
      keyword: filters.keyword.trim() || undefined,
      task_id: filters.task_id || undefined,
      root_domain: filters.root_domain || undefined,
      ratio: ratioParam.value,
      limit: undefined,
      offset: undefined,
    },
    responseType: 'blob',
  })
  saveBlob(res, `suoyu_${sheetKey.value || 'all'}.csv`)
}

async function openDetail(a) {
  const http = (await import('@/api/http')).default
  const res = await http.get(`/api/assets/${a.id}`)
  detail.value = res.item
}

function copy(text) {
  navigator.clipboard?.writeText(text)
}

// 详情弹窗里 extra 是嵌套对象：把测绘/Whois 这类平铺字段翻成中文排前面，
// 证书、指纹这种结构化的仍按 JSON 展示，别让用户对着一坨英文键名找字段
const EXTRA_LABEL = {
  protocol: '协议', app: '应用', product: '产品', isp: 'ISP', os: 'OS',
  country: '国家', province: '省份', city: '城市', updated: '更新时间',
  whois: 'Whois 注册商', whois_created: 'Whois 注册', whois_expires: 'Whois 到期',
  icp: 'ICP备案', title: '标题', server: '中间件', cdn: 'CDN',
}
const detailFields = computed(() => {
  const a = detail.value
  if (!a) return []
  let ex = a.extra
  if (typeof ex === 'string') {
    try {
      ex = JSON.parse(ex || '{}')
    } catch {
      ex = {}
    }
  }
  ex = ex && typeof ex === 'object' ? ex : {}
  const out = []
  for (const [key, label] of Object.entries(EXTRA_LABEL)) {
    const v = ex[key]
    if (v === undefined || v === null || v === '' || (typeof v === 'object' && !Object.keys(v).length)) continue
    out.push([label, typeof v === 'object' ? JSON.stringify(v) : v])
  }
  const skip = new Set(['extra', 'cert', 'fingerprint'])
  for (const [key, v] of Object.entries(a)) {
    if (skip.has(key) || key === 'extra_json') continue
    if (v === undefined || v === null || v === '') continue
    out.push([key, typeof v === 'object' ? JSON.stringify(v) : v])
  }
  return out
})

function openRisk() {
  router.push({ path: '/risk', query: filters.task_id ? { task: filters.task_id } : {} })
}

watch(() => [route.query.task, route.query.task_id], ([v, w]) => {
  const next = v || w || ''
  if (next !== filters.task_id) {
    filters.task_id = next
    // 阶段属于任务内维度，换任务后旧阶段没有意义
    filters.stage = route.query.stage || ''
    loadTaskName()
    loadFacets()
    loadRisks()
    loadSheets()
    search()
    if (view.value === 'sheets') loadSheet()
  }
})

watch(() => route.query.root, (v) => {
  if ((v || '') !== filters.root_domain) {
    filters.root_domain = v || ''
    search()
    if (view.value === 'sheets') loadSheet()
  }
})

watch(() => route.query.stage, (v) => {
  if ((v || '') !== filters.stage) {
    filters.stage = v || ''
    loadFacets()
    search()
    if (view.value === 'sheets') loadSheet()
  }
})

watch(() => route.query.view, (v) => {
  const next = ['overview', 'tasks', 'sheets'].includes(v) ? v : 'overview'
  if (next !== view.value) {
    view.value = next
    if (next === 'sheets') loadSheet()
  }
})

onMounted(() => {
  loadKinds()
  loadTaskName()
  loadFacets()
  loadRisks()
  loadSheets()
  loadTasks()
  search()
  if (view.value === 'sheets') loadSheet()
})
</script>

<template>
  <div class="stack">
    <PageHead title="资产台账" desc="全库检索：域名、站点、IP、服务、工商主体统一入库，按分表 / 任务 / 资产面拆开看">
      <template #actions>
        <button class="btn sm" :disabled="repairing" @click="repairAlive">
          <Icon name="bolt" :size="13" />{{ repairing ? '补全中…' : '补全存活状态' }}
        </button>
        <button class="btn sm" @click="openRisk"><Icon name="bolt" :size="13" />脆弱资产</button>
        <button class="btn sm" :disabled="exporting" @click="exportAll">
          <Icon name="download" :size="13" />{{ exporting ? '导出中…' : '导出整本 Excel' }}
        </button>
        <button class="btn primary sm" @click="router.push('/oneclick')"><Icon name="bolt" :size="13" />一键收集全</button>
      </template>
    </PageHead>

    <div class="panel">
      <div class="panel-body">
        <div class="row" style="justify-content: space-between">
          <div class="seg">
            <button v-for="v in VIEWS" :key="v.key" :class="{ on: view === v.key }" @click="setView(v.key)">
              {{ v.label }}
            </button>
          </div>

          <div v-if="view === 'overview'" class="row">
            <input v-model="filters.keyword" class="input" style="width: 240px"
                   placeholder="关键字：URL / 标题 / 指纹 / 主机" @keyup.enter="search()" />
            <select v-model="filters.order" class="select" style="width: 120px" @change="search()">
              <option v-for="o in ORDERS" :key="o.v" :value="o.v">{{ o.label }}</option>
            </select>
            <button class="btn primary sm" @click="search()"><Icon name="search" :size="13" />检索</button>
            <button class="btn sm" :class="{ primary: filters.is_new }"
                    @click="filters.is_new = !filters.is_new; search()">
              <Icon name="flow" :size="13" />只看新增
            </button>
          </div>

          <div v-else-if="view === 'tasks'" class="row">
            <input v-model="taskQ" class="input" style="width: 200px" placeholder="任务名 / 目标" />
            <span class="muted" style="font-size: 11.5px">{{ taskRows.length }} 个任务有资产</span>
          </div>

          <div v-else class="row">
            <input v-model="filters.keyword" class="input" style="width: 240px"
                   placeholder="在当前表里找：名称 / 备案号 / 法人" @keyup.enter="loadSheet()" />
            <select v-model="filters.order" class="select" style="width: 120px" @change="loadSheet()">
              <option v-for="o in ORDERS" :key="o.v" :value="o.v">{{ o.label }}</option>
            </select>
            <button class="btn primary sm" @click="loadSheet()"><Icon name="search" :size="13" />表内检索</button>
          </div>
        </div>

        <div v-if="view === 'overview'" class="surface-row">
          <button class="surface" :class="{ on: !filters.surface }" @click="filters.surface = ''; search()">
            <span class="surface-name">全部资产</span>
            <span class="surface-num mono">{{ surfaceTotal.toLocaleString() }}</span>
          </button>
          <button v-for="s in SURFACES" :key="s.key" class="surface" :class="{ on: filters.surface === s.key }" @click="pickSurface(s.key)">
            <span class="surface-name"><Icon :name="s.icon" :size="12" />{{ facets.labels[s.key] || s.label }}</span>
            <span class="surface-num mono">{{ (facets.surfaces[s.key] || 0).toLocaleString() }}</span>
          </button>
        </div>

        <div v-if="filters.task_id || filters.risk || filters.root_domain || filters.stage || filters.kind" class="scope-row">
          <span v-if="filters.task_id" class="chip on" :title="filters.task_id">
            任务 {{ taskName || filters.task_id }}
            <button class="chip-x" @click="clearTask">×</button>
          </span>
          <span v-if="filters.kind" class="chip on">
            类型 {{ k(filters.kind) }}
            <button class="chip-x" @click="pick('kind', filters.kind)">×</button>
          </span>
          <span v-if="filters.stage" class="chip on">
            阶段 <span class="mono">{{ STAGE_LABEL[filters.stage] || filters.stage }}</span>
            <button class="chip-x" @click="clearStage">×</button>
          </span>
          <span v-if="filters.root_domain" class="chip on">
            根域 <span class="mono">{{ filters.root_domain }}</span>
            <button class="chip-x" @click="clearRoot">×</button>
          </span>
          <span v-if="filters.risk" class="chip on">
            脆弱面 <span class="mono">{{ (risks.buckets.find((b) => b.key === filters.risk) || {}).label || filters.risk }}</span>
            <button class="chip-x" @click="pickRisk(filters.risk)">×</button>
          </span>
        </div>
      </div>
    </div>

    <!-- 按任务：每趟侦察各自收了多少、都是什么类型，点进去就是这趟的资产表 -->
    <div v-if="view === 'tasks'" class="ta-grid">
      <article v-for="t in taskRows" :key="t.id" class="ta-card" @click="drillTask(t)">
        <header class="ta-head">
          <span class="ellipsis flex-1" :title="t.name">{{ t.name || t.id }}</span>
          <span class="tag" :class="{ ok: t.status === 'finished', warn: t.status === 'running', err: t.status === 'failed' }">
            {{ STATUS_LABEL[t.status] || t.status }}
          </span>
        </header>
        <div class="mono muted ellipsis ta-target" :title="t.target">{{ t.target || '-' }}</div>
        <div class="ta-num">
          <strong class="mono">{{ (t.counts?.total || 0).toLocaleString() }}</strong>
          <span class="muted">条去重资产</span>
          <span v-if="t.partial" class="tag info" style="margin-left: auto">局部任务</span>
        </div>
        <div class="ta-mods">
          <span v-for="m in modsOf(t)" :key="m.key" class="ta-mod" :title="`${m.label} ${m.pct}%`">
            <span class="ta-mod-name">{{ m.label }}</span>
            <span class="progress"><i :style="{ width: (m.pct || 0) + '%' }"></i></span>
          </span>
        </div>
        <div class="ta-kinds">
          <span v-for="kk in kindsOf(t).slice(0, 4)" :key="kk.key" class="kind-chip">
            {{ kk.label }}<b class="mono">{{ kk.n.toLocaleString() }}</b>
          </span>
          <span v-if="kindsOf(t).length > 4" class="muted" style="font-size: 11px">
            另有 {{ kindsOf(t).length - 4 }} 类
          </span>
          <span v-if="!kindsOf(t).length" class="muted" style="font-size: 11px">还没有资产入库</span>
        </div>
        <footer class="ta-foot">
          <button class="btn xs" @click.stop="drillTask(t)"><Icon name="search" :size="11" />看这趟资产</button>
          <button class="btn xs" @click.stop="exportTask(t)"><Icon name="download" :size="11" />导出</button>
        </footer>
      </article>
      <div v-if="!taskRows.length" class="empty" style="grid-column: 1 / -1">
        <Icon name="tasks" :size="22" />还没有收到资产的任务，先去「一键收集」跑一趟
      </div>
    </div>

    <!-- 分表：像导出的多工作表台账，上面一排表名，下面直接就是这张表的明细 -->
    <div v-else-if="view === 'sheets'" class="stack">
      <div class="sheet-bar">
        <button v-for="s in sheets" :key="s.key" class="sheet-tab" :class="{ on: sheetKey === s.key }" @click="pickSheet(s.key)">
          <span class="st-label">{{ s.label }}</span>
          <span class="st-num mono">{{ (s.count || 0).toLocaleString() }}</span>
          <span v-if="s.ratio" class="st-flag" title="这张表可按控股比例筛">%</span>
        </button>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span>
            <Icon name="layers" :size="13" />
            {{ activeSheet?.label || '全量资产' }}
            <span class="muted" style="font-size: 11px">· {{ activeSheetNote }}</span>
            <b class="mono" style="margin-left: 8px">{{ sheetTotal.toLocaleString() }}</b>
            <span class="muted" style="font-size: 11px">条</span>
          </span>
          <div class="flex gap-8">
            <select v-if="ratioActive" v-model.number="filters.min_ratio" class="select" style="width: 140px" @change="applyRatio">
              <option v-for="o in RATIO_OPTIONS" :key="o.v" :value="o.v">{{ o.label }}</option>
            </select>
            <span class="mono muted" style="font-size: 10.5px">{{ sheetPage }} / {{ sheetPages }}</span>
            <button class="btn xs" :disabled="sheetPage <= 1" @click="goSheetPage(sheetPage - 1)">上一页</button>
            <button class="btn xs" :disabled="sheetPage >= sheetPages" @click="goSheetPage(sheetPage + 1)">下一页</button>
            <button class="btn xs" @click="exportCsv"><Icon name="download" :size="11" />导出本表</button>
          </div>
        </div>
        <AssetTable :items="sheetItems" :sheet-kinds="sheetKinds" :kind-label="kindLabel" :loading="sheetLoading"
                    :empty-text="`${activeSheet?.label || '这张表'}还没有数据`" @detail="openDetail" />
      </div>
    </div>

    <div v-else class="flex gap-14" style="align-items: flex-start">
      <div class="panel" style="width: 200px; flex: 0 0 auto">
        <div class="panel-head"><span><Icon name="filter" :size="13" />分面</span></div>
        <div class="panel-body" style="max-height: calc(100vh - 340px); overflow-y: auto">
          <div class="facet-title">脆弱面</div>
          <button class="facet" :class="{ on: filters.risk === 'leak' }" @click="pickRisk('leak')">
            <span class="ellipsis">信息泄露</span><span class="mono muted">{{ (risks.buckets.find((b) => b.key === 'leak') || {}).count || 0 }}</span>
          </button>
          <button v-for="b in riskBuckets.filter((x) => x.key !== 'leak')" :key="b.key" class="facet" :class="{ on: filters.risk === b.key }" @click="pickRisk(b.key)">
            <span class="ellipsis">{{ b.label }}</span><span class="mono muted">{{ b.count }}</span>
          </button>

          <div class="facet-title">类型</div>
          <button v-for="f in facets.kind" :key="f.value" class="facet" :class="{ on: filters.kind === f.value }" @click="pick('kind', f.value)">
            <span class="ellipsis">{{ k(f.value) }}</span><span class="mono muted">{{ f.count }}</span>
          </button>

          <div class="facet-title">根域</div>
          <button v-for="f in facets.root_domain.slice(0, 15)" :key="f.value" class="facet" :class="{ on: filters.root_domain === f.value }" @click="pick('root_domain', f.value)">
            <span class="ellipsis mono">{{ f.value }}</span><span class="mono muted">{{ f.count }}</span>
          </button>

          <div class="facet-title">端口</div>
          <button v-for="f in facets.port.slice(0, 15)" :key="f.value" class="facet" :class="{ on: String(filters.port) === String(f.value) }" @click="pick('port', String(f.value))">
            <span class="mono">{{ f.value }}</span><span class="mono muted">{{ f.count }}</span>
          </button>

          <div class="facet-title">指纹</div>
          <button v-for="f in facets.fingerprint.slice(0, 15)" :key="f.value" class="facet" :class="{ on: filters.keyword === f.value }" @click="pick('keyword', f.value)">
            <span class="ellipsis">{{ f.value }}</span><span class="mono muted">{{ f.count }}</span>
          </button>

          <div class="facet-title">CDN</div>
          <button v-for="f in facets.cdn" :key="f.value" class="facet" :class="{ on: filters.cdn === f.value }" @click="pick('cdn', f.value)">
            <span class="ellipsis">{{ f.value }}</span><span class="mono muted">{{ f.count }}</span>
          </button>
        </div>
      </div>

      <div class="panel flex-1" style="min-width: 0">
        <div class="panel-head">
          <span><Icon name="layers" :size="13" /><span class="mono">{{ total.toLocaleString() }}</span> 条结果</span>
          <div class="flex gap-8">
            <span class="mono muted" style="font-size: 10.5px">{{ page }} / {{ pages }}</span>
            <button class="btn xs" :disabled="page <= 1" @click="goPage(page - 1)">上一页</button>
            <button class="btn xs" :disabled="page >= pages" @click="goPage(page + 1)">下一页</button>
          </div>
        </div>
        <AssetTable :items="items" :kind-label="kindLabel" :loading="loading" @detail="openDetail" />
      </div>
    </div>

    <div v-if="detail" class="overlay" @click.self="detail = null">
      <div class="modal">
        <div class="modal-head">
          <Icon name="layers" :size="15" style="color: var(--cyan)" />
          <span class="flex-1 ellipsis">{{ detail.url }}</span>
          <button class="btn ghost sm" @click="detail = null"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body">
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px">
            <div v-for="([key, v], i) in detailFields" :key="key + i" class="field">
              <span class="field-label">{{ key }}</span>
              <span class="mono ellipsis" style="font-size: 11.5px" :title="String(v)">{{ v }}</span>
            </div>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn sm" @click="copy(detail.url)"><Icon name="copy" :size="12" />复制地址</button>
          <a v-if="String(detail.url).startsWith('http')" :href="detail.url" target="_blank" rel="noopener" class="btn sm primary">
            <Icon name="external" :size="12" />打开站点
          </a>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.facet-title {
  margin: 10px 0 4px;
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--muted-2);
}
.facet-title:first-child { margin-top: 0; }
.facet {
  display: flex; align-items: center; justify-content: space-between; gap: 6px;
  width: 100%; height: 26px; padding: 0 6px;
  border-radius: 6px; font-size: 11.5px; color: var(--text-2); text-align: left;
}
.facet:hover { background: rgba(120, 200, 220, 0.07); }
.facet.on { background: rgba(52, 229, 200, 0.13); color: var(--cyan-ink); }

.surface-row {
  display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px;
}
.surface {
  display: flex; align-items: center; gap: 10px;
  height: 32px; padding: 0 12px; border-radius: 8px;
  border: 1px solid var(--line); background: transparent;
  color: var(--text-2); font-size: 12px;
}
.surface:hover { border-color: rgba(52, 229, 200, 0.45); color: var(--text); }
.surface.on { border-color: rgba(52, 229, 200, 0.65); background: rgba(52, 229, 200, 0.12); color: var(--cyan-ink); }
.surface-name { display: inline-flex; align-items: center; gap: 5px; }
.surface-num { font-size: 11px; color: var(--muted); }
.surface.on .surface-num { color: var(--cyan-ink); }

.scope-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
.chip-x {
  margin-left: 4px; border: 0; background: transparent; cursor: pointer;
  color: inherit; font-size: 12px; line-height: 1; padding: 0 2px;
}

/* 按任务 */
.ta-grid {
  display: grid; gap: 12px;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
}
.ta-card {
  display: flex; flex-direction: column; gap: 8px;
  padding: 12px 14px; cursor: pointer;
  border: 1px solid var(--line); border-radius: var(--radius);
  background: var(--surface-2, rgba(18, 28, 36, 0.6));
  transition: border-color 0.15s, transform 0.15s;
}
.ta-card:hover { border-color: rgba(52, 229, 200, 0.5); transform: translateY(-1px); }
.ta-head { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; }
.ta-target { font-size: 11px; }
.ta-num { display: flex; align-items: baseline; gap: 6px; font-size: 11.5px; }
.ta-num strong { font-size: 19px; color: var(--cyan); }
.ta-mods { display: flex; flex-wrap: wrap; gap: 6px 10px; }
.ta-mod { display: inline-flex; align-items: center; gap: 5px; font-size: 10.5px; color: var(--muted); }
.ta-mod-name { white-space: nowrap; }
.ta-mod .progress { width: 40px; }
.ta-kinds { display: flex; flex-wrap: wrap; gap: 5px; align-items: center; }
.kind-chip {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 1px 6px; border-radius: 5px; font-size: 10.5px;
  border: 1px solid var(--line-soft, var(--line)); color: var(--text-2);
  background: rgba(120, 200, 220, 0.05);
}
.kind-chip b { color: var(--cyan); font-weight: 600; }
.ta-foot { display: flex; gap: 6px; margin-top: 2px; }

/* 分表：一排工作表标签，选中的那张下面直接出明细 */
.sheet-bar {
  display: flex; flex-wrap: wrap; gap: 6px;
  padding: 8px; border: 1px solid var(--line); border-radius: var(--radius);
  background: var(--panel-2, rgba(120, 200, 220, 0.03));
}
.sheet-tab {
  display: inline-flex; align-items: center; gap: 6px;
  height: 28px; padding: 0 10px; border-radius: 7px; cursor: pointer;
  border: 1px solid transparent; background: transparent;
  color: var(--text-2); font-size: 12px; white-space: nowrap;
}
.sheet-tab:hover { background: rgba(120, 200, 220, 0.09); color: var(--text); }
.sheet-tab.on {
  border-color: rgba(52, 229, 200, 0.55); background: rgba(52, 229, 200, 0.13); color: var(--cyan-ink);
}
.st-num { font-size: 11px; color: var(--muted); }
.sheet-tab.on .st-num { color: var(--cyan-ink); }
.st-flag {
  padding: 0 4px; border-radius: 4px; font-size: 9.5px; line-height: 14px;
  border: 1px solid rgba(52, 229, 200, 0.35); color: var(--cyan);
}
</style>
