<script setup>
// 功能自检 = 全收集流程的五段：主体收集 → 域名收集 → 空间测绘 → 主动探测 → 深度挖掘。
// 一屏一张卡，卡里就是这一段该管的事：勾哪几个阶段、走哪几路来源（主源 / 辅助）、参数收在折叠里。
// 目标只在最上面填一次，五张卡和「一键跑完整流程」共用，不再每项各填一遍。
import { computed, onMounted, reactive, ref, watch } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import ParamGrid from '@/components/ParamGrid.vue'
import RunLive from '@/components/RunLive.vue'
import OpsDirect from '@/components/OpsDirect.vue'
import { exportAssets, opsCatalog, opsRun } from '@/api/endpoints'

// 这几项是来源勾选，卡上单独画成「主源 / 辅助」两栏，不再进参数表重复一遍
const SOURCE_PARAMS = ['equity_sources', 'sources', 'space_engines']
const MEM_KEY = 'suoyu_ops_v2'
const CIRCLED = ['①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧']
// 主源/辅助源多于这个数就折叠，否则几十个芯片糊满一屏，跟以前那张杂项清单没区别
const PRIMARY_FOLD = 6
const AUX_FOLD = 10
const MODULE_ICON = {
  subject: 'building',
  domain: 'globe',
  space: 'radar',
  probe: 'server',
  deep: 'aim',
}

const loading = ref(false)
const loadErr = ref('')
const catalog = reactive({ items: [], modules: [], groups: [], tools: [] })
const cards = ref([])
const goal = reactive({ target: '', expand: true, seedTask: '', more: false })
const full = reactive({ running: false, taskId: '', steps: [], err: '', total: 0 })
const history = ref([])
const tools = reactive({ sel: '', dOpts: {}, dRes: null, dRunning: false, dErr: '' })
const memory = reactive({ cards: {}, directs: {} })

// ── 本地记住勾选与参数：切走再回来还是上次那套 ──
function readMemory() {
  try {
    const raw = JSON.parse(localStorage.getItem(MEM_KEY) || '{}')
    if (!raw || typeof raw !== 'object') return
    if (raw.cards && typeof raw.cards === 'object') memory.cards = raw.cards
    if (raw.directs && typeof raw.directs === 'object') memory.directs = raw.directs
    goal.target = raw.target || ''
    goal.expand = raw.expand ?? true
    goal.seedTask = raw.seedTask || ''
  } catch (e) {
    /* 本地缓存坏了就当没有，不影响使用 */
  }
}

function snapshot() {
  const out = { target: goal.target, expand: goal.expand, seedTask: goal.seedTask, cards: {}, directs: {} }
  for (const c of cards.value) {
    out.cards[c.key] = {
      on: { ...c.on },
      deps: c.deps,
      opts: JSON.parse(JSON.stringify(c.opts || {})),
      src: JSON.parse(JSON.stringify(c.src || {})),
    }
  }
  out.directs = JSON.parse(JSON.stringify(memory.directs || {}))
  return out
}

let saveTimer = null
function save() {
  clearTimeout(saveTimer)
  saveTimer = setTimeout(() => {
    try {
      localStorage.setItem(MEM_KEY, JSON.stringify(snapshot()))
    } catch (e) {
      /* 隐私模式写不了就不存 */
    }
  }, 300)
}

function defaultsOf(params) {
  const out = {}
  for (const p of params || []) {
    const d = p.default
    if (p.type === 'multi') {
      out[p.key] = Array.isArray(d)
        ? [...d]
        : d
          ? String(d).split(',').map((x) => x.trim()).filter(Boolean)
          : []
    } else {
      out[p.key] = d
    }
  }
  return out
}

// 只认本项参数表里的键：别的功能留下的键不会被带进来
function fillOpts(params, saved) {
  const defs = defaultsOf(params)
  const out = {}
  for (const k of Object.keys(defs)) {
    const from = saved ? saved[k] : undefined
    out[k] = from === undefined ? defs[k] : JSON.parse(JSON.stringify(from))
  }
  return out
}

// ── 建五张卡 ──
function makeCard(m, prev) {
  const saved = (memory.cards && memory.cards[m.key]) || {}
  const params = (m.params || []).filter((p) => !SOURCE_PARAMS.includes(p.key))
  const labels = {}
  ;(m.stages || []).forEach((s, i) => {
    labels[s] = (m.stage_labels || [])[i] || s
  })
  const on = {}
  for (const s of m.stages || []) on[s] = saved.on ? saved.on[s] ?? true : true
  const groups = catalog.groups.filter((g) => g.module === m.key)
  const card = reactive({
    key: m.key,
    no: m.no,
    label: m.label,
    hint: m.hint,
    icon: MODULE_ICON[m.key] || 'layers',
    runKey: m.run_key,
    stages: m.stages || [],
    labels,
    params,
    directs: m.directs || [],
    groups,
    on,
    deps: saved.deps ?? false,
    opts: fillOpts(params, saved.opts),
    src: {},
    srcAll: {},
    openParams: false,
    priOpen: {},
    auxOpen: {},
    sel: (m.directs || [])[0]?.key || '',
    dParams: false,
    dKey: '',
    dOpts: {},
    dRes: null,
    dRunning: false,
    dErr: '',
    running: false,
    taskId: prev?.taskId || '',
    steps: prev?.steps || [],
    total: prev?.total || 0,
    err: '',
  })
  for (const g of card.groups) {
    const vals = saved.src ? saved.src[g.param] : undefined
    card.src[g.param] = Array.isArray(vals) ? [...vals] : [...(g.default || [])]
    card.srcAll[g.param] = !!g.empty_means_all && !card.src[g.param].length
  }
  if (card.sel) pickDirect(card, card.directs.find((d) => d.key === card.sel))
  return card
}

function buildCards() {
  const prev = {}
  for (const c of cards.value) prev[c.key] = c
  cards.value = (catalog.modules || []).map((m) => makeCard(m, prev[m.key]))
}

// ── 阶段 / 来源勾选 ──
function stagesOn(card) {
  return card.stages.filter((s) => card.on[s])
}

function onCount(card) {
  return stagesOn(card).length
}

function primaries(g) {
  return (g.options || []).filter((o) => (o.role || 'aux') === 'primary')
}

function auxs(g) {
  return (g.options || []).filter((o) => (o.role || 'aux') !== 'primary')
}

// 两栏叫什么由后端给（测绘引擎那栏不是「辅助」，是「待配 key」），前端不硬编码
function roleLabel(g, role) {
  const map = g.roles || {}
  return map[role] || (role === 'primary' ? '主源' : '辅助')
}

function auxShown(card, g) {
  if (auxs(g).length <= AUX_FOLD) return true
  return !!card.auxOpen[g.param]
}

function priShown(card, g) {
  if (primaries(g).length <= PRIMARY_FOLD) return true
  return !!card.priOpen[g.param]
}

function isOn(card, g, val) {
  if (card.srcAll[g.param]) return true
  return (card.src[g.param] || []).includes(val)
}

function toggleSrc(card, g, val) {
  if (card.srcAll[g.param]) {
    // 从「全部启用」切到「只跑勾选的」：点谁就只留谁
    card.srcAll[g.param] = false
    card.src[g.param] = [val]
    save()
    return
  }
  const cur = card.src[g.param] || (card.src[g.param] = [])
  const i = cur.indexOf(val)
  if (i >= 0) cur.splice(i, 1)
  else cur.push(val)
  // 全取消 = 后端按全开跑，这里跟着回到「全部启用」，免得界面和实际请求说的不是一件事
  if (!cur.length && g.empty_means_all) card.srcAll[g.param] = true
  save()
}

function allSrc(card, g) {
  card.src[g.param] = []
  card.srcAll[g.param] = !!g.empty_means_all
  save()
}

function onlyPrimary(card, g) {
  card.srcAll[g.param] = false
  card.src[g.param] = primaries(g).map((o) => o.value)
  save()
}

function srcPayload(card) {
  const out = {}
  for (const g of card.groups) {
    out[g.param] = card.srcAll[g.param] ? [] : [...(card.src[g.param] || [])]
  }
  return out
}

function srcOk(card) {
  for (const g of card.groups) {
    if (card.srcAll[g.param]) continue
    if ((card.src[g.param] || []).length) continue
    if (g.empty_means_all) {
      card.srcAll[g.param] = true
      continue
    }
    card.err =
      g.param === 'equity_sources'
        ? '主体收集至少要留一路工商来源：默认主源（爱企查 / 天眼查 / 备案）就够，取消后要另勾一路'
        : `${g.title}至少要留一路`
    return false
  }
  return true
}

function srcState(card, g) {
  if (card.srcAll[g.param]) return '全部启用'
  const n = (card.src[g.param] || []).length
  return n ? `只跑勾选的 ${n} 路` : '未选'
}

// ── 跑：整段 / 单项 ──
function pickErr(e) {
  return e?.response?.data?.detail || e?.message || '执行失败'
}

function stepsOf(res) {
  const stages = res?.stages || []
  const labels = res?.labels || []
  return stages.map((s, i) => ({ key: s, label: labels[i] || s }))
}

function pushHistory(label, ok, ms, note) {
  history.value.unshift({
    label: label || '功能',
    ok,
    ms: ms || 0,
    note: String(note || ''),
    at: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
  })
  if (history.value.length > 40) history.value.length = 40
}

function needTarget(it) {
  return (it?.input || 'any') !== 'none'
}

async function runModule(card) {
  if (card.running) return
  card.err = ''
  const target = goal.target.trim()
  if (!target) {
    card.err = '先在最上面填目标：企业名 / 品牌名 / 域名'
    return
  }
  const stages = stagesOn(card)
  if (!stages.length) {
    card.err = '这张卡的阶段全关掉了，至少开一个'
    return
  }
  if (!srcOk(card)) return
  card.running = true
  card.taskId = ''
  card.steps = []
  card.total = 0
  const t0 = Date.now()
  try {
    const res = await opsRun({
      key: card.runKey,
      targets: target,
      stages,
      with_deps: card.deps,
      expand_entity: goal.expand,
      seed_task: goal.seedTask.trim(),
      options: { ...card.opts, ...srcPayload(card) },
    })
    card.taskId = res.task_id
    card.steps = stepsOf(res)
    pushHistory(`${card.label}整段`, true, Date.now() - t0, `${card.steps.length} 个阶段已开跑`)
  } catch (e) {
    card.err = pickErr(e)
    card.running = false
    pushHistory(`${card.label}整段`, false, Date.now() - t0, card.err)
  }
}

function onModuleDone(card, r) {
  card.running = false
  if (r && r.total !== undefined) card.total = r.total
  pushHistory(
    `${card.label}整段`,
    (r?.status || 'done') === 'done',
    0,
    `结束 · 产出 ${r?.total || 0} 条`,
  )
}

const fullStages = computed(() => {
  const out = []
  for (const c of cards.value) {
    if (c.key === 'tail') continue
    out.push(...stagesOn(c))
  }
  return out
})

const fullSummary = computed(() => {
  const picked = cards.value.filter((c) => stagesOn(c).length)
  if (!picked.length) return '五段都关掉了，至少在一张卡上开一个阶段'
  return `要跑 ${picked.length} 段、共 ${fullStages.value.length} 个阶段：${picked
    .map((c) => c.label)
    .join(' → ')}`
})

// ── 顶部概览：几段、勾了多少阶段、这把跑出多少条、现在有没有在跑 ──
const stageTotal = computed(() => cards.value.reduce((a, c) => a + c.stages.length, 0))
const stagePicked = computed(() => cards.value.reduce((a, c) => a + onCount(c), 0))
const outTotal = computed(() => cards.value.reduce((a, c) => a + Number(c.total || 0), 0))
const runningN = computed(() => cards.value.filter((c) => c.running).length)

function jumpTo(card) {
  const el = document.getElementById(`mod-${card.key}`)
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

// 产出可能是六位数，概览卡里挤不下就用万位
function num(n) {
  const v = Number(n || 0)
  if (v < 10000) return String(v)
  return `${(v / 10000).toFixed(v < 100000 ? 1 : 0)} 万`
}

async function runFull() {
  if (full.running) return
  full.err = ''
  const target = goal.target.trim()
  if (!target) {
    full.err = '先在最上面填目标：企业名 / 品牌名 / 域名'
    return
  }
  for (const card of cards.value) card.err = ''
  const stages = fullStages.value
  if (!stages.length) {
    full.err = '五段都关掉了，至少在一张卡上开一个阶段'
    return
  }
  for (const card of cards.value) {
    if (stagesOn(card).length && !srcOk(card)) {
      full.err = `${card.label}：${card.err || '来源没选'}`
      return
    }
  }
  const opts = {}
  for (const card of cards.value) {
    if (!stagesOn(card).length) continue
    Object.assign(opts, card.opts, srcPayload(card))
  }
  full.running = true
  full.taskId = ''
  full.steps = []
  full.total = 0
  const t0 = Date.now()
  try {
    const res = await opsRun({
      key: 'stage:full',
      targets: target,
      stages,
      with_deps: false,
      expand_entity: goal.expand,
      seed_task: goal.seedTask.trim(),
      options: opts,
    })
    full.taskId = res.task_id
    full.steps = stepsOf(res)
    pushHistory('全流程（五段）', true, Date.now() - t0, `${full.steps.length} 个阶段已开跑`)
  } catch (e) {
    full.err = pickErr(e)
    full.running = false
    pushHistory('全流程（五段）', false, Date.now() - t0, full.err)
  }
}

function onFullDone(r) {
  full.running = false
  if (r && r.total !== undefined) full.total = r.total
  pushHistory('全流程（五段）', (r?.status || 'done') === 'done', 0, `结束 · 产出 ${r?.total || 0} 条`)
}

function resetCard(card) {
  card.opts = defaultsOf(card.params)
  save()
}

function curDirect(card) {
  return card.directs.find((d) => d.key === card.sel) || null
}

function pickDirect(card, it) {
  if (!it) return
  card.sel = it.key
  card.dKey = it.key
  card.dRes = null
  card.dErr = ''
  card.dParams = false
  card.dOpts = fillOpts(it.params, memory.directs ? memory.directs[it.key] : null)
}

function resetDirect(card) {
  const it = curDirect(card)
  if (it) card.dOpts = defaultsOf(it.params)
}

async function runDirect(card) {
  const it = curDirect(card)
  if (!it || card.dRunning) return
  card.dErr = ''
  card.dRes = null
  const target = needTarget(it) ? goal.target.trim() : ''
  if (needTarget(it) && !target) {
    card.dErr = '这一项要目标：先在最上面填企业名 / 域名 / IP'
    return
  }
  card.dRunning = true
  const t0 = Date.now()
  try {
    const res = await opsRun({ key: it.key, params: { target, ...card.dOpts } })
    card.dRes = res
    memory.directs[it.key] = JSON.parse(JSON.stringify(card.dOpts))
    save()
    const d = res.result
    const note = Array.isArray(d?.items)
      ? `${d.items.length} 条`
      : d?.count !== undefined
        ? `${d.count} 条`
        : `${res.elapsed_ms} ms`
    pushHistory(it.label, true, Date.now() - t0, note)
  } catch (e) {
    card.dErr = pickErr(e)
    pushHistory(it.label, false, Date.now() - t0, card.dErr)
  } finally {
    card.dRunning = false
  }
}

// ── 底部：数据源与工具（不属于五段，但也要能单独验） ──
function pickTool(it) {
  tools.sel = it.key
  tools.dRes = null
  tools.dErr = ''
  tools.dOpts = fillOpts(it.params, memory.directs ? memory.directs[it.key] : null)
}

const curTool = computed(() => (catalog.tools || []).find((t) => t.key === tools.sel) || null)

async function runTool() {
  const it = curTool.value
  if (!it || tools.dRunning) return
  tools.dErr = ''
  tools.dRes = null
  tools.dRunning = true
  const t0 = Date.now()
  try {
    const res = await opsRun({ key: it.key, params: { ...tools.dOpts } })
    tools.dRes = res
    memory.directs[it.key] = JSON.parse(JSON.stringify(tools.dOpts))
    save()
    pushHistory(it.label, true, Date.now() - t0, `${res.elapsed_ms} ms`)
  } catch (e) {
    tools.dErr = pickErr(e)
    pushHistory(it.label, false, Date.now() - t0, tools.dErr)
  } finally {
    tools.dRunning = false
  }
}

async function exportTask(taskId, tag) {
  if (!taskId) return
  try {
    const res = await exportAssets({ fmt: 'csv', sheet: 'all', task_id: taskId })
    const blob = res?.data instanceof Blob ? res.data : res instanceof Blob ? res : new Blob([res])
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `suoyu_${tag || 'task'}_${taskId}.csv`
    a.style.display = 'none'
    document.body.appendChild(a)
    a.click()
    a.remove()
    // 立刻回收会让部分浏览器把还没写完的下载掐掉，等两秒再释放
    setTimeout(() => URL.revokeObjectURL(url), 2000)
  } catch (e) {
    loadErr.value = pickErr(e)
  }
}

function stateOf(card) {
  if (card.err) return { cls: 'err', text: '有错' }
  if (card.running) return { cls: 'warn', text: '运行中' }
  if (card.total) return { cls: 'ok', text: `产出 ${card.total} 条` }
  if (card.taskId) return { cls: 'ok', text: '已开跑' }
  return { cls: 'info', text: '待跑' }
}

async function load() {
  loading.value = true
  loadErr.value = ''
  try {
    const res = await opsCatalog()
    catalog.items = res.items || []
    catalog.modules = res.modules || []
    catalog.groups = res.source_groups || []
    catalog.tools = res.tools || []
    buildCards()
    if (!tools.sel && catalog.tools.length) pickTool(catalog.tools[0])
  } catch (e) {
    // 目录拉不到时以前什么都不说，页面上只剩「0 项」，看着像功能没了。这里把原因说清。
    const status = e?.response?.status
    loadErr.value =
      status === 401
        ? '登录态已过期，重新登录后再点右上角「刷新目录」。'
        : `功能目录没拉到：${e?.message || '未知错误'}。点右上角「刷新目录」重试。`
  } finally {
    loading.value = false
  }
}

watch(
  () => [goal.target, goal.expand, goal.seedTask, cards.value],
  () => save(),
  { deep: true },
)

onMounted(() => {
  readMemory()
  load()
})
</script>

<template>
  <div class="stack">
    <PageHead
      title="功能自检"
      desc="全收集就是五段：主体收集 → 域名收集 → 空间测绘 → 主动探测 → 深度挖掘。一段一张卡，卡里勾阶段、选来源，跑起来当场看进度。"
    >
      <template #actions>
        <span class="tag mono">{{ cards.length }} 段 · {{ catalog.items.length }} 项</span>
        <button class="btn sm" :disabled="loading" @click="load">
          <Icon name="refresh" :size="13" />刷新目录
        </button>
      </template>
    </PageHead>

    <!-- 概览：几段、勾了多少阶段、这次跑出多少条、现在有没有在跑 -->
    <div class="ops-metrics">
      <div class="ops-metric" style="--tone: var(--cyan)">
        <div class="om-top"><span>流程段</span><Icon name="flow" :size="13" /></div>
        <b class="om-value mono">{{ cards.length }}</b>
        <span class="om-foot">主体 → 域名 → 测绘 → 探测 → 深挖</span>
      </div>
      <div class="ops-metric" style="--tone: var(--violet)">
        <div class="om-top"><span>已勾阶段</span><Icon name="list" :size="13" /></div>
        <b class="om-value mono">{{ stagePicked }}<i>/{{ stageTotal }}</i></b>
        <span class="om-foot">一键跑时按勾上的阶段走</span>
      </div>
      <div class="ops-metric" style="--tone: var(--ok-text)">
        <div class="om-top"><span>本页产出</span><Icon name="layers" :size="13" /></div>
        <b class="om-value mono">{{ num(outTotal) }}</b>
        <span class="om-foot">这次跑完落到任务里的资产条数</span>
      </div>
      <div class="ops-metric" style="--tone: var(--amber)">
        <div class="om-top"><span>正在跑</span><Icon name="play" :size="13" /></div>
        <b class="om-value mono">{{ runningN }}</b>
        <span class="om-foot">{{ runningN ? '卡里实时显示在查什么' : '现在没有在跑的段' }}</span>
      </div>
    </div>

    <div v-if="loadErr" class="ops-error">
      <Icon name="alert" :size="13" />
      <span class="flex-1">{{ loadErr }}</span>
      <button class="btn xs" :disabled="loading" @click="load">重试</button>
    </div>

    <!-- 五段流程条：点一段直接跳到那张卡 -->
    <div class="panel ops-flow">
      <div class="panel-head">
        <span><Icon name="route" :size="13" />五段流程</span>
        <span class="muted of-hint">点一段跳到下面对应的卡；数字是「已勾阶段 / 全部阶段」</span>
      </div>
      <div class="of-body">
        <button
          v-for="card in cards"
          :key="card.key"
          class="of-step"
          :class="`st-${stateOf(card).cls}`"
          :title="card.hint"
          @click="jumpTo(card)"
        >
          <span class="of-no mono">{{ CIRCLED[(card.no || 1) - 1] }}</span>
          <Icon :name="card.icon" :size="14" />
          <span class="of-label">{{ card.label }}</span>
          <span class="of-num mono">{{ onCount(card) }}<i>/{{ card.stages.length }}</i></span>
          <span class="of-state">{{ stateOf(card).text }}</span>
        </button>
      </div>
    </div>

    <!-- 目标：五段共用一次输入 -->
    <div class="panel goal">
      <div class="panel-head">
        <span><Icon name="target" :size="13" />目标<span class="tag info">五段共用</span></span>
        <span class="muted goal-hint">企业名 / 品牌名 / 域名都行，多个用换行或逗号分隔</span>
      </div>
      <div class="panel-body stack" style="gap: 10px">
        <textarea
          v-model="goal.target"
          class="textarea goal-input"
          rows="2"
          placeholder="小米科技有限责任公司（也可填品牌名、根域 example.com）"
        />

        <div class="row" style="gap: 16px; align-items: center; flex-wrap: wrap">
          <label class="opt" @click="goal.expand = !goal.expand">
            <span class="switch" :class="{ on: goal.expand }" />
            企业名先认主体、再补域名池
          </label>
          <button class="btn xs ghost" @click="goal.more = !goal.more">
            <Icon name="chevron" :size="11" />{{ goal.more ? '收起' : '从旧任务回填资产' }}
          </button>
        </div>
        <p class="goal-note">
          填企业名或品牌名就打开：先认主体和子公司，再从主体名、备案反查域名，后面四段才有东西可打；
          填的已经是域名清单就关掉，直接从域名收集开始。
        </p>
        <ul v-if="goal.expand" class="goal-steps">
          <li><b>1</b> 工商主源认主体：全名、别名、曾用名、分支机构</li>
          <li><b>2</b> 按控股比例收子公司，落进「子公司 / 控股企业 / 对外投资」分类</li>
          <li><b>3</b> 主体名去备案库反查，拿到登记在该主体名下的域名</li>
          <li><b>4</b> 域名词过证据闸，证明不了归属的记「待核验」，不落扫描</li>
        </ul>
        <p v-if="goal.expand" class="goal-note">
          认不出主体时任务里会写原因，不留空任务；后面才发现漏了子公司，用「重跑」再扩一次即可。
        </p>

        <div v-if="goal.more" class="field">
          <span class="field-label">回填来源任务 ID（可选）</span>
          <input
            v-model="goal.seedTask"
            class="input mono"
            placeholder="填了就从这个任务的历史资产回填域名 / IP；留空按本次输入"
          />
        </div>

        <div class="row" style="gap: 10px; align-items: center; flex-wrap: wrap">
          <button class="btn primary sm" :disabled="full.running" @click="runFull">
            <Icon name="play" :size="12" />{{
              full.running ? '正在跑…' : '一键跑完整流程（五段）'
            }}
          </button>
          <span class="muted goal-note flex-1">{{ fullSummary }}</span>
        </div>

        <div v-if="full.err" class="ops-error"><Icon name="alert" :size="13" />{{ full.err }}</div>

        <RunLive v-if="full.taskId" :task-id="full.taskId" :steps="full.steps" @done="onFullDone" />

        <div v-if="full.taskId" class="row" style="gap: 8px; align-items: center">
          <button class="btn xs" @click="exportTask(full.taskId, 'full')">
            <Icon name="download" :size="11" />导出本次数据（CSV）
          </button>
          <router-link class="btn xs" :to="`/tasks/${full.taskId}`">
            <Icon name="external" :size="11" />任务详情 · 全部资产
          </router-link>
          <span class="muted" style="font-size: 11px">导出的表按类型铺全字段，和资产库里的表一致</span>
        </div>
      </div>
    </div>

    <!-- 五段模块卡 -->
    <div
      v-for="card in cards"
      :key="card.key"
      :id="`mod-${card.key}`"
      class="panel mod"
      :class="`st-${stateOf(card).cls}`"
    >
      <div class="panel-head">
        <span class="mod-title">
          <span class="mod-no">{{ CIRCLED[(card.no || 1) - 1] }}</span>
          <Icon :name="card.icon" :size="13" />{{ card.label }}
          <span class="tag" :class="stateOf(card).cls">{{ stateOf(card).text }}</span>
        </span>
        <span class="muted mod-sub">{{ card.hint }}</span>
      </div>

      <div class="panel-body stack" style="gap: 10px">
        <!-- 阶段 -->
        <div class="mod-line">
          <span class="mod-key">阶段</span>
          <div class="chips">
            <button
              v-for="s in card.stages"
              :key="s"
              class="chip"
              :class="{ on: card.on[s] }"
              @click="card.on[s] = !card.on[s]"
            >
              <Icon v-if="card.on[s]" name="check" :size="10" />{{ card.labels[s] }}
            </button>
          </div>
        </div>

        <!-- 来源：主源 / 辅助，来自后端算好的 role -->
        <template v-for="g in card.groups" :key="g.param">
          <div class="mod-line">
            <span class="mod-key">{{ roleLabel(g, 'primary') }}</span>
            <div class="chips">
              <template v-if="priShown(card, g)">
                <button
                  v-for="o in primaries(g)"
                  :key="o.value"
                  class="chip src"
                  :class="{ on: isOn(card, g, o.value), off: o.ready === false }"
                  :title="o.ready === false ? '还没配 key，勾了也是空跑' : o.label"
                  @click="toggleSrc(card, g, o.value)"
                >
                  {{ o.short || o.label }}
                </button>
              </template>
              <button
                v-if="primaries(g).length > PRIMARY_FOLD"
                class="btn xs ghost"
                @click="card.priOpen[g.param] = !card.priOpen[g.param]"
              >
                <Icon name="chevron" :size="10" />{{
                  priShown(card, g) ? '收起主源' : `展开 ${primaries(g).length} 路`
                }}
              </button>
              <span v-if="!primaries(g).length" class="muted" style="font-size: 11px">无</span>
            </div>
          </div>
          <div class="mod-line">
            <span class="mod-key">{{ roleLabel(g, 'aux') }}</span>
            <div class="chips">
              <template v-if="auxShown(card, g)">
                <button
                  v-for="o in auxs(g)"
                  :key="o.value"
                  class="chip src"
                  :class="{ on: isOn(card, g, o.value), off: o.ready === false }"
                  :title="o.ready === false ? '还没配 key，勾了也是空跑' : o.label"
                  @click="toggleSrc(card, g, o.value)"
                >
                  {{ o.short || o.label }}
                </button>
              </template>
              <button
                v-if="auxs(g).length > AUX_FOLD"
                class="btn xs ghost"
                @click="card.auxOpen[g.param] = !card.auxOpen[g.param]"
              >
                <Icon name="chevron" :size="10" />{{
                  auxShown(card, g) ? '收起辅助源' : `展开 ${auxs(g).length} 路`
                }}
              </button>
              <span v-if="!auxs(g).length" class="muted" style="font-size: 11px">无</span>
              <span v-if="o_need_key(g)" class="muted src-flag">带 key 的才有数据</span>
            </div>
          </div>
          <div class="mod-line mod-src-foot">
            <span class="mod-key" />
            <div class="chips" style="align-items: center">
              <span class="muted src-note">{{ g.title }}：{{ srcState(card, g) }} · {{ g.note }}</span>
              <button class="btn xs ghost" @click="onlyPrimary(card, g)">
                <Icon name="filter" :size="10" />只留主源
              </button>
              <button v-if="g.empty_means_all" class="btn xs ghost" @click="allSrc(card, g)">
                <Icon name="layers" :size="10" />全部启用
              </button>
            </div>
          </div>
        </template>

        <!-- 参数与依赖 -->
        <div class="mod-line">
          <span class="mod-key">参数</span>
          <div class="chips" style="align-items: center">
            <button class="btn xs ghost" @click="card.openParams = !card.openParams">
              <Icon name="chevron" :size="10" />{{
                card.openParams ? '收起' : `本段参数（${card.params.length} 项）`
              }}
            </button>
            <label class="opt" @click="card.deps = !card.deps">
              <span class="switch" :class="{ on: card.deps }" />
              带上游依赖
            </label>
            <span class="muted src-note">上游就是前面几段；关着只跑本段，缺输入时会空转</span>
          </div>
        </div>
        <div v-if="card.openParams" class="mod-params">
          <ParamGrid :params="card.params" :model="card.opts" @reset="resetCard(card)" />
        </div>

        <div class="row" style="gap: 10px; align-items: center; flex-wrap: wrap">
          <button class="btn primary sm" :disabled="card.running" @click="runModule(card)">
            <Icon name="play" :size="12" />{{
              card.running ? '正在跑…' : `跑本段（${onCount(card)} 个阶段）`
            }}
          </button>
          <span class="muted src-note flex-1">
            建任务、产出资产入库；跑起来下面实时显示在查什么、查到多少条
          </span>
        </div>

        <div v-if="card.err" class="ops-error"><Icon name="alert" :size="13" />{{ card.err }}</div>

        <RunLive
          v-if="card.taskId"
          :task-id="card.taskId"
          :steps="card.steps"
          @done="onModuleDone(card, $event)"
        />
        <div v-if="card.taskId" class="row" style="gap: 8px; align-items: center">
          <button class="btn xs" @click="exportTask(card.taskId, card.key)">
            <Icon name="download" :size="11" />导出本段数据（CSV）
          </button>
          <router-link class="btn xs" :to="`/tasks/${card.taskId}`">
            <Icon name="external" :size="11" />任务详情
          </router-link>
        </div>

        <!-- 单跑一项：只发这一次请求，几秒出原始返回，不建任务、不落资产 -->
        <div v-if="card.directs.length" class="mod-line">
          <span class="mod-key">单跑一项</span>
          <div class="chips" style="align-items: center">
            <select
              class="select"
              style="width: 210px"
              :value="card.sel"
              @change="pickDirect(card, card.directs.find((d) => d.key === $event.target.value))"
            >
              <option v-for="it in card.directs" :key="it.key" :value="it.key">
                {{ it.label }}
              </option>
            </select>
            <button class="btn xs" :disabled="card.dRunning" @click="runDirect(card)">
              <Icon name="bolt" :size="11" />{{ card.dRunning ? '请求中…' : '执行这一项' }}
            </button>
            <button
              v-if="curDirect(card)?.params.length"
              class="btn xs ghost"
              @click="card.dParams = !card.dParams"
            >
              <Icon name="chevron" :size="10" />{{
                card.dParams ? '收起参数' : `参数（${curDirect(card).params.length} 项）`
              }}
            </button>
            <span class="muted src-note">从来源拉一次原始返回；不建任务、不落资产</span>
          </div>
        </div>
        <div v-if="curDirect(card)" class="mod-line mod-src-foot" style="margin-top: -4px">
          <span class="mod-key" />
          <span class="muted src-note">
            {{ curDirect(card).hint }}
            <template v-if="!needTarget(curDirect(card))">这一项不用填目标。</template>
          </span>
        </div>
        <div v-if="curDirect(card) && card.dParams" class="mod-params">
          <ParamGrid
            :params="curDirect(card).params"
            :model="card.dOpts"
            @reset="resetDirect(card)"
          />
        </div>
        <div v-if="card.dErr" class="ops-error">
          <Icon name="alert" :size="13" />{{ card.dErr }}
        </div>
        <OpsDirect v-if="card.dRes" :res="card.dRes" />
      </div>
    </div>

    <!-- 数据源与工具：不属于五段，但要能单独验 -->
    <div v-if="catalog.tools.length" class="panel">
      <div class="panel-head">
        <span><Icon name="terminal" :size="13" />数据源与工具</span>
        <span class="muted goal-hint">验一下哪路来源通、哪台外部工具装好了；不用填目标</span>
      </div>
      <div class="panel-body stack" style="gap: 10px">
        <div class="chips">
          <button
            v-for="it in catalog.tools"
            :key="it.key"
            class="chip"
            :class="{ on: tools.sel === it.key }"
            @click="pickTool(it)"
          >
            {{ it.label }}
          </button>
        </div>
        <template v-if="curTool">
          <p class="muted src-note" style="margin: 0">{{ curTool.hint }}</p>
          <ParamGrid :params="curTool.params" :model="tools.dOpts" />
          <div class="row" style="gap: 10px; align-items: center">
            <button class="btn sm" :disabled="tools.dRunning" @click="runTool">
              <Icon name="bolt" :size="11" />{{
                tools.dRunning ? '请求中…' : `单跑「${curTool.label}」`
              }}
            </button>
          </div>
          <div v-if="tools.dErr" class="ops-error"><Icon name="alert" :size="13" />{{ tools.dErr }}</div>
          <OpsDirect :res="tools.dRes" />
        </template>
      </div>
    </div>

    <div v-if="history.length" class="panel">
      <div class="panel-head">
        <span><Icon name="clock" :size="13" />本次自检记录</span>
        <button class="btn xs" @click="history = []"><Icon name="trash" :size="11" />清空</button>
      </div>
      <div class="table-wrap" style="max-height: 240px">
        <table class="table">
          <thead>
            <tr><th>时间</th><th>功能</th><th>结果</th><th>耗时</th></tr>
          </thead>
          <tbody>
            <tr v-for="(h, i) in history" :key="i">
              <td class="mono muted">{{ h.at }}</td>
              <td>{{ h.label }}</td>
              <td>
                <span class="tag" :class="h.ok ? 'ok' : 'err'">{{ h.ok ? '已发出' : '失败' }}</span>
                <span class="muted" style="margin-left: 6px">{{ h.note }}</span>
              </td>
              <td class="mono">{{ h.ms ? `${(h.ms / 1000).toFixed(1)}s` : '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script>
// 模板里用到的一个小判定：这一组来源是不是「带 key 才有数据」的那类
export default {
  methods: {
    o_need_key(g) {
      const opts = g?.options || []
      return opts.some((o) => o.need_key)
    },
  },
}
</script>

<style scoped>
/* ── 顶部概览：四张指标卡，和任务列表用同一套视觉语言 ── */
.ops-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 10px;
}
.ops-metric {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 11px 13px 10px 15px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface-2);
}
.ops-metric::before {
  content: '';
  position: absolute;
  left: 0;
  top: 11px;
  bottom: 11px;
  width: 2px;
  border-radius: 0 2px 2px 0;
  background: linear-gradient(180deg, var(--tone, var(--cyan)), transparent);
}
.om-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  font-size: 11.5px;
  color: var(--muted);
}
.om-top svg {
  color: var(--tone, var(--cyan));
  opacity: 0.9;
}
.om-value {
  font-size: 22px;
  font-weight: 600;
  line-height: 1.25;
  color: var(--text);
}
.om-value i {
  margin-left: 1px;
  font-size: 12px;
  font-style: normal;
  font-weight: 500;
  color: var(--muted);
}
.om-foot {
  font-size: 11px;
  line-height: 1.5;
  color: var(--muted-2);
}

/* ── 五段流程条：一步一格，点一下滚到那张卡 ── */
.of-hint {
  font-size: 11px;
}
.of-body {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 10px 13px 11px;
}
.of-step {
  --tone: var(--muted);
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 10px 5px 8px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface-2);
  color: var(--text-2);
  font-size: 12px;
  cursor: pointer;
  transition: border-color 0.15s, transform 0.15s;
}
.of-step:hover {
  border-color: var(--line-strong);
  transform: translateY(-1px);
}
.of-step svg {
  color: var(--tone);
}
.of-step.st-ok {
  --tone: var(--ok-text);
}
.of-step.st-warn {
  --tone: var(--amber);
}
.of-step.st-err {
  --tone: var(--red);
}
.of-step.st-info {
  --tone: var(--cyan);
}
.of-no {
  font-size: 11px;
  color: var(--muted);
}
.of-label {
  color: var(--text);
  font-weight: 500;
}
.of-num {
  font-size: 11.5px;
  color: var(--text-2);
}
.of-num i {
  font-style: normal;
  color: var(--muted-2);
}
.of-state {
  padding-left: 6px;
  border-left: 1px solid var(--line);
  font-size: 11px;
  color: var(--tone);
}

.goal-input {
  min-height: 60px;
}
.goal-hint {
  font-size: 11.5px;
}
.goal-note {
  margin: 0;
  font-size: 12.5px;
  line-height: 1.65;
  color: var(--text-2);
}
/* 扩线四步：宽屏两列，窄屏一列 */
.goal-steps {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  gap: 2px 18px;
  margin: 0;
  padding: 0;
  list-style: none;
  font-size: 12px;
  line-height: 1.7;
  color: var(--text-2);
}
.goal-steps b {
  display: inline-block;
  width: 14px;
  color: var(--cyan, #34e5c8);
  font-weight: 600;
}

/* 模块卡：左边一列固定的键名，右边一行一行摆勾选项，扫一眼就知道这段管什么 */
.mod {
  position: relative;
  scroll-margin-top: 66px;
}
/* 卡左侧一条状态色，跟顶部流程条同一套颜色，滚下来还能认出是哪段 */
.mod::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 2px;
  background: var(--tone, var(--line-strong));
  opacity: 0.75;
}
.mod.st-ok {
  --tone: var(--ok-text);
}
.mod.st-warn {
  --tone: var(--amber);
}
.mod.st-err {
  --tone: var(--red);
}
.mod.st-info {
  --tone: var(--cyan);
}
.mod-title {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 13px;
  color: var(--text);
}
.mod-no {
  font-size: 13px;
  color: var(--cyan-ink);
}
.mod-sub {
  font-size: 11.5px;
}
.mod-line {
  display: flex;
  align-items: flex-start;
  gap: 9px;
  min-width: 0;
}
.mod-key {
  flex: 0 0 62px;
  font-size: 12px;
  line-height: 23px;
  color: var(--muted);
  text-align: right;
  white-space: nowrap;
}
.mod-src-foot {
  margin-top: -4px;
}
.mod-params {
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: rgba(255, 255, 255, 0.02);
}
.src-note {
  font-size: 11.5px;
  line-height: 1.6;
}
.src-flag {
  margin-left: 4px;
}
.singles {
  border-top: 1px dashed var(--line);
  padding-top: 8px;
}
.opt {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 12.5px;
  color: var(--text-2);
  cursor: pointer;
}

.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 10px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: rgba(120, 200, 220, 0.04);
  color: var(--text-2);
  font-size: 12px;
  line-height: 1.8;
  cursor: pointer;
}
.chip:hover {
  border-color: rgba(52, 229, 200, 0.4);
}
.chip.on {
  border-color: rgba(52, 229, 200, 0.5);
  background: rgba(52, 229, 200, 0.14);
  color: var(--cyan-ink);
}
/* 没配 key 的那几台：勾得上但会是空的，标灰提醒一下，不挡着勾 */
.chip.off {
  opacity: 0.55;
  border-style: dashed;
}

.ops-error {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--red-ink);
  background: rgba(220, 70, 70, 0.1);
  border: 1px solid rgba(220, 70, 70, 0.3);
  border-radius: 6px;
  padding: 7px 10px;
}

@media (max-width: 860px) {
  .of-body {
    gap: 5px;
  }
  .of-step {
    font-size: 11.5px;
  }
  .of-state {
    display: none;
  }
}
</style>
