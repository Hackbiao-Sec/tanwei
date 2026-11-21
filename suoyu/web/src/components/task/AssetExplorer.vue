<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import Icon from '@/components/Icon.vue'
import { taskAssets } from '@/api/endpoints'

const props = defineProps({
  taskId: { type: String, required: true },
  summary: { type: Object, default: null },
  kindLabels: { type: Object, default: () => ({}) },
  active: { type: Boolean, default: false },
})

const PAGE = 2000

const rows = ref([])
const total = ref(0)
const loading = ref(false)
const loadingMore = ref(false)
const err = ref('')

// 服务端筛选：面 / 类型 / 关键字 / 只看新增。前端只做交集以外的维度，
// 这样 total 始终是全库口径，不会把「全库 3 条 APP」显示成 0 条。
const surface = ref('')
const kind = ref('')
const keyword = ref('')
const onlyNew = ref(false)

// 前端筛选：控股比例 / 来源 / 端口 / 状态码 / 自定义正则
const fRatio = ref('')
const fSource = ref('')
const fPort = ref('')
const fStatus = ref('')

const rxOn = ref(false)
const rxText = ref('')
const rxIgnore = ref(true)

const sort = ref('default')
const openId = ref(null)

let kwTimer = null

const SURFACE_LABEL = {
  web: 'Web', applet: '小程序', mp: '公众号', app: 'APP',
  netblock: '网段', icp: '备案', meta: '主体与邮箱',
}
const SURFACE_ORDER = ['web', 'applet', 'mp', 'app', 'netblock', 'icp', 'meta']
const MP_KINDS = ['wxmp']
// 与后端 db._META_KINDS 对齐：漏一个类型就会被算成 Web，点了「主体与邮箱」反而看不到
const META_KINDS = [
  'enterprise', 'equity', 'mailinfo', 'email', 'branch', 'weibo',
  'holds', 'invest', 'partner', 'copyright', 'mobileapp', 'wechatoa', 'job', 'supplier',
]
const SURFACE_DUP_KINDS = ['icp']

const RATIO_BUCKETS = [
  { key: '100', label: '全资 ≥99%' },
  { key: '67', label: '绝对控股 ≥67%' },
  { key: '51', label: '相对控股 ≥51%' },
  { key: 'lt51', label: '参股 <51%' },
  { key: 'none', label: '无持股比例' },
]
const STATUS_LABEL = {
  '2xx': '正常 2xx', '3xx': '跳转 3xx', alive: '存活 / 解析', auth: '401/403 需认证',
  '4xx': '4xx 拒绝', '5xx': '5xx 异常', space: '测绘收录', none: '未探测', other: '其他',
}

const RATIO_KEYS = ['ratio', 'percent', 'invest_ratio', 'hold_ratio', 'share_ratio', 'acc', 'acc_ratio']

function ratioOf(a) {
  const x = a?.extra || {}
  for (const k of RATIO_KEYS) {
    const v = Number(x[k])
    if (Number.isFinite(v) && v > 0)
      return v <= 1 ? Number((v * 100).toFixed(2)) : v
  }
  return null
}
function ratioBucket(r) {
  if (r == null)
    return 'none'
  if (r >= 99.99)
    return '100'
  if (r >= 67)
    return '67'
  if (r >= 51)
    return '51'
  return 'lt51'
}
// 存活分档：有状态码按码分，没有码的域名/端口行看后端给的 alive
function statusKey(a) {
  const n = Number(a && a.status_code)
  if (!n) {
    const alive = String((a && a.alive) || '')
    if (alive === 'alive' || alive === 'open' || alive === 'dns')
      return 'alive'
    if (alive === 'space')
      return 'space'
    return 'none'
  }
  if (n >= 200 && n < 300)
    return '2xx'
  if (n >= 300 && n < 400)
    return '3xx'
  if (n === 401 || n === 403)
    return 'auth'
  if (n >= 500)
    return '5xx'
  if (n >= 400)
    return '4xx'
  return 'other'
}
function splitSources(s) {
  return String(s || '').split(',').map((x) => x.trim()).filter(Boolean)
}
// 来源列只留前两个，多的折成 +N，完整值放 title
function srcText(s) {
  const list = splitSources(s)
  if (!list.length)
    return ''
  return list.length > 2 ? `${list.slice(0, 2).join(' · ')} +${list.length - 2}` : list.join(' · ')
}
function haystack(a) {
  const extra = a.extra ? JSON.stringify(a.extra) : ''
  return [
    a.url, a.host, a.ip, a.title, a.fingerprint, a.sources, a.root_domain, extra,
  ].filter(Boolean).join('\n')
}
function kindLabel(k) {
  return props.kindLabels?.[k] || k || '未分类'
}
function fmtTime(ts) {
  if (!ts)
    return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}
function isUrl(u) {
  return /^https?:\/\//i.test(String(u || ''))
}
// 主体侧资产的地址是合成标识（icp:域名 / holds:母体:子公司），不能当链接点
function identText(a) {
  const raw = String(a.url || '')
  const i = raw.indexOf(':')
  if (i <= 0)
    return raw
  const rest = raw.slice(i + 1)
  const j = rest.lastIndexOf(':')
  return j > 0 ? rest.slice(j + 1) : rest
}
function titleText(a) {
  const t = String(a.title || '').trim()
  if (!t)
    return ''
  const n = identText(a)
  if (n && t.startsWith(n))
    return t.slice(n.length).replace(/^[\s|·\-:]+/, '').trim()
  return t
}
// 标题下面补一行关系/占比：列太挤，挂在标题下面才看得出「怎么算进来的」
function rowHint(a) {
  const x = a.extra || {}
  const parts = []
  if (a.kind === 'holds') {
    if (x.level)
      parts.push(`第 ${x.level} 级`)
    const r = Number(x.ratio)
    if (Number.isFinite(r) && r > 0)
      parts.push(`累计持股 ${r}%`)
    if (x.capital)
      parts.push(`注册资本 ${x.capital}`)
  } else if (a.kind === 'invest' || a.kind === 'partner') {
    const r = Number(x.ratio)
    if (Number.isFinite(r) && r > 0)
      parts.push(`占比 ${r}%`)
    if (x.type)
      parts.push(String(x.type))
    if (x.capital)
      parts.push(`注册资本 ${x.capital}`)
  } else if (a.kind === 'copyright') {
    if (x.reg_num)
      parts.push(`登记号 ${x.reg_num}`)
    if (x.category)
      parts.push(String(x.category))
  } else if (a.kind === 'branch') {
    if (x.legal)
      parts.push(`负责人 ${x.legal}`)
    if (x.status)
      parts.push(String(x.status))
  } else if (a.kind === 'icp') {
    if (x.icp)
      parts.push(`备案号 ${x.icp}`)
    if (x.domain)
      parts.push(String(x.domain))
    if (x.unit)
      parts.push(`主办 ${x.unit}`)
    if (x.site_name)
      parts.push(String(x.site_name))
  } else if (a.kind === 'mobileapp') {
    if (x.bundle)
      parts.push(`包名 ${x.bundle}`)
    if (x.updated)
      parts.push(`更新 ${x.updated}`)
  } else if (a.kind === 'wechatoa') {
    if (x.account)
      parts.push(`微信号 ${x.account}`)
  } else if (a.kind === 'weibo') {
    if (x.link)
      parts.push(String(x.link))
  } else if (a.kind === 'job') {
    if (x.published)
      parts.push(`发布 ${x.published}`)
    if (x.education)
      parts.push(String(x.education))
  } else if (a.kind === 'supplier') {
    if (x.parent)
      parts.push(`归属 ${x.parent}`)
  } else if (a.kind === 'equity') {
    const chain = Array.isArray(x.chain) ? x.chain.length : 0
    const icps = Array.isArray(x.icps) ? x.icps.length : 0
    const cprs = Array.isArray(x.copyrights) ? x.copyrights.length : 0
    if (chain)
      parts.push(`穿透到 ${chain} 家`)
    if (icps)
      parts.push(`备案 ${icps}`)
    if (cprs)
      parts.push(`软著 ${cprs}`)
  } else if (a.kind === 'enterprise') {
    const doms = Array.isArray(x.domains) ? x.domains.length : 0
    const pend = Array.isArray(x.domains_pending) ? x.domains_pending.length : 0
    if (doms)
      parts.push(`确认域 ${doms}`)
    if (pend)
      parts.push(`待核验 ${pend}：${x.domains_pending.slice(0, 3).join('、')}`)
  } else if (x.relation && typeof x.relation === 'string') {
    parts.push(x.relation)
  }
  return parts.join(' · ')
}
function surfaceOf(k) {
  if (k === 'applet')
    return 'applet'
  if (MP_KINDS.includes(k))
    return 'mp'
  if (k === 'mobile')
    return 'app'
  if (META_KINDS.includes(k))
    return 'meta'
  if (k === 'netblock')
    return 'netblock'
  if (k === 'icp')
    return 'icp'
  return 'web'
}

const rx = computed(() => {
  const t = rxText.value.trim()
  if (!rxOn.value || !t)
    return { re: null, err: '' }
  try {
    return { re: new RegExp(t, rxIgnore.value ? 'i' : ''), err: '' }
  } catch (e) {
    return { re: null, err: `正则写错了：${e.message}` }
  }
})

const docs = computed(() =>
  rows.value.map((a) => {
    const ratio = ratioOf(a)
    return { a, ratio, bucket: ratioBucket(ratio), srcs: splitSources(a.sources), stat: statusKey(a), hay: haystack(a) }
  }),
)

const searched = computed(() => {
  const re = rx.value.re
  if (!re)
    return docs.value
  return docs.value.filter((d) => re.test(d.hay))
})

function pass(d, skip) {
  if (skip !== 'ratio' && fRatio.value && d.bucket !== fRatio.value)
    return false
  if (skip !== 'source' && fSource.value && !d.srcs.includes(fSource.value))
    return false
  if (skip !== 'port' && fPort.value && String(d.a.port || '') !== fPort.value)
    return false
  if (skip !== 'status' && fStatus.value && d.stat !== fStatus.value)
    return false
  if (onlyNew.value && !d.a.is_new)
    return false
  return true
}

const filtered = computed(() => searched.value.filter((d) => pass(d, '')))

const sorted = computed(() => {
  const list = [...filtered.value]
  if (sort.value === 'ratio')
    return list.sort((x, y) => (y.ratio ?? -1) - (x.ratio ?? -1))
  if (sort.value === 'status')
    return list.sort((x, y) => (Number(x.a.status_code) || 999) - (Number(y.a.status_code) || 999))
  if (sort.value === 'title')
    return list.sort((x, y) => String(x.a.url || '').localeCompare(String(y.a.url || '')))
  if (sort.value === 'kind')
    return list.sort((x, y) => String(x.a.kind || '').localeCompare(String(y.a.kind || '')))
  return list
})

// 按类型分组：先看清这一趟收了几类、各多少条，再往下看明细
const view = computed(() => {
  const list = sorted.value
  if (sort.value !== 'kind')
    return list.map((d) => ({ t: 'r', d }))
  const map = new Map()
  for (const d of list) {
    if (!map.has(d.a.kind))
      map.set(d.a.kind, [])
    map.get(d.a.kind).push(d)
  }
  const out = []
  for (const [k, arr] of [...map.entries()].sort((x, y) => y[1].length - x[1].length)) {
    out.push({ t: 'g', k, n: arr.length })
    for (const d of arr)
      out.push({ t: 'r', d })
  }
  return out
})

function countBy(list, fn) {
  const m = new Map()
  for (const d of list) {
    const k = fn(d)
    if (k === '' || k == null)
      continue
    m.set(k, (m.get(k) || 0) + 1)
  }
  return m
}

const surfaces = computed(() => {
  const s = props.summary?.surfaces || {}
  const sum = SURFACE_ORDER.reduce((n, k) => n + (s[k] || 0), 0)
  return [
    { key: '', label: '全部', n: sum || props.summary?.total || 0 },
    ...SURFACE_ORDER.filter((k) => s[k]).map((k) => ({ key: k, label: SURFACE_LABEL[k] || k, n: s[k] })),
  ]
})

const kindChips = computed(() => {
  const list = (props.summary?.by_kind || [])
    .filter((r) => !SURFACE_DUP_KINDS.includes(r.value))
    .filter((r) => !surface.value || surfaceOf(r.value) === surface.value)
  const sum = list.reduce((n, r) => n + (r.count || 0), 0)
  return [
    { key: '', label: '全部类型', n: sum },
    ...list.map((r) => ({ key: r.value, label: kindLabel(r.value), n: r.count })),
  ]
})

const ratioChips = computed(() => {
  const base = searched.value.filter((d) => pass(d, 'ratio'))
  const m = countBy(base, (d) => d.bucket)
  return RATIO_BUCKETS.filter((b) => m.get(b.key)).map((b) => ({ ...b, n: m.get(b.key) }))
})

const sourceChips = computed(() => {
  const base = searched.value.filter((d) => pass(d, 'source'))
  const m = new Map()
  for (const d of base)
    for (const s of d.srcs)
      m.set(s, (m.get(s) || 0) + 1)
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 14)
    .map(([k, n]) => ({ key: k, label: k, n }))
})

const portChips = computed(() => {
  const base = searched.value.filter((d) => pass(d, 'port'))
  const m = new Map()
  for (const d of base) {
    if (!d.a.port)
      continue
    m.set(String(d.a.port), (m.get(String(d.a.port)) || 0) + 1)
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([k, n]) => ({ key: k, label: `:${k}`, n }))
})

const statusChips = computed(() => {
  const base = searched.value.filter((d) => pass(d, 'status'))
  const m = countBy(base, (d) => d.stat)
  return ['2xx', '3xx', 'alive', 'auth', '4xx', '5xx', 'space', 'none'].filter((k) => m.get(k))
    .map((k) => ({ key: k, label: STATUS_LABEL[k], n: m.get(k) }))
})

const KIND_COLORS = ['var(--c1)', 'var(--c2)', 'var(--c3)', 'var(--c4)', 'var(--c5)', 'var(--c6)', 'var(--c7)', 'var(--c8)']
const comp = computed(() => {
  const m = new Map()
  for (const d of filtered.value)
    m.set(d.a.kind, (m.get(d.a.kind) || 0) + 1)
  const arr = [...m.entries()].sort((a, b) => b[1] - a[1])
  const sum = arr.reduce((n, [, v]) => n + v, 0) || 1
  const top = arr.slice(0, 7)
  const rest = arr.slice(7).reduce((n, [, v]) => n + v, 0)
  if (rest)
    top.push(['__other', rest])
  return top.map(([k, n], i) => ({
    key: k, label: k === '__other' ? '其他' : kindLabel(k), n,
    pct: (n / sum) * 100, color: KIND_COLORS[i % KIND_COLORS.length],
  }))
})

const RX_PRESETS = [
  { label: '仅 http(s) 地址', re: '^https?://' },
  { label: '政府 / 教育域', re: '\\.(gov|edu)\\.cn$' },
  { label: 'IP 字面量', re: '\\b\\d{1,3}(\\.\\d{1,3}){3}\\b' },
  { label: '后台 / 文档面', re: 'nacos|swagger|actuator|druid|jenkins' },
  { label: '工商来源', re: 'aiqicha|tianyancha|qichacha|qcc' },
]

const activeCount = computed(() => [
  surface.value, kind.value, keyword.value.trim(), fRatio.value, fSource.value, fPort.value,
  fStatus.value, rxOn.value && rxText.value.trim(), onlyNew.value,
].filter(Boolean).length)

const shownCount = computed(() => filtered.value.length)

function clearAll() {
  surface.value = ''
  kind.value = ''
  keyword.value = ''
  fRatio.value = ''
  fSource.value = ''
  fPort.value = ''
  fStatus.value = ''
  rxText.value = ''
  onlyNew.value = false
  reload()
}

function pickSurface(key) {
  surface.value = surface.value === key ? '' : key
  if (kind.value && surface.value && surfaceOf(kind.value) !== surface.value)
    kind.value = ''
  reload()
}
function pickKind(key) {
  kind.value = kind.value === key ? '' : key
  if (kind.value && surface.value && surfaceOf(kind.value) !== surface.value)
    surface.value = surfaceOf(kind.value)
  reload()
}
async function load(append = false) {
  if (append)
    loadingMore.value = true
  else
    loading.value = true
  try {
    const res = await taskAssets(props.taskId, {
      limit: PAGE,
      offset: append ? rows.value.length : 0,
      surface: surface.value || undefined,
      kind: kind.value || undefined,
      keyword: keyword.value.trim() || undefined,
    })
    const items = res.items || []
    if (append) {
      const seen = new Set(rows.value.map((a) => a.id))
      rows.value = rows.value.concat(items.filter((a) => !seen.has(a.id)))
    } else {
      rows.value = items
      openId.value = null
    }
    total.value = res.total || rows.value.length
    err.value = ''
  } catch {
    err.value = '资产列表没拉到，点「刷新」再试'
  } finally {
    loading.value = false
    loadingMore.value = false
  }
}

function reload(append = false) {
  return load(append)
}

function onKeyword() {
  clearTimeout(kwTimer)
  kwTimer = setTimeout(() => load(false), 320)
}

function focusKind(k) {
  kind.value = k || ''
  surface.value = ''
  reload()
}
function focusSurface(s) {
  surface.value = s || ''
  reload()
}

function exportCsv() {
  const head = ['类型', '地址', '标题', '状态码', '存活', 'IP', '端口', '指纹', '来源', '持股比例', '最近']
  const q = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`
  const lines = [head.map(q).join(',')]
  for (const d of filtered.value) {
    const a = d.a
    lines.push([
      kindLabel(a.kind), a.url, titleText(a) || a.title, a.status_code || '', a.alive_text || '',
      a.ip || '', a.port || '', a.fingerprint || '', a.sources || '', d.ratio == null ? '' : d.ratio,
      fmtTime(a.last_seen),
    ].map(q).join(','))
  }
  const blob = new Blob([`\ufeff${lines.join('\r\n')}`], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const el = document.createElement('a')
  el.href = url
  el.download = `资产_${props.taskId}_${new Date().toISOString().slice(0, 10)}.csv`
  el.style.display = 'none'
  document.body.appendChild(el)
  el.click()
  el.remove()
  // 立刻回收会让部分浏览器把还没写完的下载掐掉，等两秒再释放
  setTimeout(() => URL.revokeObjectURL(url), 2000)
}

function detailPairs(a) {
  const out = []
  if (a.host)
    out.push(['主机', a.host])
  if (a.root_domain)
    out.push(['根域', a.root_domain])
  if (a.title)
    out.push(['标题', a.title])
  if (a.sources)
    out.push(['来源', a.sources])
  if (a.last_seen)
    out.push(['最近', fmtTime(a.last_seen)])
  if (a.cdn)
    out.push(['CDN', '是'])
  return out
}

watch(() => props.taskId, () => {
  rows.value = []
  total.value = 0
  load()
})
watch(() => props.active, (v) => {
  if (v && !rows.value.length && !loading.value)
    load()
})

load()

onBeforeUnmount(() => clearTimeout(kwTimer))

defineExpose({ reload, focusKind, focusSurface })
</script>

<template>
  <div class="ae">
    <div class="ae-bar">
      <label class="ae-search">
        <Icon name="search" :size="13" />
        <input
          v-model="keyword"
          class="input mono"
          placeholder="搜域名 / IP / 标题 / 指纹 / 备案号 / 公司名 / 附加字段"
          @input="onKeyword"
          @keyup.enter="load(false)"
        />
        <button v-if="keyword" class="btn xs ghost" title="清空关键词" @click="keyword = ''; onKeyword()">
          <Icon name="close" :size="11" />
        </button>
      </label>
      <button class="btn sm" :class="{ primary: rxOn }" @click="rxOn = !rxOn">
        <Icon name="filter" :size="12" />正则
      </button>
      <select v-model="sort" class="select sort-sel">
        <option value="default">默认排序</option>
        <option value="kind">按类型分组</option>
        <option value="ratio">持股比例降序</option>
        <option value="status">状态码升序</option>
        <option value="title">按地址字典序</option>
      </select>
      <span class="grow" />
      <button class="btn sm" :class="{ primary: onlyNew }" @click="onlyNew = !onlyNew">
        <Icon name="spark" :size="12" />只看新增
      </button>
      <button class="btn sm" @click="load(false)">
        <Icon name="refresh" :size="12" />刷新
      </button>
      <button class="btn sm primary" @click="exportCsv">
        <Icon name="download" :size="12" />导出筛选结果
      </button>
    </div>

    <div v-if="rxOn" class="rx-row">
      <span class="rx-tag mono">/</span>
      <input v-model="rxText" class="input mono rx-input" placeholder="自定义正则，例如 \.gov\.cn$ 或 ^https?://api\." />
      <span class="rx-tag mono">/</span>
      <label class="rx-case">
        <input v-model="rxIgnore" type="checkbox" />忽略大小写
      </label>
      <span class="rx-hint">匹配地址 / 标题 / IP / 指纹 / 来源 / 附加字段；<code>^</code> 锚在整串开头，地址以 <code>https://</code> 起</span>
      <span v-if="rx.err" class="rx-err">{{ rx.err }}</span>
    </div>

    <div v-if="rxOn" class="rx-presets">
      <span class="facet-label">常用</span>
      <div class="facet-chips">
        <button
          v-for="p in RX_PRESETS" :key="'rx-' + p.label" class="fchip mono"
          :class="{ on: rxText === p.re }" @click="rxText = rxText === p.re ? '' : p.re"
        >{{ p.label }}</button>
      </div>
    </div>

    <div v-if="surfaces.length" class="facet">
      <span class="facet-label">采集面</span>
      <div class="facet-chips">
        <button
          v-for="s in surfaces" :key="'sf-' + s.key" class="fchip"
          :class="{ on: surface === s.key }" @click="pickSurface(s.key)"
        >{{ s.label }}<b>{{ s.n }}</b></button>
      </div>
    </div>

    <div v-if="kindChips.length > 1" class="facet">
      <span class="facet-label">资产类型</span>
      <div class="facet-chips">
        <button
          v-for="k in kindChips" :key="'kd-' + k.key" class="fchip"
          :class="{ on: kind === k.key }" @click="pickKind(k.key)"
        >{{ k.label }}<b>{{ k.n }}</b></button>
      </div>
    </div>

    <div v-if="ratioChips.length" class="facet">
      <span class="facet-label">控股比例</span>
      <div class="facet-chips">
        <button
          v-for="b in ratioChips" :key="'rt-' + b.key" class="fchip"
          :class="{ on: fRatio === b.key }" @click="fRatio = fRatio === b.key ? '' : b.key"
        >{{ b.label }}<b>{{ b.n }}</b></button>
      </div>
      <span class="facet-note">比例取自工商穿透的持股字段，0.87 这类小数按 87% 计</span>
    </div>

    <div v-if="sourceChips.length" class="facet">
      <span class="facet-label">数据来源</span>
      <div class="facet-chips">
        <button
          v-for="s in sourceChips" :key="'sc-' + s.key" class="fchip mono"
          :class="{ on: fSource === s.key }" @click="fSource = fSource === s.key ? '' : s.key"
        >{{ s.label }}<b>{{ s.n }}</b></button>
      </div>
    </div>

    <div v-if="portChips.length > 1 || statusChips.length > 1" class="facet">
      <span class="facet-label">端口与状态</span>
      <div class="facet-chips">
        <button
          v-for="p in portChips" :key="'pt-' + p.key" class="fchip mono"
          :class="{ on: fPort === p.key }" @click="fPort = fPort === p.key ? '' : p.key"
        >{{ p.label }}<b>{{ p.n }}</b></button>
        <span v-if="portChips.length && statusChips.length" class="facet-sep" />
        <button
          v-for="s in statusChips" :key="'st-' + s.key" class="fchip"
          :class="{ on: fStatus === s.key }" @click="fStatus = fStatus === s.key ? '' : s.key"
        >{{ s.label }}<b>{{ s.n }}</b></button>
      </div>
    </div>

    <div v-if="comp.length" class="comp-wrap">
      <div class="comp-bar">
        <span
          v-for="c in comp" :key="'cb-' + c.key" class="comp-seg"
          :style="{ width: Math.max(c.pct, 0.8) + '%', background: c.color }" :title="`${c.label} ${c.n}`"
        />
      </div>
      <div class="comp-legend">
        <button
          v-for="c in comp" :key="'cl-' + c.key" class="comp-item"
          :disabled="c.key === '__other'" @click="focusKind(c.key)"
        >
          <i :style="{ background: c.color }" />{{ c.label }}
          <b class="mono">{{ c.n }}</b>
        </button>
      </div>
    </div>

    <div class="ae-meta">
      <span>
        共 <b class="mono">{{ total }}</b> 条 · 已载入 <b class="mono">{{ rows.length }}</b> · 当前视图
        <b class="mono">{{ shownCount }}</b> 条
      </span>
      <span v-if="activeCount" class="muted">· 生效筛选 {{ activeCount }} 项</span>
      <button v-if="activeCount" class="btn xs" @click="clearAll">
        <Icon name="close" :size="11" />清除筛选
      </button>
      <span v-if="err" class="ae-err">{{ err }}</span>
      <span class="grow" />
      <span v-if="loading" class="muted">载入中…</span>
      <button v-if="rows.length < total" class="btn xs" :disabled="loadingMore" @click="load(true)">
        <Icon name="plus" :size="11" />再载入 {{ Math.min(PAGE, total - rows.length) }} 条
      </button>
    </div>

    <div class="ae-table-wrap">
      <table class="table ae-table">
        <colgroup>
          <col class="c-url" />
          <col class="c-title" />
          <col class="c-kind" />
          <col class="c-status" />
          <col class="c-ip" />
          <col class="c-port" />
          <col class="c-src" />
          <col class="c-time" />
        </colgroup>
        <thead>
          <tr>
            <th>地址 / 名称</th>
            <th>标题与关系</th>
            <th>类型</th>
            <th>状态</th>
            <th>IP</th>
            <th>端口</th>
            <th>来源</th>
            <th>最近</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="e in view" :key="e.t === 'g' ? 'g-' + e.k : 'r-' + e.d.a.id">
            <tr v-if="e.t === 'g'" class="group-row">
              <td colspan="8">
                <span class="tag">{{ kindLabel(e.k) }}</span>
                <span class="muted">共 {{ e.n }} 条</span>
              </td>
            </tr>
            <template v-else>
              <tr class="ae-row" :class="{ open: openId === e.d.a.id }" @click="openId = openId === e.d.a.id ? null : e.d.a.id">
                <td class="mono cell-url" :title="e.d.a.url">
                  <a v-if="isUrl(e.d.a.url)" :href="e.d.a.url" target="_blank" rel="noopener" @click.stop>{{ e.d.a.url }}</a>
                  <span v-else>{{ identText(e.d.a) }}</span>
                  <span v-if="e.d.a.is_new" class="tag warn new-tag">NEW</span>
                </td>
                <td class="ellipsis" :title="e.d.a.title || ''">
                  <span v-if="titleText(e.d.a)">{{ titleText(e.d.a) }}</span>
                  <span v-if="rowHint(e.d.a)" class="hint-line" :class="{ weak: !titleText(e.d.a) }">{{ rowHint(e.d.a) }}</span>
                </td>
                <td class="ellipsis"><span class="tag">{{ kindLabel(e.d.a.kind) }}</span></td>
                <td class="mono">
                  <span :class="'st-' + e.d.stat">{{ e.d.a.alive_text || e.d.a.status_code || '—' }}</span>
                </td>
                <td class="mono ellipsis" :title="e.d.a.ip || ''">{{ e.d.a.ip || '' }}</td>
                <td class="mono">{{ e.d.a.port || '' }}</td>
                <td class="muted ellipsis" :title="e.d.a.sources">{{ srcText(e.d.a.sources) }}</td>
                <td class="mono muted nowrap">{{ fmtTime(e.d.a.last_seen) }}</td>
              </tr>
              <tr v-if="openId === e.d.a.id" class="det-row">
                <td colspan="8">
                  <div class="det-grid">
                    <div v-for="p in detailPairs(e.d.a)" :key="p[0]" class="det-item">
                      <span class="det-k">{{ p[0] }}</span>
                      <span class="det-v mono">{{ p[1] }}</span>
                    </div>
                    <div class="det-item">
                      <span class="det-k">持股</span>
                      <span class="det-v mono">{{ e.d.ratio == null ? '—' : e.d.ratio + '%' }}</span>
                    </div>
                  </div>
                  <pre v-if="e.d.a.extra && Object.keys(e.d.a.extra).length" class="det-extra mono">{{ JSON.stringify(e.d.a.extra, null, 2) }}</pre>
                </td>
              </tr>
            </template>
          </template>
          <tr v-if="!view.length">
            <td colspan="8">
              <div class="empty">
                <Icon name="layers" :size="22" />
                <span>{{ loading ? '正在载入资产…' : (activeCount ? '当前筛选下没有资产，放宽一个维度再看' : '这个任务还没有入库资产') }}</span>
                <button v-if="activeCount" class="btn xs" @click="clearAll">清除筛选</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.ae {
  --c1: var(--cyan);
  --c2: #4aa8ff;
  --c3: #9d8cff;
  --c4: var(--amber);
  --c5: #46d68a;
  --c6: var(--red);
  --c7: #ff8f6b;
  --c8: #8fa6b8;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
:global(html[data-theme="light"]) .ae {
  --c2: #2b7fd4;
  --c3: #6b5bd6;
  --c5: #1f8f5c;
  --c7: #c25a35;
  --c8: #6b8391;
}
.ae-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.ae-search {
  display: flex;
  align-items: center;
  gap: 7px;
  flex: 1 1 320px;
  min-width: 240px;
  height: 30px;
  padding: 0 8px 0 10px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface-2);
  color: var(--muted);
}
.ae-search:focus-within {
  border-color: rgba(52, 229, 200, 0.5);
}
.ae-search .input {
  flex: 1;
  min-width: 0;
  height: 26px;
  padding: 0;
  border: 0;
  background: transparent;
  font-size: 11.5px;
}
.ae-search .input:focus {
  box-shadow: none;
  border: 0;
}
.grow { flex: 1; }
.sort-sel { height: 28px; width: auto; font-size: 11.5px; }
.rx-row {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  padding: 7px 9px;
  border: 1px dashed var(--line-strong);
  border-radius: 8px;
  background: rgba(52, 229, 200, 0.04);
}
.rx-tag { color: var(--cyan); font-size: 13px; }
.rx-input { flex: 1 1 260px; height: 26px; font-size: 11.5px; }
.rx-case { display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--text-2); }
.rx-hint { font-size: 10.5px; color: var(--muted); }
.rx-hint code {
  padding: 0 3px;
  border-radius: 3px;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--cyan-ink);
  background: rgba(52, 229, 200, 0.1);
}
.rx-err { font-size: 11px; color: var(--red); }
.rx-presets {
  display: flex;
  align-items: flex-start;
  gap: 8px;
}
.rx-presets .facet-chips { flex: 1 1 auto; }
.facet {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  min-width: 0;
}
.facet-label {
  flex: 0 0 60px;
  padding-top: 6px;
  font-size: 11px;
  color: var(--muted);
  letter-spacing: 0.04em;
  white-space: nowrap;
}
.facet-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  min-width: 0;
}
.facet-note { align-self: center; font-size: 10.5px; color: var(--muted-2); }
.facet-sep { width: 1px; height: 18px; align-self: center; background: var(--line); margin: 0 4px; }
.fchip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 24px;
  padding: 0 9px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: transparent;
  font-family: inherit;
  font-size: 11.5px;
  color: var(--text-2);
  white-space: nowrap;
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s, color 0.15s;
}
.fchip b {
  font-family: var(--mono);
  font-size: 10.5px;
  font-weight: 500;
  color: var(--muted);
}
.fchip:hover { border-color: var(--line-strong); color: var(--text); }
.fchip.on {
  border-color: rgba(52, 229, 200, 0.55);
  background: rgba(52, 229, 200, 0.13);
  color: var(--cyan-ink);
}
.fchip.on b { color: var(--cyan-ink); }
.comp-wrap {
  display: flex;
  flex-direction: column;
  gap: 7px;
  padding: 9px 10px;
  border: 1px solid var(--line);
  border-radius: 9px;
  background: var(--surface-2);
}
.comp-bar {
  display: flex;
  height: 8px;
  border-radius: 999px;
  overflow: hidden;
  background: rgba(255, 255, 255, 0.06);
}
.comp-seg { height: 100%; }
.comp-legend { display: flex; flex-wrap: wrap; gap: 4px 12px; }
.comp-item {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 0;
  border: 0;
  background: transparent;
  font-family: inherit;
  font-size: 11px;
  color: var(--text-2);
  cursor: pointer;
}
.comp-item:hover { color: var(--cyan-ink); }
.comp-item:disabled { cursor: default; opacity: 0.7; }
.comp-item i { width: 8px; height: 8px; border-radius: 2px; }
.comp-item b { color: var(--text); font-size: 10.5px; }
.ae-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: 11.5px;
  color: var(--text-2);
}
.ae-meta b { color: var(--text); font-weight: 600; }
.ae-err { color: var(--amber); }
.ae-table-wrap {
  border: 1px solid var(--line);
  border-radius: 9px;
  overflow: auto;
  max-height: 72vh;
  background: var(--surface-2);
}
/* 固定布局 + 百分比列宽：地址再长也只截自己这一格，不会把「IP / 最近」挤出可视区 */
.ae-table {
  width: 100%;
  min-width: 900px;
  table-layout: fixed;
}
.ae-table col.c-url { width: 28%; }
.ae-table col.c-title { width: 18%; }
.ae-table col.c-kind { width: 8%; }
.ae-table col.c-status { width: 8%; }
.ae-table col.c-ip { width: 11%; }
.ae-table col.c-port { width: 5%; }
.ae-table col.c-src { width: 12%; }
.ae-table col.c-time { width: 10%; }
.ae-table td.ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ae-table th {
  position: sticky;
  top: 0;
  z-index: 2;
}
.ae-row { cursor: pointer; }
.ae-row.open td { background: rgba(52, 229, 200, 0.06); }
.ae-row .hint-line {
  display: block;
  font-size: 10.5px;
  color: var(--muted);
  margin-top: 1px;
}
.ae-row .hint-line.weak { color: var(--text-2); }
.new-tag { margin-left: 6px; font-size: 9.5px; height: 15px; padding: 0 4px; }
.st-2xx { color: var(--ok-text); }
.st-3xx { color: var(--violet-ink); }
.st-alive { color: var(--ok-text); }
.st-auth { color: var(--amber); }
.st-5xx { color: var(--red); }
.st-space { color: var(--muted); }
.det-row td { background: rgba(52, 229, 200, 0.03); padding: 10px 12px; }
.det-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 6px 14px;
}
.det-item { display: flex; gap: 6px; min-width: 0; font-size: 11.5px; }
.det-k { flex: 0 0 42px; color: var(--muted); }
.det-v { color: var(--text-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.det-extra {
  margin: 8px 0 0;
  padding: 8px;
  max-height: 240px;
  overflow: auto;
  font-size: 10.5px;
  line-height: 1.6;
  color: var(--text-2);
  background: rgba(0, 0, 0, 0.18);
  border-radius: 6px;
  white-space: pre-wrap;
  word-break: break-all;
}
:global(html[data-theme="light"]) .det-extra { background: rgba(24, 62, 82, 0.05); }
.group-row td {
  background: rgba(120, 200, 220, 0.06);
  font-weight: 600;
  font-size: 12px;
  padding: 6px 10px;
}
.group-row .tag { margin-right: 8px; }
</style>
