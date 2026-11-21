<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { aiStatus as aiStatusApi, credState as credStateApi, getConfig, installTools, listAudit, listChannels, netDiagnose, saveChannels, saveConfig, setRelay, spaceEngines, spaceProbe, spaceProbeAll, testAi, testChannels, testConfig, throttleReset, throttleSave, throttleState, toolsCatalog, toolsStatus } from '@/api/endpoints'

const loading = ref(false)
const saving = ref(false)
const saved = ref(false)
const tab = ref('sources')
const audit = ref([])
const tools = ref({})
const toolsDir = ref('')
const installing = ref('')
const manualFor = ref('')
const testing = ref('')
const diag = ref(null)
const diagRunning = ref(false)

const sections = [
  { k: 'sources', label: '数据源', icon: 'globe' },
  { k: 'ai', label: 'AI', icon: 'spark' },
  { k: 'notify', label: '通知', icon: 'bolt' },
  { k: 'proxy', label: '代理', icon: 'route' },
  { k: 'server', label: '服务', icon: 'server' },
  { k: 'tools', label: '组件安装', icon: 'terminal' },
  { k: 'audit', label: '审计日志', icon: 'list' },
]

// 哪些数据源需要 key，以及提示
const SOURCE_META = {
  fofa: { label: 'FOFA', keys: ['email', 'key'], vendor: 'hunter_console' },
  hunter: { label: 'Hunter 奇安信', keys: ['key'] },
  quake: { label: 'Quake 360', keys: ['key'] },
  zoomeye: { label: 'ZoomEye', keys: ['key'] },
  shodan: { label: 'Shodan', keys: ['key'] },
  censys: { label: 'Censys', keys: ['id', 'secret'] },
  virustotal: { label: 'VirusTotal', keys: ['key'] },
  securitytrails: { label: 'SecurityTrails', keys: ['key'] },
  passivetotal: { label: 'PassiveTotal', keys: ['user', 'key'] },
  chaos: { label: 'Chaos', keys: ['key'] },
  certspotter: { label: 'CertSpotter', keys: ['key'] },
  threatbook: { label: '微步在线', keys: ['key'] },
  github: { label: 'GitHub', keys: ['token'] },
  deepseek: { label: 'DeepSeek', keys: ['key', 'model'] },
  openai: { label: 'OpenAI', keys: ['key', 'model'] },
}

// 支持中转站的源（测绘 + 大模型）
const relayTargets = [
  { key: 'fofa', label: 'FOFA' },
  { key: 'hunter', label: 'Hunter' },
  { key: 'quake', label: 'Quake' },
  { key: 'zoomeye', label: 'ZoomEye' },
  { key: 'shodan', label: 'Shodan' },
  { key: 'censys', label: 'Censys' },
  { key: 'virustotal', label: 'VirusTotal' },
  { key: 'securitytrails', label: 'SecurityTrails' },
  { key: 'threatbook', label: '微步' },
  { key: 'deepseek', label: 'DeepSeek' },
  { key: 'openai', label: 'OpenAI' },
]

const sources = reactive({})
const notify = reactive({ webhook: '', dingtalk: '', feishu: '', wecom: '', on_task_done: true, on_new_asset: true })
const proxy = reactive({ url: '', sources_via_proxy: false, scan_via_proxy: false })
const server = reactive({ host: '0.0.0.0', port: 5113, auth: true, api_key: '' })
const deep = reactive({ ai_search: false, ai_triage: true })
const mobile = reactive({ deep: true, jadx: false, apktool: false })
const ai = reactive({ engine: '', timeout: 90, temperature: 0.2, models: [] })
const bulkRelay = ref('')
const relayPicks = ref(['fofa'])

// ── 空间测绘引擎：填了 key 不等于能用，额度/账号状态只有真打一次才知道 ──
const spaceList = ref([])
const spaceProbing = ref({})
const spaceAllBusy = ref(false)
const spaceState = reactive({})

async function loadSpace() {
  try {
    const res = await spaceEngines()
    spaceList.value = res.items || []
  } catch {
    /* 拦截器已提示 */
  }
}

async function probeSpace(name) {
  spaceProbing.value = { ...spaceProbing.value, [name]: true }
  try {
    const res = await spaceProbe({ engine: name })
    spaceState[name] = { ok: Boolean(res.ok), msg: res.error || `可用，命中 ${res.total ?? 0} 条`, ms: res.ms || 0 }
  } catch (e) {
    spaceState[name] = { ok: false, msg: e?.response?.data?.detail || '请求失败', ms: 0 }
  } finally {
    spaceProbing.value = { ...spaceProbing.value, [name]: false }
  }
}

async function probeAllSpace() {
  spaceAllBusy.value = true
  try {
    const res = await spaceProbeAll()
    for (const it of res.items || []) {
      spaceState[it.engine] = {
        ok: Boolean(it.ok),
        msg: it.error || `可用，命中 ${it.total ?? 0} 条`,
        ms: it.ms || 0,
      }
    }
    ElMessage[res.usable?.length ? 'success' : 'warning'](
      res.usable?.length ? `可用引擎：${res.usable.join('、')}` : '没有可用引擎，看每条的错误原因',
    )
  } catch {
    /* 拦截器已提示 */
  } finally {
    spaceAllBusy.value = false
  }
}

// ── 登录态凭据：官网自己签发的 Cookie / Token，不解码，原样贴进配置 ──
// 公开接口给的「匿名可查」数据量很小，逐个主体深挖时必须有浏览器里的登录态。
const CRED_SOURCES = [
  {
    key: 'aiqicha',
    label: '爱企查',
    hint: '股东、对外投资、分支机构、软著、备案；企业主体扩展和股权穿透的主路。',
    verify: '保存后用「企业主体扩展」跑一个主体即可验证是否生效；日志里会出现股东 / 投资链路条数。',
    open: 'https://aiqicha.baidu.com',
    how: '浏览器登录爱企查 → 该站任意页面按 F12 → Network 任选一条 aiqicha.baidu.com 请求 → 复制请求头里的 Cookie 整行。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
  {
    key: 'tianyancha',
    label: '天眼查',
    hint: '第二来源：搜索定位主体后取股权上下游；主路没数据时兜底。采集走网页登录态（Cookie 里的 auth_token + TYCID），单独填的 Token / TYCID 只是 Cookie 里抠不到时的覆盖项。',
    verify: '保存后用「企业主体扩展」跑一个主体即可验证是否生效；日志里会出现股东 / 投资链路条数。',
    open: 'https://www.tianyancha.com',
    how: '浏览器登录天眼查 → F12 → Network 里找 tianyancha.com 的请求 → 复制 Cookie 整行（须含 auth_token 与 TYCID）；粘贴时会自动把这两个值带进下面的槽。',
    fields: [['cookie', 'Cookie（整行粘贴）'], ['token', 'Authorization / auth_token（可留空）'],
             ['tycid', 'TYCID（可留空）'], ['open_token', '开放平台 API Key（可留空）']],
  },
  {
    key: 'xiaolanben',
    label: '小蓝本',
    hint: '工商第四路：股东与对外投资，按需填。网页版数据接口要页面内验签，所以填了 Cookie 也只会按能取到的部分算。',
    verify: '保存后点「连通测试」：只打登录态校验口，能分清 Cookie 有效 / 已过期；采集时股东与投资是否取到以任务日志里的小蓝本备注为准。',
    open: 'https://sou.xiaolanben.com',
    how: '浏览器登录小蓝本 → F12 → Network 里找 /api.xiaolanben.com/ 的请求 → 复制 Cookie 整行；若请求头带 Authorization，把值填到 Token。',
    fields: [['cookie', 'Cookie（整行粘贴）'], ['token', 'Authorization / Token（可留空）']],
  },
  {
    key: 'qimai',
    label: '七麦',
    hint: '应用商店检索：补应用宝、豌豆荚搜不到的 APP，并带出 AppID / 包名 / 开发者。不填也能用其它商店来源。',
    verify: '保存后用「一键收集」跑一个应用名即可验证是否生效；任务日志里会出现 App 检索条数。',
    open: 'https://www.qimai.cn',
    how: '浏览器登录七麦 → 随便搜一次 → F12 → Network 里找 api.qimai.cn 的请求 → 复制 Cookie 整行；站点带签名参数时，把请求里的 analysis 值一并贴进来也能用。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
  {
    key: 'qichacha',
    label: '企查查',
    hint: '工商第三路：股东、对外投资、分支机构。企查查网页接口要 Cookie，部分接口还要 X-Tycid。',
    verify: '保存后用「企业主体扩展」跑一个主体，日志里会出现该来源的股东 / 投资条数，或写明被风控。',
    open: 'https://www.qcc.com',
    how: '浏览器登录企查查 → F12 → Network 任一 qcc.com 接口 → 复制请求头 Cookie 整行；若请求头里有 X-Tycid，把值填到 TYCID。',
    fields: [['cookie', 'Cookie（整行粘贴）'], ['tycid', 'X-Tycid（可留空）']],
  },
  {
    key: 'qcctid',
    label: '企查查开放接口',
    hint: '企查查开放平台的接口凭据，接口走独立域名，和网页版 Cookie 分开配。',
    verify: '保存后跑一个主体，日志里会出现该来源命中或被拒的提示。',
    open: 'https://openapi.qcc.com',
    how: '登录企查查开放平台 → 我的接口 → 复制 AppKey 对应的 Authorization / Cookie；接口需要 TYCID 请求头时一并填。',
    fields: [['cookie', 'Cookie / Authorization（整行粘贴）'], ['tycid', 'TYCID（可留空）']],
  },
  {
    key: 'riskbird',
    label: '风鸟',
    hint: '工商第四路：股权与关联企业检索，免费账号也能查一部分。',
    verify: '保存后跑一个主体，日志里会出现风鸟命中条数，或提示 Cookie 过期。',
    open: 'https://www.riskbird.com',
    how: '浏览器登录风鸟 → F12 → Network 找 riskbird-api 的请求 → 复制 Cookie 整行。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
  {
    key: 'kuaicha',
    label: '快查',
    hint: '工商备用来源：主体基本信息与对外投资，前几家都空时兜底。',
    verify: '保存后跑一个主体，日志里会出现快查命中条数。',
    open: 'https://www.kuaicha365.com',
    how: '浏览器登录快查 → F12 → Network 找 kuaicha365.com 的接口 → 复制 Cookie 整行。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
  {
    key: 'qidian',
    label: '企典',
    hint: '工商备用来源：股东与投资链路，按需填。',
    verify: '保存后跑一个主体，日志里会出现企典命中条数。',
    open: 'https://www.qidianxin.com',
    how: '浏览器登录企典 → F12 → Network 任一站点接口 → 复制 Cookie 整行。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
  {
    key: 'chinaz',
    label: '站长之家',
    hint: '备案与域名历史补充：用于给工商链路之外的主体名找备案域。',
    verify: '保存后跑一个主体，日志里会出现备案 / 域名补充条数。',
    open: 'https://www.chinaz.com',
    how: '浏览器登录站长之家 → F12 → Network 任一接口 → 复制 Cookie 整行；只需查公开数据时可留空。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
  {
    key: 'aldzs',
    label: '阿拉丁',
    hint: '小程序榜单与统计：按企业名找对应小程序，补本地包扫描之外的入口。',
    verify: '保存后用「小程序检索」跑一个企业名，日志里会出现阿拉丁命中条数。',
    open: 'https://www.aldzs.com',
    how: '浏览器登录阿拉丁 → F12 → Network 找 aldzs.com 的接口 → 复制 Cookie 整行。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
  {
    key: 'appbk',
    label: 'appbk',
    hint: '应用包信息补充：开发者、包名、下载页，和七麦互为补充。',
    verify: '保存后跑一个应用名，日志里会出现 appbk 命中条数。',
    open: 'https://www.appbk.com',
    how: '浏览器打开 appbk → F12 → Network 任一接口 → 复制 Cookie 整行。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
  {
    key: 'weibo',
    label: '微博',
    hint: '账号线：站内搜索用户卡、粉丝数、认证、简介；不带 Cookie 只能靠搜索引擎发现主页。',
    verify: '保存后点「连通测试」，站内搜索会回一条用户卡；Cookie 失效会明确回「要求登录」。',
    open: 'https://weibo.com',
    how: '浏览器登录微博 → F12 → Network 任一 weibo.com 接口 → 复制 Cookie 整行（须含 SUB）。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
  {
    key: 'weixin',
    label: '微信（公众号）',
    hint: '公众号线：主页昵称、gh_ 原始 ID、文章标题；带 Cookie 能少撞风控页。',
    verify: '保存后点「连通测试」，请求会带上这条 Cookie；被拦会回「环境异常」。',
    open: 'https://mp.weixin.qq.com',
    how: '浏览器打开公众号后台或任一公众号主页 → F12 → Network → 复制 Cookie 整行（含 uin / key）。',
    fields: [['cookie', 'Cookie（整行粘贴）']],
  },
]
const CRED_KEYS = CRED_SOURCES.map((s) => s.key)
const credForm = reactive(Object.fromEntries(CRED_SOURCES.map((s) => [
  s.key, Object.fromEntries(s.fields.map(([f]) => [f, ''])),
])))
const credPaste = reactive(Object.fromEntries(CRED_SOURCES.map((s) => [s.key, ''])))
// 备用登录态：一行一份，保存后进 sources.<key>.cookie_pool；主值被封就自动轮换
const credPool = reactive(Object.fromEntries(CRED_SOURCES.map((s) => [s.key, ''])))
const credPoolDirty = reactive(Object.fromEntries(CRED_SOURCES.map((s) => [s.key, false])))
// 后端内存里的池子状态（配了几份 / 当前第几份 / 哪份在冷却）
const poolState = reactive({})

// 把浏览器里复制的一整段（可能带 Request Headers 全文）归一成可用的 Cookie 行
function normalizeCookie(text) {
  const raw = String(text || '').trim()
  if (!raw) return ''
  const m = raw.match(/(?:^|\n)[Cc]ookie:\s*(.+)/)
  const body = (m ? m[1] : raw).trim()
  // 逐段挑 key=value，丢掉 Sec-* / User-Agent 这类不是 cookie 的头
  const parts = body.split(/;\s*|\r?\n/).map((s) => s.trim()).filter((s) => /^[^=;\s]+=[^;]*$/.test(s))
  return parts.join('; ')
}

function applyCredPaste(key) {
  const val = normalizeCookie(credPaste[key])
  if (!val) return ElMessage.warning('没认出 Cookie，请粘贴以 key=value; key2=value2 形式的内容')
  const target = credForm[key]
  if ('cookie' in target) target.cookie = val
  else target.token = val
  // Cookie 行里本来就夹着登录态字段，顺手填进对应槽，省得再回浏览器抠一遍。
  // 已经有值的槽不覆盖——手填的那份优先。
  const pick = (name) => {
    const m = val.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'))
    return m ? m[1].trim() : ''
  }
  const fill = (field, names) => {
    if (!(field in target) || String(target[field] || '').trim()) return
    for (const n of names) {
      const v = pick(n)
      if (v) { target[field] = v; return }
    }
  }
  fill('token', ['auth_token', 'Authorization', 'authorization'])
  fill('tycid', ['TYCID', 'tycid', 'X-Tycid'])
  credPaste[key] = ''
  ElMessage.success(`已填入 ${val.split(';').length} 个字段，记得点保存`)
}

function credReady(key) {
  const v = credForm[key] || {}
  return Object.values(v).some((x) => String(x || '').trim())
}

// 备用登录态一行一份：清洗成 Cookie 行、去重，保存后进 sources.<key>.cookie_pool
function poolLines(key) {
  const seen = new Set()
  const out = []
  for (const line of String(credPool[key] || '').split(/\r?\n/)) {
    const v = normalizeCookie(line)
    if (!v || seen.has(v)) continue
    seen.add(v)
    out.push(v)
  }
  return out
}

function applyCredPool(key) {
  const lines = poolLines(key)
  credPool[key] = lines.join('\n')
  credPoolDirty[key] = true
  if (!lines.length) return ElMessage.warning('没认出备用 Cookie，每行写一份 key=value; k2=v2')
  ElMessage.success(`已整理成 ${lines.length} 份备用登录态，点保存生效`)
}

function clearPool(key) {
  credPool[key] = ''
  credPoolDirty[key] = true
  ElMessage.info('已清空备用登录态，保存后只剩主值那一份')
}

// 池子现状：后端内存里配了几份、当前用第几份、还有几份在冷却
function poolHint(key) {
  const st = poolState[key]
  if (!st || !st.total) return ''
  const slots = Array.isArray(st.slots) ? st.slots : []
  const cooling = slots.filter((s) => Number(s.cooling) > 0).length
  const active = slots.find((s) => s.idx === st.active)
  const tail = active ? `当前第 ${active.idx + 1} 份 …${active.tail}` : `共 ${st.total} 份`
  return cooling ? `${tail} · ${cooling} 份冷却中` : tail
}

async function loadPool() {
  try {
    const res = await credStateApi()
    const map = {}
    for (const it of res.pool || []) map[it.source] = it
    for (const k of CRED_KEYS) poolState[k] = map[k] || null
  } catch {
    /* 后端旧版没有这个接口，忽略 */
  }
}

// 连过测试：后端按来源发一次真实请求，回的是「认了 / 没认 / 没填」，不用去任务日志里猜
const credTesting = reactive({})
const credState = reactive(Object.fromEntries(CRED_KEYS.map((k) => [k, null])))
async function testCred(key) {
  credTesting[key] = true
  try {
    const res = await testConfig({ source: key })
    credState[key] = res || { ok: false, msg: '无回包' }
  } catch (e) {
    credState[key] = { ok: false, msg: e?.response?.data?.detail || e?.message || '请求失败' }
  } finally {
    credTesting[key] = false
  }
}
const aiStatus = reactive({ ready: false, msg: '' })
const aiMsg = ref('')
const aiTesting = ref(false)

// ai.models：可以并存多套大模型（DeepSeek 官方 / autorouter 中转 / 本地修片…），
// 引擎选哪条，下面表单就编哪条；老配置里只有 sources.deepseek / openai 的照样能选。
const aiRows = computed(() => (Array.isArray(ai.models) ? ai.models : []))
const aiLegacy = computed(() => (ai.engine === 'openai' || ai.engine === 'deepseek' ? ai.engine : ''))
const aiRow = computed(() => aiRows.value.find((m) => m.name === ai.engine) || aiRows.value[0] || null)
// 兜底对象固定，不然没条目时输入框写进每次新建的 {}，用户以为填上了其实丢了
const aiBlank = {}
const aiModel = computed(() => (aiLegacy.value ? sources[aiLegacy.value] || aiBlank : aiRow.value || aiBlank))
const aiMasked = computed(() => String(aiModel.value?.key || '').includes('*'))

// 引擎下拉：自动（第一条）/ 每条自定义模型 / 两个官方兜底
const aiOptions = computed(() => [
  { value: '', label: '自动（用列表第一条）' },
  ...aiRows.value.map((m) => ({ value: m.name, label: `${m.name} · ${m.model || '未填模型'}` })),
  { value: 'deepseek', label: 'DeepSeek（老配置 sources.deepseek）' },
  { value: 'openai', label: 'OpenAI（老配置 sources.openai）' },
])

function aiPick(name) {
  ai.engine = name
}

function aiAdd() {
  if (!Array.isArray(ai.models)) ai.models = []
  let n = ai.models.length + 1
  while (ai.models.some((m) => m.name === `model${n}`)) n += 1
  const item = { name: `model${n}`, model: '', base: '', key: '', note: '' }
  ai.models.push(item)
  ai.engine = item.name
}

function aiDel() {
  const cur = aiRow.value
  if (!cur) return
  const idx = ai.models.indexOf(cur)
  if (idx >= 0) ai.models.splice(idx, 1)
  if (ai.engine === cur.name) ai.engine = aiRows.value[0]?.name || ''
}

// 改名要同步 engine，否则下拉指向一个不存在的条目，状态会退回「未接入」
const aiName = computed({
  get: () => aiRow.value?.name || '',
  set: (v) => {
    const name = String(v || '').trim()
    const row = aiRow.value
    if (!name || !row) return
    if (ai.engine === row.name) ai.engine = name
    row.name = name
  },
})

const sourceList = computed(() =>
  Object.keys(SOURCE_META).map((k) => ({
    key: k,
    label: SOURCE_META[k].label,
    fields: (SOURCE_META[k].keys || []).map((f) => ({ key: f })),
    cfg: sources[k] || {},
    form: sources[k] || {},
    ready: Boolean((sources[k]?.key || sources[k]?.token) && !String(sources[k]?.key || '').includes('*')),
  })),
)

// ── 查询节流：每个来源自己的间隔 / 冷却，细节可控 ──
const thrConfig = ref({})
const thrState = ref({})
// 编辑态：全局口径 + 每个来源的间隔；保存后后端立刻生效
const thrDraft = reactive({
  enabled: true, min_interval: 1.5, max_interval: 4, concurrent: 1,
  risk_threshold: 3, cooldown: 60, cooldown_max: 900,
})
const thrEdit = reactive({})
const thrSaving = ref(false)
const THR_LABEL = {
  aiqicha: '爱企查', tianyancha: '天眼查', qichacha: '企查查', qcctid: '企查查开放接口',
  riskbird: '风鸟', kuaicha: '快查', qidian: '企典', zero_zone: '空间测绘', miit: '备案查询',
  fofa: 'FOFA', hunter: 'Hunter', quake: 'Quake', zoomeye: 'ZoomEye', shodan: 'Shodan',
  censys: 'Censys', virustotal: 'VirusTotal', securitytrails: 'SecurityTrails',
  passivetotal: 'PassiveTotal', chaos: 'Chaos', certspotter: 'CertSpotter',
  threatbook: '微步在线', github: 'GitHub',
}

const thrRows = computed(() => {
  const per = thrConfig.value.per_source || {}
  const names = Array.from(new Set([...Object.keys(per), ...Object.keys(thrState.value)]))
  return names
    .map((name) => {
      const p = per[name] || {}
      const st = thrState.value[name] || {}
      const lo = p.min_interval ?? thrConfig.value.min_interval ?? 0
      const hi = p.max_interval ?? thrConfig.value.max_interval ?? 0
      return {
        name,
        label: THR_LABEL[name] || name,
        lo,
        hi,
        custom: p.min_interval != null || p.max_interval != null,
        interval: `${lo}～${hi}`,
        ok: st.ok || 0,
        risk: st.risk || 0,
        cooldowns: st.cooldowns || 0,
        cooling: st.cooling || 0,
        why: st.last_why || '',
      }
    })
    .sort((a, b) => b.cooling - a.cooling || b.cooldowns - a.cooldowns || b.risk - a.risk)
})

function fillThrottle(res) {
  // 全局口径和 per_source 分开返回，这里合起来渲染；表格行要有 per_source 才出得来
  thrConfig.value = { ...(res.config || {}), per_source: res.per_source || {} }
  thrState.value = res.state || {}
  for (const [k, v] of Object.entries(res.config || {})) {
    if (k in thrDraft && v != null) thrDraft[k] = v
  }
  // 来源间隔：有单独配置就带出来，没有就按全局占位
  const per = res.per_source || thrConfig.value.per_source || {}
  for (const k of Object.keys(thrEdit)) delete thrEdit[k]
  for (const name of Object.keys(per)) {
    const p = per[name]
    // 存成 null 表示这条来源跟随全局，不当成单独覆盖
    if (!p || typeof p !== 'object') continue
    thrEdit[name] = {
      min: p.min_interval ?? thrDraft.min_interval,
      max: p.max_interval ?? thrDraft.max_interval,
    }
  }
}

async function loadThrottle() {
  try {
    const res = await throttleState()
    fillThrottle(res)
  } catch {
    /* 拦截器已提示 */
  }
}

// 表格里每个来源的间隔：有编辑值用编辑值，否则用已保存的覆盖值 / 全局值
function thrLo(name) {
  const e = thrEdit[name]
  if (e) return e.min
  return thrConfig.value.per_source?.[name]?.min_interval ?? thrConfig.value.min_interval ?? 1.5
}

function thrHi(name) {
  const e = thrEdit[name]
  if (e) return e.max
  return thrConfig.value.per_source?.[name]?.max_interval ?? thrConfig.value.max_interval ?? 4
}

function setThrInterval(name, key, raw) {
  if (!thrEdit[name]) thrEdit[name] = { min: thrLo(name), max: thrHi(name) }
  thrEdit[name][key] = raw === '' ? 0 : Number(raw)
}

async function saveThrottle() {
  thrSaving.value = true
  try {
    const per = {}
    for (const row of thrRows.value) {
      if (!thrEdit[row.name]) continue
      per[row.name] = { min_interval: Number(thrEdit[row.name].min), max_interval: Number(thrEdit[row.name].max) }
    }
    const res = await throttleSave({
      enabled: thrDraft.enabled,
      min_interval: Number(thrDraft.min_interval),
      max_interval: Number(thrDraft.max_interval),
      concurrent: Number(thrDraft.concurrent),
      risk_threshold: Number(thrDraft.risk_threshold),
      cooldown: Number(thrDraft.cooldown),
      cooldown_max: Number(thrDraft.cooldown_max),
      per_source: per,
    })
    thrConfig.value = { ...(res.config || {}), per_source: res.per_source || {} }
    thrState.value = res.state || {}
    ElMessage.success('节流口径已保存，下一条查询立即按新口径排队')
    loadThrottle()
  } catch {
    /* 拦截器已提示 */
  } finally {
    thrSaving.value = false
  }
}

// 单来源改回跟随全局：传 null 让后端把这条覆盖删掉
async function thrFollowGlobal(name) {
  delete thrEdit[name]
  try {
    await throttleSave({ per_source: { [name]: null } })
    ElMessage.success(`${THR_LABEL[name] || name} 已改为跟随全局间隔`)
    loadThrottle()
  } catch {
    /* 拦截器已提示 */
  }
}

async function resetThrottle() {
  try {
    await throttleReset()
    ElMessage.success('已解除所有来源的冷却')
    loadThrottle()
  } catch {
    /* 拦截器已提示 */
  }
}

async function load() {
  loading.value = true
  try {
    const res = await getConfig()
    const cfg = res.config || {}
    // 每个已知源都先补一个空对象，后端没返回的源照样能渲染输入框
    for (const k of Object.keys(SOURCE_META)) if (!sources[k]) sources[k] = {}
    for (const [k, v] of Object.entries(cfg.sources || {})) {
      if (!sources[k]) sources[k] = {}
      Object.assign(sources[k], v)
    }
    Object.assign(notify, cfg.notification || {})
    // 登录态凭据单独编辑；打码值（***）不写回输入框，避免存盘时被当成新值
    for (const s of CRED_SOURCES) {
      const src = cfg.sources?.[s.key] || {}
      for (const [f] of s.fields) {
        const v = String(src[f] ?? '')
        if (!v || v.includes('*')) credForm[s.key][f] = ''
      }
    }
    Object.assign(proxy, cfg.proxy || {})
    Object.assign(server, cfg.server || {})
    Object.assign(deep, cfg.deep || {})
    Object.assign(mobile, cfg.mobile || {})
    Object.assign(ai, cfg.ai || {})
    loadPool()
  } finally {
    loading.value = false
  }
}

async function applyRelay(list) {
  if (!list.length) return ElMessage.warning('先勾选要设置中转站的数据源')
  try {
    const res = await setRelay({ relay: bulkRelay.value.trim(), sources: list })
    for (const k of list) {
      if (!sources[k]) sources[k] = {}
      sources[k].relay = bulkRelay.value.trim()
    }
    ElMessage.success(res.relay ? `已切到中转站 ${res.relay}` : '已恢复官方地址')
  } catch {
    /* 拦截器已提示 */
  }
}

async function loadAI() {
  try {
    const res = await aiStatusApi()
    Object.assign(aiStatus, { ready: Boolean(res.ready), msg: res.msg || '' })
  } catch {
    /* 未登录或后端旧版 */
  }
}

async function testAI() {
  aiTesting.value = true
  aiMsg.value = ''
  try {
    const res = await testAi()
    aiMsg.value = res.msg || ''
    aiStatus.ready = Boolean(res.ok)
    ElMessage[res.ok ? 'success' : 'warning'](res.msg || '已发送')
  } catch (e) {
    aiMsg.value = e?.response?.data?.detail || '测试失败'
  } finally {
    aiTesting.value = false
  }
}

async function save() {
  saving.value = true
  saved.value = false
  try {
    // 只提交真正填了新值的那一格，空串不进 patch（否则会把已存的 Cookie 抹掉）
    const credPatch = {}
    for (const s of CRED_SOURCES) {
      const filled = {}
      for (const [f] of s.fields) {
        const v = String(credForm[s.key][f] || '').trim()
        if (v) filled[f] = v
      }
      // 备用登录态只在这次真编辑过时才提交：清空就送 [] 让后端删掉整段池子
      if (credPoolDirty[s.key]) filled.cookie_pool = poolLines(s.key)
      if (Object.keys(filled).length) credPatch[s.key] = filled
    }
    await saveConfig({
      sources: { ...sources, ...credPatch },
      ai: { ...ai },
      deep: { ...deep },
      mobile: { ...mobile },
      notification: { ...notify },
      proxy: { ...proxy },
      server: { ...server },
    })
    for (const k of CRED_KEYS) credPoolDirty[k] = false
    loadPool()
    saved.value = true
    setTimeout(() => { saved.value = false }, 2400)
  } finally {
    saving.value = false
  }
}

async function test(source) {
  testing.value = source
  try {
    const res = await testConfig({ source })
    ElMessage[res?.ok ? 'success' : 'warning'](res?.msg || '已发送测试请求')
  } catch {
    /* 拦截器已提示错误 */
  } finally {
    testing.value = ''
  }
}

// 直连 / 代理 / DNS 三段分开探，直接告诉人该改哪一处配置
async function runDiagnose() {
  diagRunning.value = true
  try {
    diag.value = await netDiagnose({ with_proxy: true })
  } catch {
    diag.value = null
  } finally {
    diagRunning.value = false
  }
}

const DIAG_TAG = {
  ok: { cls: 'ok', text: '正常' },
  proxy_broken: { cls: 'err', text: '代理异常' },
  need_proxy: { cls: 'warn', text: '需走代理' },
  offline: { cls: 'err', text: '外网不通' },
}

async function loadAudit() {
  const res = await listAudit({ limit: 200 })
  audit.value = res.items || []
}

async function loadTools() {
  try {
    const res = await toolsCatalog()
    tools.value = res.items || {}
    toolsDir.value = res.dir || ''
  } catch {
    // 后端旧版没这个接口时退回只看路径
    const res = await toolsStatus()
    tools.value = Object.fromEntries(Object.entries(res.items || {}).map(([k, v]) => [k, { path: v, installed: Boolean(v) }]))
  }
}

function openManual(name) {
  manualFor.value = manualFor.value === name ? '' : name
}

async function installOne(name) {
  installing.value = name
  try {
    const res = await installTools({ names: [name] })
    tools.value = res.items || tools.value
    const r = res.results?.[name] || {}
    if (r.ok) ElMessage.success(r.msg || `${name} 已就绪`)
    else ElMessage.warning(`${name} 没装上：${r.error || '未知原因'}，看下面的手动安装步骤`)
  } catch (e) {
    ElMessage.warning(e?.response?.data?.detail || '安装请求失败（检查代理与网络）')
  } finally {
    installing.value = ''
  }
}

async function installMissing() {
  const missing = Object.entries(tools.value).filter(([, v]) => !v.installed).map(([k]) => k)
  if (!missing.length) return ElMessage.success('已经全部可用')
  installing.value = '__all__'
  try {
    const res = await installTools({ names: missing })
    tools.value = res.items || tools.value
    const bad = Object.entries(res.results || {}).filter(([, r]) => !r.ok).map(([k]) => k)
    ElMessage[bad.length ? 'warning' : 'success'](bad.length ? `装好 ${missing.length - bad.length} 个，${bad.join('、')} 失败` : `已装好 ${missing.length} 个`)
  } catch (e) {
    ElMessage.warning(e?.response?.data?.detail || '安装请求失败')
  } finally {
    installing.value = ''
  }
}

function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

// ─────────────── 数据来源开关 · 自检 ───────────────
// 这一块原来挂在功能自检页上，2026-11 挪到设置：开关和凭据是同一件事，
// 换 Cookie 的时候顺手就能把这一路的开关和自检点掉。
const chan = reactive({
  groups: [], items: [], total: 0, enabled: 0, usable: 0, dead: 0,
  timeout: 0, config: 0, skip: 0, untested: 0, tested_at: '',
})
const chanLoading = ref(false)
const chanTesting = ref(false)
const chanErr = ref('')
const chanMsg = ref('')
const chanFilter = ref('')
const chanOnlyOn = ref(false)
const chanProbe = ref('')

const CHAN_TONE = { ok: 'ok', empty: 'info', partial: 'warn', timeout: 'warn',
                    dead: 'err', config: 'warn', skip: '', untested: '' }

function applyChannels(d) {
  if (!d) return
  const items = d.items || []
  chan.groups = d.groups || []
  chan.items = items
  chan.total = d.total ?? items.length
  chan.enabled = d.enabled ?? items.filter((i) => i.enabled).length
  chan.usable = d.usable ?? 0
  chan.dead = d.dead ?? 0
  chan.timeout = d.timeout ?? 0
  chan.config = d.config ?? 0
  chan.skip = d.skip ?? 0
  chan.untested = d.untested ?? 0
  chan.tested_at = d.tested_at || ''
}

async function loadChannels() {
  chanLoading.value = true
  chanErr.value = ''
  try {
    applyChannels(await listChannels())
  } catch (e) {
    chanErr.value = e?.response?.data?.detail || '渠道目录取不到'
  } finally {
    chanLoading.value = false
  }
}

const chanGroups = computed(() => {
  const q = chanFilter.value.trim().toLowerCase()
  return (chan.groups || [])
    .map((g) => {
      const items = (g.items || []).filter((it) => {
        if (chanOnlyOn.value && !it.enabled) return false
        if (!q) return true
        return `${it.label} ${it.key} ${it.need} ${it.note}`.toLowerCase().includes(q)
      })
      return {
        ...g,
        items,
        onCount: items.filter((i) => i.enabled).length,
        okCount: items.filter((i) => i.enabled && ['ok', 'empty', 'partial'].includes(i.state)).length,
      }
    })
    .filter((g) => g.items.length)
})

const chanSummary = computed(() => [
  { label: '渠道', value: chan.total, tone: '' },
  { label: '已启用', value: chan.enabled, tone: 'cyan' },
  { label: '可用', value: chan.usable, tone: 'ok' },
  { label: '未测', value: chan.untested, tone: '' },
  { label: '失效', value: chan.dead, tone: chan.dead ? 'err' : '' },
  { label: '超时', value: chan.timeout, tone: chan.timeout ? 'warn' : '' },
  { label: '缺凭据', value: chan.config, tone: chan.config ? 'warn' : '' },
])

async function toggleChannel(it) {
  const next = !it.enabled
  it.enabled = next // 先动界面，存不上再翻回来
  chanErr.value = ''
  try {
    applyChannels(await saveChannels({ key: it.key, enabled: next }))
  } catch (e) {
    it.enabled = !next
    chanErr.value = `${it.label} 开关没存上：${e?.response?.data?.detail || e.message}`
  }
}

async function setAllChannels(on) {
  chanLoading.value = true
  chanErr.value = ''
  chanMsg.value = ''
  try {
    applyChannels(await saveChannels({ off: on ? [] : chan.items.map((i) => i.key) }))
    chanMsg.value = on ? '已全部开启' : '已全部停用'
  } catch (e) {
    chanErr.value = e?.response?.data?.detail || '开关没存上'
  } finally {
    chanLoading.value = false
  }
}

async function testChannel(it) {
  chanTesting.value = true
  chanErr.value = ''
  chanMsg.value = `正在测 ${it.label}…`
  try {
    const r = await testChannels({ keys: [it.key], query: chanProbe.value.trim() })
    const got = (r.items || [])[0]
    if (got) Object.assign(it, got)
    chanMsg.value = got
      ? `${got.label}：${got.state_label || '已测'}${got.ms ? ` · ${got.ms}ms` : ''}${got.note ? ` — ${got.note}` : ''}`
      : '这一路没回执'
    await loadChannels()
  } catch (e) {
    chanErr.value = `${it.label} 自检失败：${e?.response?.data?.detail || e.message}`
    chanMsg.value = ''
  } finally {
    chanTesting.value = false
  }
}

async function testAllChannels() {
  chanTesting.value = true
  chanErr.value = ''
  chanMsg.value = '正在逐路真打最小请求，慢源要等一会儿…'
  try {
    const r = await testChannels({ query: chanProbe.value.trim() })
    await loadChannels()
    chanMsg.value = `自检完 ${r.count || 0} 路：可用 ${r.usable || 0} 路，失效 ${r.dead || 0} 路`
  } catch (e) {
    chanErr.value = `自检失败：${e?.response?.data?.detail || e.message}`
    chanMsg.value = ''
  } finally {
    chanTesting.value = false
  }
}

onMounted(() => {
  load()
  loadAudit()
  loadTools()
  loadAI()
  loadThrottle()
  loadSpace()
  loadChannels()
})
</script>

<template>
  <div class="stack">
    <PageHead title="系统设置" desc="数据源密钥、通知通道、代理与账号；保存后立即生效，打码值不会被覆盖">
      <template #actions>
        <span v-if="saved" class="tag ok">已保存并生效</span>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="13" />重载</button>
        <button v-if="['sources', 'notify', 'proxy', 'server', 'ai', 'tools'].includes(tab)" class="btn primary sm" :disabled="saving" @click="save">
          <Icon name="check" :size="13" />保存
        </button>
      </template>
    </PageHead>

    <div class="row">
      <div class="seg">
        <button v-for="s in sections" :key="s.k" :class="{ on: tab === s.k }" @click="tab = s.k">{{ s.label }}</button>
      </div>
    </div>

    <div v-if="tab === 'sources'" class="stack">
      <div class="panel">
        <div class="panel-head">
          <span><Icon name="route" :size="13" />中转站（代理商 / 自建转发）</span>
          <span class="mono muted">留空 = 走官方接口</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="row" style="gap: 10px; align-items: flex-end">
            <div class="field flex-1">
              <span class="field-label">中转站根地址（不带 /api 后缀，程序自己拼 /api/v1/search/all 等路径）</span>
              <input v-model="bulkRelay" class="input mono" placeholder="https://api.你的中转站.com（不带 /api 后缀）" />
            </div>
            <button class="btn sm" @click="applyRelay(relayPicks)"><Icon name="check" :size="12" />应用到所选</button>
          </div>
          <div class="row" style="flex-wrap: wrap; gap: 12px">
            <label v-for="o in relayTargets" :key="o.key" class="opt">
              <input v-model="relayPicks" type="checkbox" :value="o.key" style="margin-right: 4px" />{{ o.label }}
            </label>
          </div>
          <span class="field-hint">直接填代理商给的中转站根地址（如 https://api.你的代理商.com），程序会自己拼 /api/v1/search/all 等路径；带不带中转都只配这一个地址，不用去改官方域名。FOFA / Hunter / Quake / ZoomEye / Shodan 等测绘源与 DeepSeek / OpenAI 都支持，保存后立即生效，「连通测试」会打最终生效的地址。</span>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span><Icon name="globe" :size="13" />空间测绘引擎 · 可用性</span>
          <button class="btn xs" :disabled="spaceAllBusy" @click="probeAllSpace">
            <Icon name="bolt" :size="11" />{{ spaceAllBusy ? '逐个测试中…' : '全部测试' }}
          </button>
        </div>
        <div class="panel-body stack" style="gap: 8px">
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr><th>引擎</th><th>凭据</th><th>落地地址</th><th>最近一次测试</th><th></th></tr>
              </thead>
              <tbody>
                <tr v-for="e in spaceList" :key="e.name">
                  <td>
                    <span>{{ e.label }}</span>
                    <span class="tag" :class="e.queryable ? 'ok' : ''" style="margin-left: 6px">{{ e.queryable ? '可检索' : '未接入' }}</span>
                  </td>
                  <td class="mono muted">{{ e.keys ? `${e.keys} 把` : '未配置' }}</td>
                  <td class="mono muted ellipsis" style="max-width: 240px">{{ e.base || e.official }}</td>
                  <td>
                    <span v-if="!spaceState[e.name]" class="muted">未测试</span>
                    <span v-else :style="{ color: spaceState[e.name].ok ? 'var(--ok)' : 'var(--warn)' }">
                      {{ spaceState[e.name].ok ? '可用' : '不可用' }} · {{ spaceState[e.name].ms }}ms
                      <span class="muted">— {{ spaceState[e.name].msg }}</span>
                    </span>
                  </td>
                  <td style="text-align: right">
                    <button class="btn xs" :disabled="spaceProbing[e.name]" @click="probeSpace(e.name)">
                      {{ spaceProbing[e.name] ? '测试中…' : '连通测试' }}
                    </button>
                  </td>
                </tr>
                <tr v-if="!spaceList.length"><td colspan="5" class="muted">未取到引擎列表</td></tr>
              </tbody>
            </table>
          </div>
          <span class="field-hint">测试会真发一条最小语法到最终生效的地址（含中转站改写），平台回了「账号无效 / 额度不足 / 被限流」会原样显示。多条 key 时按「主 key → keys 列表」顺序轮换，一把被拒自动换下一把。</span>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span><Icon name="bolt" :size="13" />数据来源开关 · 自检</span>
          <span class="row" style="gap: 6px">
            <input v-model="chanProbe" class="input mono chan-q" placeholder="自检样例词（空 = 用内置）" />
            <button class="btn xs" :disabled="chanTesting" @click="testAllChannels">
              <Icon name="bolt" :size="11" />{{ chanTesting ? '自检中…' : '一键自检' }}
            </button>
            <button class="btn xs" :disabled="chanLoading" @click="loadChannels"><Icon name="refresh" :size="11" />刷新</button>
          </span>
        </div>
        <div class="panel-body stack" style="gap: 8px">
          <div class="row chan-sum">
            <span v-for="s in chanSummary" :key="s.label" class="tag" :class="s.tone">{{ s.label }} {{ s.value }}</span>
            <span v-if="chan.tested_at" class="field-hint">上次自检 {{ chan.tested_at }}</span>
          </div>
          <div class="row" style="gap: 8px; align-items: center">
            <input v-model="chanFilter" class="input chan-q" placeholder="按名称 / 凭据 / 提示过滤（如 工商、备案、Cookie）" />
            <label class="opt"><input v-model="chanOnlyOn" type="checkbox" style="margin-right: 4px" />只看启用</label>
            <span class="flex-1" />
            <button class="btn xs" :disabled="chanLoading" @click="setAllChannels(true)">全部开启</button>
            <button class="btn xs" :disabled="chanLoading" @click="setAllChannels(false)">全部停用</button>
          </div>
          <span v-if="chanErr" class="field-hint" style="color: var(--red)">{{ chanErr }}</span>
          <span v-if="chanMsg" class="field-hint">{{ chanMsg }}</span>
          <div v-if="!chanGroups.length" class="empty">{{ chanLoading ? '读取中…' : '没有匹配的渠道' }}</div>
          <div v-for="g in chanGroups" :key="g.group" class="chan-group">
            <div class="chan-group-head">
              <span class="chan-group-name">{{ g.label }}</span>
              <span class="muted">启用 {{ g.onCount }} / 可用 {{ g.okCount }} / 共 {{ g.items.length }}</span>
              <span class="chan-hint">{{ g.hint }}</span>
            </div>
            <div v-for="it in g.items" :key="it.key" class="chan-row" :class="{ off: !it.enabled }">
              <span class="switch" :class="{ on: it.enabled }" @click="toggleChannel(it)" />
              <span class="chan-name" :title="it.key">{{ it.label }}</span>
              <span class="chan-need mono muted">{{ it.need || '免凭据' }}</span>
              <span class="tag" :class="CHAN_TONE[it.state] || ''">{{ it.state_label }}</span>
              <span class="chan-note" :title="it.note">{{ it.note }}</span>
              <span class="chan-ms mono muted">{{ it.ms ? `${it.ms}ms` : '' }}</span>
              <button class="btn xs" :disabled="chanTesting || !it.enabled" @click="testChannel(it)">测</button>
            </div>
          </div>
          <span class="field-hint">开关落 config.yaml 的 `channels.off`，与 `sources.&lt;名&gt;.enabled` 同时生效，任一为关就不发请求。自检是逐路真打一次最小请求，把「额度用尽」「登录态过期」「没填凭据」和「能用」分开；结果只活在本次运行里，重启后重新测。</span>
        </div>
      </div>

      <div class="cards two">
        <div v-for="c in CRED_SOURCES" :key="c.key" class="panel">
          <div class="panel-head">
            <span><Icon name="key" :size="13" />{{ c.label }} · 登录态</span>
            <span class="tag" :class="credReady(c.key) ? 'ok' : 'warn'">{{ credReady(c.key) ? '本次将更新' : '未填新值' }}</span>
          </div>
          <div class="panel-body stack" style="gap: 8px">
            <span class="field-hint">{{ c.hint }}</span>
            <div class="field">
              <span class="field-label">整段粘贴（自动清洗成 Cookie 行）</span>
              <div class="row" style="gap: 8px">
                <input v-model="credPaste[c.key]" class="input mono flex-1" placeholder="Cookie: a=1; b=2; … 或直接把整段请求头贴进来" />
                <button class="btn sm" @click="applyCredPaste(c.key)"><Icon name="check" :size="12" />解析填入</button>
                <a class="btn sm" :href="c.open" target="_blank" rel="noreferrer">去登录</a>
              </div>
            </div>
            <div v-for="[f, label] in c.fields" :key="f" class="field">
              <span class="field-label">{{ label }}</span>
              <textarea v-model="credForm[c.key][f]" class="textarea mono" style="min-height: 62px" placeholder="留空 = 不改动已保存的值" />
            </div>
            <div class="field">
              <span class="field-label">
                备用登录态（一行一份）
                <span v-if="poolHint(c.key)" class="muted" style="font-size: 11px; margin-left: 6px">{{ poolHint(c.key) }}</span>
              </span>
              <textarea
                v-model="credPool[c.key]"
                class="textarea mono"
                style="min-height: 62px"
                placeholder="每行一份完整 Cookie，例如：&#10;uin=abc; key=def&#10;uin=ghi; key=jkl"
              />
              <div class="row" style="gap: 6px">
                <button class="btn xs" @click="applyCredPool(c.key)"><Icon name="check" :size="11" />清洗去重</button>
                <button class="btn xs" @click="clearPool(c.key)"><Icon name="trash" :size="11" />清空备用</button>
                <span class="field-hint flex-1">主值被 429 / 403 挡下就按顺序换下一份重打，冷却过了自动回来。</span>
              </div>
            </div>
            <details>
              <summary class="muted" style="cursor: pointer; font-size: 12px">怎么取</summary>
              <span class="field-hint">{{ c.how }}</span>
            </details>
            <div class="row">
              <span class="field-hint flex-1">{{ c.verify }}</span>
              <button class="btn xs" :disabled="credTesting[c.key]" @click="testCred(c.key)">
                <Icon name="bolt" :size="11" />{{ credTesting[c.key] ? '测试中…' : '连通测试' }}
              </button>
            </div>
            <span v-if="credState[c.key]" class="field-hint" :style="{ color: credState[c.key].ok ? 'var(--ok)' : 'var(--warn)' }">
              {{ credState[c.key].ok ? '可用' : '未通过' }}：{{ credState[c.key].msg }}
            </span>
          </div>
        </div>
      </div>

      <div class="cards two">
        <div v-for="s in sourceList" :key="s.key" class="panel">
          <div class="panel-head">
            <span><Icon name="globe" :size="13" />{{ s.label }}</span>
            <span class="tag" :class="s.ready ? 'ok' : ''">{{ s.ready ? '已配置' : '未配置' }}</span>
          </div>
          <div class="panel-body stack" style="gap: 8px">
            <div v-for="f in s.fields" :key="f.key" class="field">
              <span class="field-label">{{ f.key === 'key' ? 'API Key' : f.key === 'token' ? 'Token' : f.key === 'secret' ? 'Secret' : f.key === 'model' ? '模型' : '账号 / 邮箱' }}</span>
              <input
                v-model="s.form[f.key]"
                class="input mono"
                :type="f.key === 'email' || f.key === 'user' || f.key === 'model' ? 'text' : 'password'"
                :placeholder="String(s.cfg[f.key] || '').includes('*') ? '已保存（不改动则保留原值）' : '未配置'"
              />
            </div>
            <div class="field">
              <span class="field-label">中转站根地址（直接填代理商给的域名，留空 = 用官方 {{ s.cfg.api || '' }}）</span>
              <input
                v-model="s.form.relay"
                class="input mono"
                :placeholder="s.cfg.relay || 'https://你的中转站域名（不要带 /api 后缀）'"
              />
            </div>
            <div class="row">
              <label class="opt">
                <span class="switch" :class="{ on: s.form.enabled !== false }" @click="s.form.enabled = !(s.cfg.enabled !== false)" />启用
              </label>
              <button class="btn xs right" :disabled="testing === s.key" @click="test(s.key)">
                <Icon name="bolt" :size="11" />连通测试
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="panel span-2">
        <div class="panel-head">
          <span><Icon name="clock" :size="13" />查询节流（防封禁）</span>
          <div class="row" style="gap: 8px">
            <span class="tag" :class="thrConfig.enabled === false ? 'warn' : 'ok'">
              {{ thrConfig.enabled === false ? '已关闭' : '生效中' }}
            </span>
            <button class="btn xs" @click="loadThrottle"><Icon name="refresh" :size="11" />刷新</button>
            <button class="btn xs ghost" @click="resetThrottle"><Icon name="stop" :size="11" />解除冷却</button>
          </div>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="row" style="gap: 12px; flex-wrap: wrap; align-items: flex-end">
            <label class="opt"><span class="switch" :class="{ on: thrDraft.enabled !== false }" @click="thrDraft.enabled = thrDraft.enabled === false" />启用节流</label>
            <div class="field" style="width: 112px">
              <span class="field-label">最小间隔（秒）</span>
              <input v-model.number="thrDraft.min_interval" class="input mono" type="number" step="0.5" min="0" />
            </div>
            <div class="field" style="width: 112px">
              <span class="field-label">最大间隔（秒）</span>
              <input v-model.number="thrDraft.max_interval" class="input mono" type="number" step="0.5" min="0" />
            </div>
            <div class="field" style="width: 94px">
              <span class="field-label">同源并发</span>
              <input v-model.number="thrDraft.concurrent" class="input mono" type="number" min="1" max="8" />
            </div>
            <div class="field" style="width: 108px">
              <span class="field-label">熔断阈值（次）</span>
              <input v-model.number="thrDraft.risk_threshold" class="input mono" type="number" min="1" max="20" />
            </div>
            <div class="field" style="width: 116px">
              <span class="field-label">首次冷却（秒）</span>
              <input v-model.number="thrDraft.cooldown" class="input mono" type="number" min="5" />
            </div>
            <div class="field" style="width: 116px">
              <span class="field-label">冷却上限（秒）</span>
              <input v-model.number="thrDraft.cooldown_max" class="input mono" type="number" min="30" />
            </div>
            <button class="btn sm" :disabled="thrSaving" @click="saveThrottle"><Icon name="check" :size="12" />{{ thrSaving ? '保存中' : '保存口径' }}</button>
          </div>
          <span class="field-hint">
            每个来源单独排队：相邻两次查询之间随机停顿，命中风控词自动拉长间隔，连续命中到阈值就熔断冷却（冷却时长逐次翻倍，到上限为止）。表格里的间隔可按来源单独改，保存后下一条查询立刻按新口径排队，不用重启服务。
          </span>
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>来源</th>
                  <th>间隔（秒）</th>
                  <th>成功</th>
                  <th>风控</th>
                  <th>熔断次数</th>
                  <th>当前冷却</th>
                  <th>最近原因</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="r in thrRows" :key="r.name">
                  <td class="mono">{{ r.label }}</td>
                  <td>
                    <div class="row" style="gap: 4px; align-items: center">
                      <input
                        class="input mono"
                        type="number"
                        step="0.5"
                        min="0"
                        style="width: 62px"
                        :value="thrLo(r.name)"
                        @input="setThrInterval(r.name, 'min', $event.target.value)"
                      />
                      <span class="muted">～</span>
                      <input
                        class="input mono"
                        type="number"
                        step="0.5"
                        min="0"
                        style="width: 62px"
                        :value="thrHi(r.name)"
                        @input="setThrInterval(r.name, 'max', $event.target.value)"
                      />
                      <span v-if="r.custom" class="tag" title="这条来源单独配过间隔，点一下恢复跟随全局" style="cursor: pointer" @click="thrFollowGlobal(r.name)">跟随全局</span>
                    </div>
                  </td>
                  <td class="mono">{{ r.ok }}</td>
                  <td class="mono">{{ r.risk }}</td>
                  <td class="mono">{{ r.cooldowns }}</td>
                  <td>
                    <span v-if="r.cooling > 0" class="tag err">{{ r.cooling }}s</span>
                    <span v-else class="tag ok">可打</span>
                  </td>
                  <td class="muted ellipsis" style="max-width: 260px">{{ r.why || '—' }}</td>
                </tr>
                <tr v-if="!thrRows.length">
                  <td colspan="7" class="empty">暂无来源节流记录；任务跑起来后这里会实时显示</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <div v-if="tab === 'ai'" class="cards two">
      <div class="panel">
        <div class="panel-head">
          <span><Icon name="spark" :size="13" />大模型</span>
          <span class="tag" :class="aiStatus.ready ? 'ok' : ''">{{ aiStatus.ready ? '已接入' : '未接入' }}</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="field">
            <span class="field-label">首选引擎（可并存多套，切换即生效）</span>
            <select v-model="ai.engine" class="input">
              <option v-for="o in aiOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
            </select>
          </div>
          <div class="ai-list">
            <div
              v-for="m in aiRows" :key="m.name"
              class="ai-item" :class="{ on: aiRow && aiRow.name === m.name }"
              @click="aiPick(m.name)"
            >
              <div class="ai-item-top">
                <span class="ai-item-name">{{ m.name }}</span>
                <span class="mono muted">{{ m.model || '未填模型' }}</span>
              </div>
              <div class="mono muted ellipsis">{{ m.base || '未填地址（走官方）' }}</div>
              <div v-if="m.note" class="muted ellipsis">{{ m.note }}</div>
            </div>
            <div v-if="!aiRows.length" class="empty">还没有模型条目，点「新增模型」填一条</div>
          </div>
          <div class="row" style="gap: 8px">
            <button class="btn xs" @click="aiAdd"><Icon name="plus" :size="11" />新增模型</button>
            <button class="btn xs" :disabled="!aiRow" @click="aiDel"><Icon name="trash" :size="11" />删除当前</button>
          </div>
          <div v-if="aiLegacy" class="field-hint">
            正在编辑老配置 <span class="mono">sources.{{ aiLegacy }}</span>：它的 Key / 地址 / 模型名是任务里 P1、研判、小结真正读的那一份。
          </div>
          <template v-else>
            <div class="row" style="gap: 10px">
              <div class="field flex-1">
                <span class="field-label">条目名（引擎下拉显示这个名字）</span>
                <input v-model="aiName" class="input mono" placeholder="deepseek-flash" />
              </div>
              <div class="field flex-1">
                <span class="field-label">模型名（发给 API 的 model）</span>
                <input v-model="aiModel.model" class="input mono" placeholder="deepseek-chat" />
              </div>
            </div>
            <div class="field">
              <span class="field-label">接口根地址（不带 /v1，程序自己拼 /v1/chat/completions）</span>
              <input v-model="aiModel.base" class="input mono" placeholder="https://api.deepseek.com" />
            </div>
          </template>
          <div class="field">
            <span class="field-label">API Key</span>
            <input v-model="aiModel.key" class="input mono" type="password" :placeholder="aiMasked ? '已保存（不改动则保留原值）' : 'sk-…'" />
          </div>
          <div v-if="aiLegacy" class="row" style="gap: 10px">
            <div class="field flex-1">
              <span class="field-label">中转站 / 自定义地址（必须能转发 /v1/chat/completions）</span>
              <input v-model="aiModel.relay" class="input mono" placeholder="https://api.deepseek.com" />
            </div>
            <div class="field flex-1">
              <span class="field-label">模型名</span>
              <input v-model="aiModel.model" class="input mono" placeholder="deepseek-chat" />
            </div>
          </div>
          <div v-else class="field">
            <span class="field-label">备注（这条是干什么的，比如「本地 8787 修片，服务没起时不可用」）</span>
            <input v-model="aiModel.note" class="input" placeholder="说明这条模型的用途" />
          </div>
          <div class="field" style="width: 130px">
            <span class="field-label">超时（秒）</span>
            <input v-model.number="ai.timeout" class="input mono" type="number" />
          </div>
          <div class="row">
            <button class="btn xs" :disabled="aiTesting" @click="testAI"><Icon name="bolt" :size="11" />测试大模型</button>
            <span v-if="aiMsg" class="mono muted">{{ aiMsg }}</span>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head"><span><Icon name="control" :size="13" />AI 功能开关</span></div>
        <div class="panel-body stack" style="gap: 12px">
          <label class="opt"><span class="switch" :class="{ on: deep.ai_search }" @click="deep.ai_search = !deep.ai_search" />企业阶段 AI 关键词扩展（P1 自动跑）</label>
          <label class="opt"><span class="switch" :class="{ on: deep.ai_triage }" @click="deep.ai_triage = !deep.ai_triage" />任务结束自动写 AI 侦察小结</label>
          <div class="divider" />
          <span class="field-hint">
            AI 工坊里还有 4 个手动入口：测绘语法生成、资产研判排序、任务侦察小结、指纹规则建议。保存本页后到左侧「AI 工坊」使用。
          </span>
        </div>
      </div>
    </div>

    <div v-if="tab === 'notify'" class="cards two">
      <div class="panel">
        <div class="panel-head"><span><Icon name="bolt" :size="13" />通知通道</span></div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="field">
            <span class="field-label">通用 Webhook</span>
            <input v-model="notify.webhook" class="input mono" placeholder="https://…" />
          </div>
          <div class="field">
            <span class="field-label">钉钉机器人</span>
            <input v-model="notify.dingtalk" class="input mono" placeholder="https://oapi.dingtalk.com/robot/send?access_token=…" />
          </div>
          <div class="field">
            <span class="field-label">飞书机器人</span>
            <input v-model="notify.feishu" class="input mono" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/…" />
          </div>
          <div class="field">
            <span class="field-label">企业微信机器人</span>
            <input v-model="notify.wecom" class="input mono" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=…" />
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head"><span><Icon name="alert" :size="13" />推送时机</span></div>
        <div class="panel-body stack" style="gap: 12px">
          <label class="opt"><span class="switch" :class="{ on: notify.on_task_done }" @click="notify.on_task_done = !notify.on_task_done" />任务完成时推送汇总</label>
          <label class="opt"><span class="switch" :class="{ on: notify.on_new_asset }" @click="notify.on_new_asset = !notify.on_new_asset" />出现新资产时推送（周期任务主力）</label>
          <div class="divider" />
          <span class="field-hint">推送内容包含根域、新增数量与前若干条新增地址的列表。</span>
        </div>
      </div>
    </div>

    <div v-if="tab === 'proxy'" class="cards two">
      <div class="panel">
        <div class="panel-head"><span><Icon name="route" :size="13" />代理</span></div>
        <div class="panel-body stack" style="gap: 12px">
          <div class="field">
            <span class="field-label">代理地址</span>
            <input v-model="proxy.url" class="input mono" placeholder="http://127.0.0.1:7897" />
          </div>
          <label class="opt"><span class="switch" :class="{ on: proxy.sources_via_proxy }" @click="proxy.sources_via_proxy = !proxy.sources_via_proxy" />数据源请求走代理</label>
          <label class="opt"><span class="switch" :class="{ on: proxy.scan_via_proxy }" @click="proxy.scan_via_proxy = !proxy.scan_via_proxy" />目标探测走代理</label>
          <div class="row">
            <button class="btn sm" :disabled="testing === 'proxy'" @click="test('proxy')"><Icon name="bolt" :size="12" />测试连通</button>
          </div>
          <div class="field">
            <span class="field-label">链路诊断</span>
            <span class="field-hint">分别探测直连、经代理、DNS 解析三段，定位「没数据」是卡在哪一环。</span>
          </div>
          <div class="row">
            <button class="btn sm" :disabled="diagRunning" @click="runDiagnose">
              <Icon name="bolt" :size="12" />{{ diagRunning ? '探测中…' : '开始诊断' }}
            </button>
          </div>
          <div v-if="diag" class="stack" style="gap: 8px">
            <div class="row" style="gap: 6px; align-items: center">
              <span class="tag" :class="DIAG_TAG[diag.verdict]?.cls">{{ DIAG_TAG[diag.verdict]?.text || diag.verdict }}</span>
              <span style="font-size: 12px; color: var(--text-2)">{{ diag.note }}</span>
            </div>
            <div v-for="group in [
                  { title: '本机直连', rows: diag.direct },
                  { title: '经代理 ' + (diag.proxy || '（未配置）'), rows: diag.via_proxy || [] },
                ]" :key="group.title" class="field">
              <span class="field-label">{{ group.title }}</span>
              <div v-for="r in group.rows" :key="r.name" class="mono" style="font-size: 11px; color: var(--text-2)">
                <span class="tag" :class="r.ok ? 'ok' : 'err'" style="margin-right: 6px">{{ r.ok ? '通' : '断' }}</span>
                {{ r.name }} · {{ r.ms }}ms<span v-if="r.msg"> · {{ r.msg }}</span>
              </div>
            </div>
            <div class="field">
              <span class="field-label">DNS 解析</span>
              <div v-for="d in diag.dns" :key="d.host" class="mono" style="font-size: 11px; color: var(--text-2)">
                <span class="tag" :class="d.ok ? 'ok' : 'err'" style="margin-right: 6px">{{ d.ok ? '解析' : '失败' }}</span>
                {{ d.host }} · {{ (d.ips || []).join(', ') || d.msg }}
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head"><span><Icon name="server" :size="13" />服务</span></div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="row">
            <div class="field flex-1">
              <span class="field-label">监听地址</span>
              <input v-model="server.host" class="input mono" />
            </div>
            <div class="field" style="width: 110px">
              <span class="field-label">端口</span>
              <input v-model.number="server.port" class="input mono" type="number" />
            </div>
          </div>
          <label class="opt"><span class="switch" :class="{ on: server.auth }" @click="server.auth = !server.auth" />开启登录鉴权</label>
          <div class="field">
            <span class="field-label">API Key（脚本调用用，可留空）</span>
            <input v-model="server.api_key" class="input mono" type="password" placeholder="未配置" />
          </div>
        </div>
      </div>
    </div>

    <div v-if="tab === 'tools'" class="stack">
      <div class="panel">
        <div class="panel-head">
          <span><Icon name="terminal" :size="13" />组件安装</span>
          <button class="btn primary sm" :disabled="Boolean(installing)" @click="installMissing">
            <Icon name="download" :size="12" />{{ installing === '__all__' ? '安装中…' : '自动安装全部缺失' }}
          </button>
        </div>
        <div class="panel-body stack" style="gap: 8px">
          <span class="field-hint">
            装到本程序自带目录 <span class="mono">{{ toolsDir || 'tools' }}</span>，不写系统 PATH、不装服务，删目录即卸载。
            下载走配置里的代理（当前{{ proxy.url ? '已配置 ' + proxy.url : '未配置，直连 GitHub 可能超时' }}）。
            内置探测不依赖这些工具，装了只是补充；装不上也不影响主流程。
          </span>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span><Icon name="layers" :size="13" />包体分析（APK / IPA）</span>
        </div>
        <div class="panel-body stack" style="gap: 8px">
          <label class="opt">
            <input type="checkbox" v-model="mobile.deep" />
            <span>深度静态分析</span>
            <span class="field-hint">解清单树、权限、导出组件、深链、dex 字符串池、接口与凭据。关闭后只看包名和文件清单。</span>
          </label>
          <label class="opt">
            <input type="checkbox" v-model="mobile.jadx" :disabled="!mobile.deep" />
            <span>附加源码反编译（jadx）</span>
            <span class="field-hint">把 dex 还原成 java 再扫一遍，接口和硬编码串更全；单个包耗时数十秒到数分钟。需先装好下方 jadx。</span>
          </label>
          <label class="opt">
            <input type="checkbox" v-model="mobile.apktool" :disabled="!mobile.deep" />
            <span>附加资源解包（apktool）</span>
            <span class="field-hint">解出 res/ 下的字符串表与 xml，补清单里看不到的域名和接口。需先装好下方 apktool。</span>
          </label>
          <span class="field-hint">
            三项默认只开第一项：内置解析不依赖外部工具，装了 jadx / apktool 也只是加覆盖率，装不上会自动退回内置结果。
          </span>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span><Icon name="servers" :size="13" />工具状态</span>
          <button class="btn xs" :disabled="Boolean(installing)" @click="loadTools">
            <Icon name="refresh" :size="11" />重载
          </button>
        </div>
        <div class="panel-body" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px">
          <div v-for="(t, name) in tools" :key="name" class="metric" style="padding: 10px 12px; align-items: stretch; gap: 6px">
            <div class="row" style="justify-content: space-between; align-items: center">
              <span style="font-weight: 600; font-size: 12px">{{ t.label || name }}</span>
              <span class="tag" :class="t.installed ? 'ok' : 'warn'">
                {{ t.installed ? (t.version ? 'v' + t.version : '可用') : '未安装' }}
              </span>
            </div>
            <span class="muted" style="font-size: 11px; line-height: 1.55">{{ t.desc }}</span>
            <span class="mono" style="font-size: 10px; color: var(--text-2); word-break: break-all">
              {{ t.path || (t.manual?.install_to || '') }}
            </span>
            <span v-if="t.last && t.last.stage && t.last.stage !== 'done'" class="muted" style="font-size: 10px">
              上次安装：{{ t.last.stage }}{{ t.last.error ? ' · ' + t.last.error : '' }}
            </span>
            <div class="row" style="gap: 6px; margin-top: 2px">
              <button v-if="!t.installed && t.url" class="btn xs" :disabled="Boolean(installing)" @click="installOne(name)">
                <Icon name="download" :size="11" />{{ installing === name ? '安装中…' : '自动安装' }}
              </button>
              <button class="btn xs" @click="openManual(name)"><Icon name="eye" :size="11" />手动安装</button>
              <a v-if="t.manual?.download" class="btn xs" :href="t.manual.download" target="_blank" rel="noreferrer">下载页</a>
            </div>
          </div>
        </div>
      </div>

      <div v-if="manualFor" class="panel">
        <div class="panel-head">
          <span><Icon name="eye" :size="13" />{{ tools[manualFor]?.label || manualFor }} · 手动安装</span>
          <button class="btn xs" @click="manualFor = ''">收起</button>
        </div>
        <div class="panel-body stack" style="gap: 6px; font-size: 12px; line-height: 1.7">
          <span>1. 打开下载页：<a :href="tools[manualFor]?.manual?.download" target="_blank" rel="noreferrer" class="mono">{{ tools[manualFor]?.manual?.download }}</a></span>
          <span>2. 选哪个包：{{ tools[manualFor]?.manual?.pick }}</span>
          <span>3. 放到哪里：<span class="mono">{{ tools[manualFor]?.manual?.install_to }}</span></span>
          <span class="muted">目标目录：<span class="mono">{{ toolsDir || 'tools' }}</span>（便携版就在 exe 同级的 resources\bin\tools）</span>
          <span class="muted">放好后点本面板右上角「重载」刷新状态即可，不用重启服务。</span>
        </div>
      </div>
    </div>

<div v-if="tab === 'server'" class="panel">
      <div class="panel-head"><span><Icon name="server" :size="13" />服务端</span></div>
      <div class="panel-body stack" style="gap: 10px; max-width: 520px">
        <div class="row">
          <div class="field flex-1">
            <span class="field-label">监听地址</span>
            <input v-model="server.host" class="input mono" />
          </div>
          <div class="field" style="width: 110px">
            <span class="field-label">端口</span>
            <input v-model.number="server.port" class="input mono" type="number" />
          </div>
        </div>
        <label class="opt"><span class="switch" :class="{ on: server.auth }" @click="server.auth = !server.auth" />开启登录鉴权</label>
        <div class="field">
          <span class="field-label">API Key（脚本调用用，可留空）</span>
          <input v-model="server.api_key" class="input mono" type="password" placeholder="未配置" />
        </div>
        <span class="field-hint">改监听地址或端口后需要重启服务端才生效。</span>
      </div>
    </div>

    <div v-if="tab === 'audit'" class="panel">
      <div class="panel-head">
        <span><Icon name="list" :size="13" />操作审计</span>
        <button class="btn xs" @click="loadAudit"><Icon name="refresh" :size="11" />刷新</button>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>时间</th><th>用户</th><th>动作</th><th>对象</th><th>详情</th></tr></thead>
          <tbody>
            <tr v-for="a in audit" :key="a.id">
              <td class="mono muted">{{ fmtTime(a.ts) }}</td>
              <td>{{ a.user }}</td>
              <td><span class="tag">{{ a.action }}</span></td>
              <td class="mono ellipsis" style="max-width: 260px">{{ a.target }}</td>
              <td class="mono muted ellipsis" style="max-width: 320px" :title="a.detail">{{ a.detail }}</td>
            </tr>
            <tr v-if="!audit.length"><td colspan="5"><div class="empty">暂无审计记录</div></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.opt { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-2); cursor: pointer; }
.span-2 { grid-column: 1 / -1; }

/* 数据来源开关 · 自检 */
.chan-q { width: 240px; height: 26px; font-size: 11.5px; }
.chan-sum { gap: 6px; align-items: center; }
.chan-group { border-top: 1px solid var(--line); padding-top: 6px; }
.chan-group-head { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; font-size: 11.5px; padding: 2px 0; }
.chan-group-name { font-weight: 600; color: var(--text); }
.chan-hint { color: var(--muted); flex: 1; min-width: 180px; }
.chan-row {
  display: grid; align-items: center; gap: 8px; padding: 3px 0 3px 4px;
  grid-template-columns: 34px 172px 116px 60px minmax(0, 1fr) 56px 40px;
  border-radius: 4px;
}
.chan-row:hover { background: var(--surface-2); }
.chan-row.off { opacity: 0.5; }
.chan-name { font-size: 12px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chan-need { font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chan-note { font-size: 11px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chan-ms { font-size: 11px; text-align: right; }
.chan-row .switch { cursor: pointer; }

/* 多模型清单：点一条就切到它，下面表单跟着变 */
.ai-list { display: flex; flex-direction: column; gap: 4px; max-height: 210px; overflow: auto; }
.ai-item {
  padding: 5px 8px; border: 1px solid var(--line); border-radius: 5px;
  cursor: pointer; display: flex; flex-direction: column; gap: 2px; font-size: 11.5px;
}
.ai-item:hover { background: var(--surface-2); }
.ai-item.on { border-color: var(--accent); background: var(--surface-2); }
.ai-item-top { display: flex; align-items: baseline; gap: 8px; }
.ai-item-name { font-weight: 600; color: var(--text); }
</style>
