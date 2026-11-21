import http from './http'

// ── 认证 ──────────────────────────────────────────
export const login = (username, password) => http.post('/api/login', { username, password })
export const logout = () => http.post('/api/logout').catch(() => null)
export const me = () => http.get('/api/me')

// ── 总览 ──────────────────────────────────────────
export const overview = () => http.get('/api/overview')
export const stats = () => http.get('/api/stats')
export const diff = (root = '') => http.get('/api/diff', { params: { root } })
export const groups = (params) => http.get('/api/groups', { params })
export const presets = () => http.get('/api/oneclick/presets')

// ── 任务 ──────────────────────────────────────────
export const listTasks = (params) => http.get('/api/tasks', { params })
// 顶栏 / 左栏角标：只回各状态任务数，别用 listTasks 拉整张表
export const activeTasks = () => http.get('/api/tasks/active')
// 五段口径（主体 / 域名 / 测绘 / 探测 / 深挖）+ 资产类型中文名，三处页面共用
export const listModules = () => http.get('/api/modules')
export const createTask = (payload) => http.post('/api/tasks', payload)
export const getTask = (id) => http.get(`/api/tasks/${id}`)
export const taskLogs = (id, after = 0, limit = 800) =>
  http.get(`/api/tasks/${id}/logs`, { params: { after, limit } })
export const taskAssets = (id, params) => http.get(`/api/assets`, { params: { task_id: id, ...params } })
export const taskSummary = (id) => http.get(`/api/tasks/${id}/summary`)
// 阶段逐条明细：每阶段耗时、日志样本、这一阶段收进来的资产
export const taskStages = (id) => http.get(`/api/tasks/${id}/stages`)
// 阶段 → 可单独重测的细分项（被动源、测绘引擎按注册表现取）
export const rerunStages = () => http.get('/api/stages/rerun')
// 股权穿透树：chain 已拍平成 parent → children，可直接喂树图
export const taskEquity = (id) => http.get(`/api/tasks/${id}/equity`)
// 数据渠道：这趟调了哪些外部来源、哪些失效 / 额度尽 / 没配凭据，采集时逐条留痕
export const taskSources = (id) => http.get(`/api/tasks/${id}/sources`)
export const stopTask = (id) => http.post(`/api/tasks/${id}/stop`)
export const deleteTask = (id) => http.delete(`/api/tasks/${id}`)
// modules: ['deep:nuclei'] 只重测阶段内的某几项；targets: ['a.com'] 只重测这几个 host / IP
export const rerunTask = (id, stage = '', extra = {}) =>
  http.post(`/api/tasks/${id}/rerun`, stage ? { stage, ...extra } : {})

// 一键收集全
export const oneClick = (payload) => http.post('/api/oneclick', payload)

// ── 资产 ──────────────────────────────────────────
export const listAssets = (params) => http.get('/api/assets', { params })
export const assetDetail = (id) => http.get(`/api/assets/${id}`)
export const assetFacets = (params) => http.get('/api/assets/facets', { params })
export const repairLiveness = (taskId = '') => http.post('/api/assets/liveness', null, { params: { task_id: taskId } })
export const exportAssets = (params) => http.get('/api/export', { params, responseType: 'blob' })
// 分表册：每张表的条数（子公司 / ICP / 站点…），资产页据此摆分类卡
export const exportSheets = (params) => http.get('/api/export/sheets', { params })
// 一次导出多张工作表；ratio 只作用于控股 / 对外投资 / 股东
export const exportWorkbook = (params) =>
  http.get('/api/export/xlsx', { params, responseType: 'blob', timeout: 300000 })
// 脆弱资产分桶：不传 task_id 是整体，传了就是单个任务
export const riskOverview = (params) => http.get('/api/risk', { params })
// 按任务分隔的脆弱资产计数，给「整体 / 按任务」双视图用
export const riskByTask = (params) => http.get('/api/risk/by-task', { params })

// ── 空间测绘 ──────────────────────────────────────
export const searchSpace = (payload) => http.post('/api/space/search', payload)
export const spaceEngines = () => http.get('/api/space/engines')
export const spaceToTargets = (payload) => http.post('/api/space/add-targets', payload)
export const spaceComplete = (params) => http.get('/api/space/complete', { params })
// 连通测试：真打一次最小查询，回报耗时与平台错误原文
export const spaceProbe = (params) => http.get('/api/space/probe', { params })
export const spaceProbeAll = () => http.get('/api/space/probe-all')
// 免 key 热点榜：近期高增长产品 + 现成查询语法，只给起手灵感，不产资产
export const fofaHot = (params) => http.get('/api/fofa/hot', { params })
export const fofaSuggest = (params) => http.get('/api/fofa/suggest', { params })

// ── AI 工坊 ───────────────────────────────────────
export const aiStatus = () => http.get('/api/ai/status')
export const testAi = () => http.post('/api/ai/test')
export const aiQuery = (payload) => http.post('/api/ai/query', payload)
export const aiTriage = (payload) => http.post('/api/ai/triage', payload)
export const aiSummary = (payload) => http.post('/api/ai/summary', payload)
export const aiFingerprint = (payload) => http.post('/api/ai/fingerprint', payload)

// ── 中转站 ────────────────────────────────────────
export const setRelay = (payload) => http.post('/api/sources/relay', payload)

// ── 企业主体 ──────────────────────────────────────
export const searchEnterprise = (payload) => http.post('/api/enterprise/search', payload)
export const enterpriseChildren = (payload) => http.post('/api/enterprise/children', payload)
export const searchMobile = (payload) => http.post('/api/mobile/search', payload)
export const searchApplet = (payload) => http.post('/api/applet/search', payload)
export const searchMp = (payload) => http.post('/api/mp/search', payload)
// 本机微信缓存离线扫描：只读当前用户目录下的 wxapkg，不联网
export const appletLocal = (params) => http.get('/api/applet/local', { params })

// ── 计划任务 ──────────────────────────────────────
export const listSchedules = () => http.get('/api/schedules')
export const saveSchedule = (payload) => http.post('/api/schedules', payload)
export const patchSchedule = (id, payload) => http.patch(`/api/schedules/${id}`, payload)
export const deleteSchedule = (id) => http.delete(`/api/schedules/${id}`)

// ── 指纹 / POC ────────────────────────────────────
export const listFingerprints = (params) => http.get('/api/fingerprints', { params })
export const addFingerprint = (payload) => http.post('/api/fingerprints', payload)
export const deleteFingerprint = (name) => http.delete(`/api/fingerprints/${encodeURIComponent(name)}`)
export const verifyFingerprint = (payload) => http.post('/api/fingerprints/verify', payload)
export const listTemplates = () => http.get('/api/templates')
export const saveTemplate = (payload) => http.post('/api/templates', payload)
export const deleteTemplate = (name) => http.delete(`/api/templates/${encodeURIComponent(name)}`)

// ── 字典管理 ──────────────────────────────────────
// 内置字典只读；用户在界面上改过的写进 data/dicts 覆盖同名内置文件
export const listDicts = () => http.get('/api/dicts')
export const readDict = (name, params) => http.get(`/api/dicts/${encodeURIComponent(name)}`, { params })
export const createDict = (payload) => http.post('/api/dicts', payload)
export const saveDict = (name, payload) => http.put(`/api/dicts/${encodeURIComponent(name)}`, payload)
export const deleteDict = (name) => http.delete(`/api/dicts/${encodeURIComponent(name)}`)
export const bindDict = (name, key) => http.post(`/api/dicts/${encodeURIComponent(name)}/bind`, { key })

// ── 通知 / 配置 ───────────────────────────────────
export const getConfig = () => http.get('/api/config')
export const saveConfig = (payload) => http.post('/api/config', payload)
export const testNotify = (payload) => http.post('/api/notify/test', payload)
export const testConfig = (payload) => http.post('/api/config/test', payload)
export const toolsStatus = () => http.get('/api/tools')
export const toolsCatalog = () => http.get('/api/tools/catalog')
export const installTools = (payload) => http.post('/api/tools/install', payload)
export const netDiagnose = (params) => http.get('/api/net/diagnose', { params })
// 各来源的节流 / 冷却状态，配置页用来核对限速是否生效
export const throttleState = () => http.get('/api/throttle')
// 登录态池：每源配了几份 Cookie、当前用第几份、哪份在冷却
export const credState = () => http.get('/api/creds')
// 改节流口径：全局间隔 / 并发 / 熔断阈值 / 冷却，以及单来源间隔
export const throttleSave = (patch) => http.post('/api/throttle', patch)
export const throttleReset = () => http.post('/api/throttle/reset')

// ── 功能自检（单项执行） ─────────────────────────
// 全部可单独跑的功能：stage 建任务跑，direct 一次调用出结果
export const opsCatalog = () => http.get('/api/ops')
// 股权穿透深度 2 层实测二十多秒，单项跑的等待时间放宽
export const opsRun = (payload) => http.post('/api/ops/run', payload, { timeout: 300000 })

// ── 渠道：目录 / 开关 / 自检 ─────────────────────
export const listChannels = () => http.get('/api/channels')
// {off: [key…]} 整表覆盖，或 {key, enabled} 单路切换
export const saveChannels = (payload) => http.post('/api/channels', payload)
// 一键自检会真打每一路的最小请求，几十路并发，等久一点
export const testChannels = (payload = {}) => http.post('/api/channels/test', payload,
  { timeout: 300000 })

// ── 审计 ──────────────────────────────────────────
export const listAudit = (params) => http.get('/api/audit', { params })

// ── SSE 任务流 ────────────────────────────────────
export function subscribeTask(taskId, onEvent) {
  const token = localStorage.getItem('suoyu_token') || ''
  const url = `/api/tasks/${taskId}/stream?token=${encodeURIComponent(token)}`
  const es = new EventSource(url)
  es.onmessage = (ev) => {
    try {
      onEvent({ type: 'log', data: JSON.parse(ev.data) })
    } catch {
      /* 忽略非 JSON 行 */
    }
  }
  es.addEventListener('state', (ev) => {
    try {
      onEvent({ type: 'state', data: JSON.parse(ev.data) })
    } catch {
      /* 忽略非 JSON 行 */
    }
  })
  es.onerror = () => {
    es.close()
    onEvent({ type: 'stream-closed' })
  }
  return () => es.close()
}
