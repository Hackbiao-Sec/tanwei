<script setup>import {
 computed, onMounted, ref
 } from 'vue'
import {
 useRoute, useRouter
 } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import {
 riskByTask, riskOverview
 } from '@/api/endpoints'
const route = useRoute()
const router = useRouter()
const mode = ref(route.query.task ? 'task' : 'all')
const taskId = ref(route.query.task || '')
const data = ref({
 total: 0, buckets: []
 })
const labels = ref({
})
const taskRows = ref([])
const loading = ref(false)
const RISK_ICON = {
  leak: 'file', git: 'github', bucket: 'layers', takeover: 'shield',  middleware: 'server', admin: 'key', api: 'terminal',
}
const buckets = computed(() => data.value.buckets || [])
const active = computed(() => buckets.value.filter((b) => b.count > 0))
const taskTotal = computed(() => taskRows.value.reduce((s, r) => s + (r.risky || 0), 0))
async function load() {
  loading.value = true
  try {    // 桶的名字和总量始终来自整体视图；按任务视图只额外拉「每趟侦察各有多少」
    const res = await riskOverview({
 task_id: taskId.value || undefined, limit: 8
 })
    data.value = {
 total: res.total || 0, buckets: res.buckets || []
 }
    labels.value = res.labels || {
}
    if (mode.value === 'task') {
      const rows = await riskByTask({
 limit: 300
 })
      taskRows.value = rows.items || []
    }
  } finally {
    loading.value = false
  }
}
function switchMode(m) {
  if (mode.value === m)
    return
  mode.value = m
  if (m === 'all')
    taskId.value = ''
  load()
}
function openTask(id) {
  taskId.value = id
  mode.value = 'task'
  load()
}
function openAssets(risk, task = '') {
  const q = {
}
  if (task || taskId.value)
 q.task = task || taskId.value
  if (risk)
 q.risk = risk
  router.push({
 path: '/assets', query: q
 })
}
function backTasks() {
  taskId.value = ''
  load()
}
const KIND_LABEL = {
 site: '站点', domain: '域名', ip: 'IP', service: '服务', leak: '泄露', leakfile: '泄露文件', codeleak: '代码泄露', git: 'Git', bucket: '存储桶', applet: '小程序', wxmp: '公众号', mobile: 'App', api: '接口', component: '组件', takeover: '子域接管'
 }
onMounted(load)</script><template>

  <div class="stack">
    <PageHead      title="脆弱资产"      desc="按风险桶归集：信息泄露 / 代码仓库 / 对象存储 / 中间件裸口 / 管理入口 / 敏感接口；整体与按任务两种看法"    >
      <template #actions>
        <div class="seg">
          <button :class="{ on: mode === 'all' }" @click="switchMode('all')">整体预览
</button>
          <button :class="{ on: mode === 'task' }" @click="switchMode('task')">按任务
</button>
        </div>
        <button class="btn sm" @click="load">

<Icon name="refresh" :size="13" />刷新
</button>      </template>    </PageHead>    <div class="metric-row">      <div class="metric">        <div class="metric-label">脆弱资产总量</div>        <div class="metric-value mono">{{ data.total.toLocaleString() }}</div>        <div class="metric-foot">{{ taskId ? '当前任务' : '全部任务' }} · 去重后条数</div>      </div>      <div v-for="b in buckets" :key="b.key" class="metric">        <div class="metric-label"><Icon :name="RISK_ICON[b.key] || 'alert'" :size="12" />{{ b.label }}</div>        <div class="metric-value mono">{{ b.count.toLocaleString() }}</div>        <div class="metric-foot">          <button class="link-btn" @click="openAssets(b.key)">查看资产</button>        </div>      </div>    </div>    <div v-if="mode === 'task'" class="panel">      <div class="panel-head">        <span><Icon name="tasks" :size="13" />按任务分隔</span>        <div class="flex gap-8">          <span class="mono muted" style="font-size: 10.5px">{{ taskRows.length }} 个任务 · 累计 {{ taskTotal.toLocaleString() }} 条（任务间有重复，去重后见上方总量）</span>          <button v-if="taskId" class="btn xs" @click="backTasks">看全部任务</button>        </div>      </div>      <div class="table-wrap">        <table class="table">          <thead>            <tr>              <th>任务</th><th>目标</th><th>脆弱</th>              <th v-for="b in buckets.length ? buckets : [{ key: 'leak', label: '信息泄露' }]" :key="b.key">{{ b.label }}</th>              <th></th>            </tr>          </thead>          <tbody>            <tr v-for="t in taskRows" :key="t.task_id" :class="{ 'row-on': t.task_id === taskId }">              <td class="ellipsis" style="max-width: 220px">                <button class="link-btn" :title="t.name" @click="openTask(t.task_id)">{{ t.name || t.task_id }}</button>                <div class="mono muted" style="font-size: 10px">{{ t.task_id }}</div>              </td>              <td class="ellipsis mono" style="max-width: 180px">{{ t.target }}</td>              <td class="mono">{{ (t.risky || 0).toLocaleString() }}</td>              <td v-for="b in (buckets.length ? buckets : [{ key: 'leak' }])" :key="b.key" class="mono">                <button class="link-btn num" :class="{ dim: !t[b.key] }" @click="openAssets(b.key, t.task_id)">                  {{ t[b.key] || 0 }}                </button>              </td>              <td style="text-align: right">                <button class="btn xs" @click="openAssets('', t.task_id)">资产库</button>              </td>            </tr>            <tr v-if="!taskRows.length && !loading">              <td colspan="12"><div class="empty"><Icon name="check" :size="22" />没有识别到脆弱资产的记录</div></td>            </tr>          </tbody>        </table>      </div>    </div>    <div v-if="taskId" class="scope-bar">      <span class="chip on">当前只看任务 <span class="mono">{{ taskId }}</span></span>      <button class="btn xs" @click="openAssets('')">看这个任务全部资产</button>    </div>    <div class="bucket-list">      <div v-for="b in (mode === 'task' && !taskId ? [] : active)" :key="b.key" class="panel">        <div class="panel-head">          <span><Icon :name="RISK_ICON[b.key] || 'alert'" :size="13" />{{ b.label }}<span class="mono muted" style="margin-left: 8px">{{ b.count.toLocaleString() }}</span></span>          <button class="btn xs" @click="openAssets(b.key)">全部 <Icon name="chevron" :size="10" /></button>        </div>        <div class="table-wrap">          <table class="table">            <thead><tr><th>资产</th><th>类型</th><th>标题</th><th>端口</th><th>指纹</th></tr></thead>            <tbody>              <tr v-for="s in b.samples" :key="s.id">                <td class="mono ellipsis" style="max-width: 340px" :title="s.url">                  <a v-if="String(s.url).startsWith('http')" :href="s.url" target="_blank" rel="noopener">{{ s.url }}</a>                  <span v-else>{{ s.url }}</span>                </td>                <td><span class="tag">{{ KIND_LABEL[s.kind] || s.kind }}</span></td>                <td class="ellipsis" style="max-width: 200px" :title="s.title">{{ s.title }}</td>                <td class="mono">{{ s.port || '-' }}</td>                <td class="ellipsis" style="max-width: 160px">{{ s.fingerprint }}</td>              </tr>            </tbody>          </table>        </div>      </div>      <div v-if="mode === 'all' && !active.length && !loading" class="panel">        <div class="panel-body"><div class="empty"><Icon name="shield" :size="22" />还没有识别到脆弱资产</div></div>      </div>    </div>  </div></template><style scoped>.link-btn {  border: 0;
 background: transparent;
 cursor: pointer;
 padding: 0;
  color: #8fe3d6;
 font-size: 11.5px;
 text-align: left;
}
.link-btn:hover { text-decoration: underline;
 }
.link-btn.dim { color: var(--muted-2);
 }
.link-btn.num { font-family: var(--mono);
 }
.row-on { background: rgba(52, 229, 200, 0.07);
 }
.scope-bar { display: flex;
 align-items: center;
 gap: 10px;
 }
.bucket-list { display: grid;
 grid-template-columns: 1fr;
 gap: 14px;
 }</style>