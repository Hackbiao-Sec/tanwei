<script setup>import {
 computed, nextTick, onBeforeUnmount, onMounted, ref
 } from 'vue'
import {
 useRouter
 } from 'vue-router'
import * as echarts from 'echarts'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import {
 overview as fetchOverview, diff as fetchDiff
 } from '@/api/endpoints'
const router = useRouter()
const data = ref(null)
const added = ref([])
const loading = ref(true)
const trendEl = ref(null)
const portEl = ref(null)
const fpEl = ref(null)
let charts = []
const KIND_LABEL = {
  site: '站点', domain: '域名', ip: 'IP', service: '服务', port: '端口', cidr: 'C 段',  email: '邮箱', leak: '泄露', vuln: '漏洞', cert: '证书',  applet: '小程序', wxmp: '公众号', mobile: 'App', takeover: '子域接管',
  icp: '备案', enterprise: '企业', equity: '股权', branch: '分支机构', holds: '控股企业', invest: '对外投资', partner: '股东', copyright: '软著',
}
const metrics = computed(() => {
  const d = data.value
  if (!d)
 return []
  return [    {
 label: 'TOTAL ASSETS', value: d.total, foot: '全量资产', to: '/assets'
 },    {
 label: 'LIVE SITES', value: d.site, foot: '存活站点', to: '/assets?kind=site'
 },    {
 label: 'NEW · 24H', value: d.new_day, foot: '近 24 小时新增', to: '/assets?is_new=1'
 },    {
 label: 'ROOT DOMAINS', value: (d.top_roots || []).length, foot: '根域资产组', to: '/groups'
 },    {
 label: 'RUNNING', value: d.running, foot: '执行中任务', to: '/tasks'
 },  ]
})
const kindRows = computed(() => {
  const d = data.value
  if (!d)
 return []
  return Object.entries(d.by_kind || {
})    .map(([k, v]) => ({
 kind: k, label: KIND_LABEL[k] || k, count: v
 }))    .sort((a, b) => b.count - a.count)
})
const statusText = {
 running: '执行中', done: '已完成', stopped: '已停止', error: '异常', pending: '排队中'
 }
const statusClass = {
 running: 'cyan', done: 'ok', stopped: '', error: 'err', pending: 'warn'
 }
async function load() {
  loading.value = true
  try {
    const [ov, df] = await Promise.all([fetchOverview(), fetchDiff().
catch(() => ({
 items: []
 }))])
    data.value = ov
    added.value = (df.items || []).filter((x) => x.new_count > 0).slice(0, 6)
    loading.value = false    // 图表容器在数据回来后才渲染出来，必须等 DOM 挂载再 init
    await nextTick()
    render()
  } finally {
    loading.value = false
  }
}
function render() {
  charts.forEach((c) => c.dispose())
  charts = []
  const d = data.value
  if (!d)
 return
  if (trendEl.value) {
    const c = echarts.init(trendEl.value)
    c.setOption({
      grid: {
 left: 34, right: 12, top: 16, bottom: 24
 },      tooltip: {
 trigger: 'axis'
 },      xAxis: {
        type: 'category',        data: (d.trend || []).map((t) => t.day),        axisLine: {
 lineStyle: {
 color: 'rgba(115,196,214,.2)'
 }
 },        axisLabel: {
 color: '#77909f', fontSize: 10
 },
      },      yAxis: {
        type: 'value',        splitLine: {
 lineStyle: {
 color: 'rgba(115,196,214,.08)'
 }
 },        axisLabel: {
 color: '#77909f', fontSize: 10
 },
      },      series: [        {
          type: 'line',          smooth: true,          symbol: 'circle',          symbolSize: 5,          data: (d.trend || []).map((t) => t.count),          itemStyle: {
 color: '#34e5c8'
 },          lineStyle: {
 width: 2, color: '#34e5c8'
 },          areaStyle: {
            color: {
              type: 'linear', x: 0, y: 0, x2: 0, y2: 1,              colorStops: [                {
 offset: 0, color: 'rgba(52,229,200,.28)'
 },                {
 offset: 1, color: 'rgba(52,229,200,0)'
 },              ],
            },
          },
        },      ],
    })
    charts.push(c)
  }
  if (portEl.value) {
    const c = echarts.init(portEl.value)
    const ports = (d.top_ports || []).slice(0, 12)
    c.setOption({
      grid: {
 left: 46, right: 16, top: 12, bottom: 18
 },      tooltip: {
 trigger: 'axis'
 },      xAxis: {
        type: 'value',        splitLine: {
 lineStyle: {
 color: 'rgba(115,196,214,.08)'
 }
 },        axisLabel: {
 color: '#77909f', fontSize: 10
 },
      },      yAxis: {
        type: 'category',        inverse: true,        data: ports.map((p) => `${p.port}`),        axisLine: {
 lineStyle: {
 color: 'rgba(115,196,214,.2)'
 }
 },        axisLabel: {
 color: '#77909f', fontSize: 10, fontFamily: 'monospace'
 },
      },      series: [{
        type: 'bar',        data: ports.map((p) => p.count),        barWidth: 9,        itemStyle: {
 color: '#21b8a5', borderRadius: [0, 3, 3, 0]
 },
      }],
    })
    charts.push(c)
  }
  if (fpEl.value) {
    const c = echarts.init(fpEl.value)
    const items = (d.top_fingerprints || []).slice(0, 10)
    c.setOption({
      grid: {
 left: 8, right: 20, top: 12, bottom: 18, containLabel: true
 },      tooltip: {
 trigger: 'axis'
 },      xAxis: {
        type: 'value',        splitLine: {
 lineStyle: {
 color: 'rgba(115,196,214,.08)'
 }
 },        axisLabel: {
 color: '#77909f', fontSize: 10
 },
      },      yAxis: {
        type: 'category',        inverse: true,        data: items.map((i) => i.fingerprint),        axisLine: {
 lineStyle: {
 color: 'rgba(115,196,214,.2)'
 }
 },        axisLabel: {
 color: '#77909f', fontSize: 10
 },
      },      series: [{
        type: 'bar',        data: items.map((i) => i.count),        barWidth: 9,        itemStyle: {
 color: '#9d8cff', borderRadius: [0, 3, 3, 0]
 },
      }],
    })
    charts.push(c)
  }
}
function fmtTime(ts) {
  if (!ts)
 return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getMonth() + 1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}
function onResize() {
  charts.forEach((c) => c.resize())
}
onMounted(() => {
  load()
  window.addEventListener('resize', onResize)
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  charts.forEach((c) => c.dispose())
})</script><template>

  <div class="stack">
    <PageHead title="仪表盘" desc="全局侦察态势：资产规模、新增趋势、指纹分布与执行中任务">
      <template #actions>
        <button class="btn sm" @click="load">

<Icon name="refresh" :size="13" />刷新
</button>
        <button class="btn primary sm" @click="router.push('/oneclick')">
          <Icon name="bolt" :size="13" />一键收集全
        </button>      </template>    </PageHead>    <div v-if="loading && !data" class="metric-row">      <div v-for="i in 5" :key="i" class="skeleton" style="height: 78px" />    </div>    <template v-else>      <div class="metric-row">        <button          v-for="m in metrics"          :key="m.label"          class="metric clickable"          @click="router.push(m.to)"        >          <span class="metric-label">{{ m.label }}</span>          <span class="metric-value">{{ Number(m.value || 0).toLocaleString() }}</span>          <span class="metric-foot">{{ m.foot }}</span>        </button>      </div>      <div class="cards two">        <div class="panel">          <div class="panel-head">            <span><Icon name="chart" :size="13" />近 7 日资产入库趋势</span>            <span class="mono muted">assets / day</span>          </div>          <div ref="trendEl" style="height: 210px" />        </div>        <div class="panel">          <div class="panel-head">            <span><Icon name="layers" :size="13" />资产类型分布</span>            <router-link to="/assets" class="panel-link">资产搜索<Icon name="chevron" :size="10" /></router-link>          </div>          <div class="panel-body" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(104px, 1fr)); gap: 8px">            <div v-for="k in kindRows" :key="k.kind" class="metric" style="padding: 8px 10px">              <span class="metric-label">{{ k.kind }}</span>              <span class="metric-value" style="font-size: 19px">{{ k.count.toLocaleString() }}</span>              <span class="metric-foot">{{ k.label }}</span>            </div>          </div>        </div>      </div>      <div class="cards two">        <div class="panel">          <div class="panel-head"><span><Icon name="server" :size="13" />开放端口 TOP</span></div>          <div ref="portEl" style="height: 240px" />        </div>        <div class="panel">          <div class="panel-head"><span><Icon name="tags" :size="13" />指纹分布 TOP</span></div>          <div ref="fpEl" style="height: 240px" />        </div>      </div>      <div class="cards two">        <div class="panel">          <div class="panel-head">            <span><Icon name="tasks" :size="13" />最近任务</span>            <router-link to="/tasks" class="panel-link">全部任务<Icon name="chevron" :size="10" /></router-link>          </div>          <div class="table-wrap">            <table class="table">              <thead><tr><th>任务</th><th>状态</th><th>进度</th><th>时间</th></tr></thead>              <tbody>                <tr v-for="t in data?.recent_tasks || []" :key="t.id" style="cursor: pointer" @click="router.push(`/tasks/${t.id}`)">                  <td class="ellipsis" style="max-width: 260px">{{ t.name }}</td>                  <td><span class="tag" :class="statusClass[t.status]">{{ statusText[t.status] || t.status }}</span></td>                  <td style="width: 120px">                    <div class="progress"><i :style="{ width: (t.progress || 0) + '%' }" /></div>                  </td>                  <td class="mono muted">{{ fmtTime(t.created_at) }}</td>                </tr>                <tr v-if="!(data?.recent_tasks || []).length">                  <td colspan="4"><div class="empty">还没有任务，点右上「一键收集全」开始</div></td>                </tr>              </tbody>            </table>          </div>        </div>        <div class="panel">          <div class="panel-head">            <span><Icon name="flow" :size="13" />根域新增（最近一轮）</span>            <router-link to="/schedules" class="panel-link">周期监控<Icon name="chevron" :size="10" /></router-link>          </div>          <div class="panel-body">            <div v-if="!added.length" class="empty">              <Icon name="route" :size="22" />              <span>还没有变更快照。把同一目标排成周期任务，每轮会自动对比出新增资产。</span>            </div>            <div v-for="a in added" :key="a.root_domain" class="flex gap-8" style="padding: 6px 0; border-bottom: 1px solid var(--line-soft)">              <Icon name="target" :size="12" class="muted" />              <router-link :to="`/group/${a.root_domain}`" class="mono flex-1 ellipsis">{{ a.root_domain }}</router-link>              <span class="tag warn">+{{ a.new_count }}</span>              <span class="mono muted" style="font-size: 10.5px">{{ fmtTime(a.created_at) }}</span>            </div>          </div>        </div>      </div>    </template>  </div></template>