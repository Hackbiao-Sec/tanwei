<script setup>import {
 computed, onMounted, ref
 } from 'vue'
import {
 useRoute, useRouter
 } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import {
 diff as fetchDiff, listAssets, presets as fetchPresets
 } from '@/api/endpoints'
const route = useRoute()
const router = useRouter()
const root = computed(() => String(route.params.root))
const items = ref([])
const total = ref(0)
const loading = ref(false)
const kind = ref('')
const change = ref(null)
const KIND_LABEL = {
 site: '站点', domain: '域名', ip: 'IP', service: '服务', port: '端口', cidr: 'C 段', email: '邮箱', leak: '泄露', vuln: '漏洞', takeover: '子域接管',
 icp: '备案', enterprise: '企业', equity: '股权', branch: '分支机构', holds: '控股企业', invest: '对外投资', partner: '股东', copyright: '软著', applet: '小程序', wxmp: '公众号', mobile: 'APP',
 applet_icp: '小程序备案', applet_hint: '小程序线索',
 }
const kinds = computed(() => {
  const map = {
}
  for (const a of items.value)
 map[a.kind] = (map[a.kind] || 0) + 1
  return Object.entries(map).map(([k, v]) => ({
 kind: k, count: v
 })).sort((a, b) => b.count - a.count)
})
const shown = computed(() => (kind.value ? items.value.filter((a) => a.kind === kind.value) : items.value))
const newCount = computed(() => items.value.filter((a) => a.is_new).length)
const ips = computed(() => new Set(items.value.filter((a) => a.ip && !a.cdn).map((a) => a.ip)).size)
async function load() {
  loading.value = true
  try {
    const [res, df] = await Promise.all([      listAssets({
 root_domain: root.value, limit: 2000
 }),      fetchDiff(root.value).
catch(() => ({
 items: []
 })),    ])
    items.value = res.items || []
    total.value = res.total || items.value.length
    change.value = (df.items || [])[0] || null
  } finally {
    loading.value = false
  }
}
async function recollect() {
  const list = await fetchPresets().
catch(() => ({
 items: []
 }))
  const standard = (list.items || []).find((p) => p.key === 'standard')
  const http = (await import('@/api/http')).default
  const res = await http.post('/api/tasks', {
    targets: [root.value],    name: `资产组重扫-${root.value}`,    options: standard?.options || {
},
  })
  if (res?.task_id)
 router.push(`/tasks/${res.task_id}`)
}
function fmtTime(ts) {
  if (!ts)
 return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}
onMounted(load)</script><template>

  <div class="stack">
    <PageHead :title="`资产组 · ${root}`" desc="这个根域下的全部资产、端口与站点，以及最近一轮对比出的新增">
      <template #actions>
        <button class="btn sm" @click="router.push('/groups')">

<Icon name="chevron" :size="12" />返回资产组
</button>
        <button class="btn sm" @click="load">

<Icon name="refresh" :size="12" />刷新
</button>
        <button class="btn primary sm" @click="recollect">

<Icon name="bolt" :size="12" />重扫本组
</button>      </template>    </PageHead>    <div class="metric-row">      <div class="metric">        <span class="metric-label">ASSETS</span><span class="metric-value">{{ total.toLocaleString() }}</span><span class="metric-foot">组内资产</span>      </div>      <div class="metric">        <span class="metric-label">IPS</span><span class="metric-value">{{ ips }}</span><span class="metric-foot">非 CDN 独立 IP</span>      </div>      <div class="metric">        <span class="metric-label">NEW</span><span class="metric-value">{{ change?.new_count || newCount }}</span><span class="metric-foot">最近一轮新增</span>      </div>      <div class="metric">        <span class="metric-label">LAST DIFF</span>        <span class="metric-value" style="font-size: 15px">{{ fmtTime(change?.created_at) }}</span>        <span class="metric-foot">变更快照时间</span>      </div>    </div>    <div v-if="change?.items?.length" class="panel">      <div class="panel-head"><span><Icon name="flow" :size="13" />最近新增资产</span><span class="tag warn">+{{ change.new_count }}</span></div>      <div class="panel-body">        <div v-for="(u, i) in change.items.slice(-20).reverse()" :key="i" class="mono ellipsis" style="font-size: 11.5px; color: var(--text-2); padding: 2px 0">          {{ u }}        </div>      </div>    </div>    <div class="row">      <button class="btn xs" :class="{ primary: kind === '' }" @click="kind = ''">全部 {{ items.length }}</button>      <button v-for="k in kinds" :key="k.kind" class="btn xs" :class="{ primary: kind === k.kind }" @click="kind = k.kind">        {{ KIND_LABEL[k.kind] || k.kind }} {{ k.count }}      </button>    </div>    <div class="panel">      <div class="table-wrap">        <table class="table">          <thead><tr><th>类型</th><th>地址</th><th>标题</th><th>状态</th><th>IP</th><th>端口</th><th>指纹</th><th>服务器</th><th>来源</th><th>最近</th></tr></thead>          <tbody>            <tr v-for="a in shown" :key="a.id">              <td><span class="tag">{{ KIND_LABEL[a.kind] || a.kind }}</span></td>              <td class="mono cell-url" :title="a.url">                <a :href="a.url.startsWith('http') ? a.url : undefined" target="_blank" rel="noopener">{{ a.url }}</a>                <span v-if="a.is_new" class="tag warn" style="margin-left: 6px">NEW</span>              </td>              <td class="ellipsis" style="max-width: 220px" :title="a.title">{{ a.title }}</td>              <td class="mono">{{ a.status_code || '-' }}</td>              <td class="mono">{{ a.ip }}</td>              <td class="mono">{{ a.port || '-' }}</td>              <td class="ellipsis" style="max-width: 180px">{{ a.fingerprint }}</td>              <td class="ellipsis" style="max-width: 110px">{{ a.server }}</td>              <td class="muted ellipsis" style="max-width: 140px">{{ a.sources }}</td>              <td class="mono muted">{{ fmtTime(a.last_seen) }}</td>            </tr>            <tr v-if="!shown.length && !loading">              <td colspan="10"><div class="empty"><Icon name="group" :size="22" />这个根域下暂无资产</div></td>            </tr>          </tbody>        </table>      </div>    </div>  </div></template>