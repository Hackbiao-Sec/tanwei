<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { deleteSchedule, listSchedules, patchSchedule, presets as fetchPresets, saveSchedule } from '@/api/endpoints'

const router = useRouter()
const items = ref([])
const loading = ref(false)
const showForm = ref(false)
const presetList = ref([])
const form = reactive({
  name: '', target: '', interval_hours: 24, preset: 'standard',
  domain_brute: true, port_type: 'top100', site_spider: true, file_leak: true, sibling: true, deep: true,
  // 与一键下发对齐：周期任务同样能定企业主体、移动端、空间测绘、接管、ASN 与穿透口径
  enterprise: true, mobile: true, space_mapping: true, takeover: true, asn_expand: true, js_deep_scan: true,
  equity_ratio: 100, equity_ubo_threshold: 25,
})

const INTERVALS = [6, 12, 24, 72, 168]

async function load() {
  loading.value = true
  try {
    const res = await listSchedules()
    items.value = res.items || []
  } finally {
    loading.value = false
  }
}

async function toggle(s) {
  await patchSchedule(s.id, { enabled: s.enabled ? 0 : 1 })
  load()
}

async function changeInterval(s, hours) {
  await patchSchedule(s.id, { interval_hours: Number(hours) })
  load()
}

async function remove(s) {
  if (!confirm(`删除计划「${s.name}」？`)) return
  await deleteSchedule(s.id)
  load()
}

async function submit() {
  if (!form.target.trim()) return
  await saveSchedule({
    name: form.name.trim() || `周期-${form.target.split('\n')[0]}`,
    target: form.target,
    interval_hours: Number(form.interval_hours),
    options: {
      domain_brute: form.domain_brute,
      port_type: form.port_type,
      site_spider: form.site_spider,
      file_leak: form.file_leak,
      sibling: form.sibling,
      deep: form.deep,
      enterprise: form.enterprise,
      mobile: form.mobile,
      space_mapping: form.space_mapping,
      takeover: form.takeover,
      asn_expand: form.asn_expand,
      js_deep_scan: form.js_deep_scan,
      equity_ratio: Number(form.equity_ratio),
      equity_ubo_threshold: Number(form.equity_ubo_threshold),
    },
  })
  showForm.value = false
  form.name = ''
  form.target = ''
  load()
}

function fmtTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function countdown(ts) {
  if (!ts) return '—'
  const diff = ts * 1000 - Date.now()
  if (diff <= 0) return '待触发'
  const h = Math.floor(diff / 3600000)
  const m = Math.floor((diff % 3600000) / 60000)
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

onMounted(() => {
  load()
  fetchPresets().then((r) => { presetList.value = r.items || [] }).catch(() => {})
})
</script>

<template>
  <div class="stack">
    <PageHead title="计划与调度" desc="把资产组排成周期任务：每轮跑完自动做快照对比，只把新上线的资产推给你">
      <template #actions>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="13" />刷新</button>
        <button class="btn primary sm" @click="showForm = true"><Icon name="plus" :size="13" />新建计划</button>
      </template>
    </PageHead>

    <div class="panel">
      <div class="panel-head">
        <span><Icon name="clock" :size="13" />调度队列</span>
        <span class="mono muted">{{ items.filter((i) => i.enabled).length }} / {{ items.length }} 启用</span>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>状态</th><th>名称</th><th>目标</th><th>周期</th><th>上次执行</th><th>下次执行</th><th></th></tr></thead>
          <tbody>
            <tr v-for="s in items" :key="s.id">
              <td>
                <span class="switch" :class="{ on: s.enabled }" @click="toggle(s)" style="cursor: pointer" />
              </td>
              <td class="ellipsis" style="max-width: 220px; color: var(--text)">{{ s.name }}</td>
              <td class="mono ellipsis" style="max-width: 260px">{{ s.target }}</td>
              <td>
                <select class="select" style="height: 24px; width: 92px; font-size: 11px" :value="s.interval_hours" @change="changeInterval(s, $event.target.value)">
                  <option v-for="h in INTERVALS" :key="h" :value="h">{{ h >= 168 ? '每周' : h >= 24 ? `${h / 24} 天` : `${h} 小时` }}</option>
                </select>
              </td>
              <td class="mono muted">{{ fmtTime(s.last_run) }}</td>
              <td class="mono" :class="s.enabled ? '' : 'muted'">{{ s.enabled ? countdown(s.next_run) : '已暂停' }}</td>
              <td style="text-align: right; white-space: nowrap">
                <button class="btn xs" @click="router.push({ path: '/assets', query: { keyword: (s.target || '').split('\n')[0] } })">
                  <Icon name="search" :size="11" />资产
                </button>
                <button class="btn xs danger" style="margin-left: 4px" @click="remove(s)"><Icon name="trash" :size="11" /></button>
              </td>
            </tr>
            <tr v-if="!items.length && !loading">
              <td colspan="7"><div class="empty"><Icon name="clock" :size="22" />还没有计划任务，新建一个让资产自动滚动更新</div></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><span><Icon name="alert" :size="13" />变更监控说明</span></div>
      <div class="panel-body" style="font-size: 11.5px; color: var(--text-2); line-height: 1.9">
        每轮执行结束会为每个根域留一份资产快照（url 列表）。下一轮自动与之对比，把相对上轮新增的资产打上 NEW 标记，
        并在「仪表盘 / 资产组」显示新增数量。配置了 Webhook、钉钉、飞书或企业微信后，新增资产会直接推到群里。
      </div>
    </div>

    <div v-if="showForm" class="overlay" @click.self="showForm = false">
      <div class="modal">
        <div class="modal-head">
          <Icon name="clock" :size="15" style="color: var(--cyan)" />
          <span class="flex-1">新建周期计划</span>
          <button class="btn ghost sm" @click="showForm = false"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body stack" style="gap: 12px">
          <div class="field">
            <span class="field-label">计划名称</span>
            <input v-model="form.name" class="input" placeholder="例如：主域每日巡检" />
          </div>
          <div class="field">
            <span class="field-label">目标（一行一个，支持域名 / IP / 企业名）</span>
            <textarea v-model="form.target" class="textarea" style="min-height: 90px" placeholder="example.com&#10;example.cn" />
          </div>
          <div class="row">
            <div class="field" style="width: 140px">
              <span class="field-label">执行周期</span>
              <select v-model="form.interval_hours" class="select">
                <option v-for="h in INTERVALS" :key="h" :value="h">{{ h >= 168 ? '每周' : h >= 24 ? `${h / 24} 天` : `${h} 小时` }}</option>
              </select>
            </div>
            <div class="field" style="width: 150px">
              <span class="field-label">端口范围</span>
              <select v-model="form.port_type" class="select">
                <option value="enterprise">企业端口（90）</option>
                <option value="slim">精简端口（30）</option>
                <option value="top10">TOP 10</option>
                <option value="top100">TOP 100</option>
                <option value="top1000">TOP 1000</option>
                <option value="all">全端口</option>
              </select>
            </div>
          </div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px">
            <label class="opt"><span class="switch" :class="{ on: form.domain_brute }" @click="form.domain_brute = !form.domain_brute" />字典爆破</label>
            <label class="opt"><span class="switch" :class="{ on: form.site_spider }" @click="form.site_spider = !form.site_spider" />站点爬虫</label>
            <label class="opt"><span class="switch" :class="{ on: form.file_leak }" @click="form.file_leak = !form.file_leak" />敏感文件</label>
            <label class="opt"><span class="switch" :class="{ on: form.sibling }" @click="form.sibling = !form.sibling" />旁站 C 段</label>
            <label class="opt"><span class="switch" :class="{ on: form.deep }" @click="form.deep = !form.deep" />深度挖掘</label>
            <label class="opt"><span class="switch" :class="{ on: form.enterprise }" @click="form.enterprise = !form.enterprise" />企业主体</label>
            <label class="opt"><span class="switch" :class="{ on: form.mobile }" @click="form.mobile = !form.mobile" />小程序 / App</label>
            <label class="opt"><span class="switch" :class="{ on: form.space_mapping }" @click="form.space_mapping = !form.space_mapping" />空间测绘</label>
            <label class="opt"><span class="switch" :class="{ on: form.takeover }" @click="form.takeover = !form.takeover" />子域接管</label>
            <label class="opt"><span class="switch" :class="{ on: form.asn_expand }" @click="form.asn_expand = !form.asn_expand" />ASN 网段</label>
            <label class="opt"><span class="switch" :class="{ on: form.js_deep_scan }" @click="form.js_deep_scan = !form.js_deep_scan" />JS 深度分析</label>
          </div>
          <div class="row">
            <div class="field" style="width: 170px">
              <span class="field-label">控股门槛（%）</span>
              <input v-model.number="form.equity_ratio" class="input mono" type="number" min="0" max="100" />
            </div>
            <div class="field" style="width: 170px">
              <span class="field-label">实控线（%）</span>
              <input v-model.number="form.equity_ubo_threshold" class="input mono" type="number" min="0" max="100" />
            </div>
            <div class="field flex-1">
              <span class="field-label">穿透口径</span>
              <span class="field-hint">控股门槛决定收哪些子公司（100% 只收全资）；实控线是股东树逐级折算后的控制判定线，个股穿透常用 25%。</span>
            </div>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn sm" @click="showForm = false">取消</button>
          <button class="btn primary sm" @click="submit"><Icon name="check" :size="12" />保存计划</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.opt { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-2); cursor: pointer; }
</style>
