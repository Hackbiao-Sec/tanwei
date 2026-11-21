<script setup>
// 跑起来以后的现场：现在走到哪一段、最近一句在查什么、进度、已经产出多少。
// 日志走 SSE 实时推，任务状态每 3 秒补一次；流断了也照样能看到进度，不会停在「执行中」。
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import Icon from '@/components/Icon.vue'
import { getTask, subscribeTask, taskLogs } from '@/api/endpoints'

const props = defineProps({
  taskId: { type: String, default: '' },
  // 这一轮要跑的几段 [{key,label}]，用来画「现在第几段」
  steps: { type: Array, default: () => [] },
  max: { type: Number, default: 1500 },
})
const emit = defineEmits(['done'])

const PHASE_LABEL = {
  P0: '目标归一',
  target_parse: '目标归一',
  enterprise: '工商主体',
  equity: '股权穿透',
  mobile: '移动端',
  P1: '企业主体',
  P1a: '股权穿透',
  P1b: '移动端',
  passive: '被动子域',
  brute: '字典爆破',
  port: '端口扫描',
  web: '存活探测',
  crawl: '站点爬虫',
  leak: '敏感文件',
  vhost: 'VHost',
  sibling: '旁站C段',
  deep: '深度挖掘',
  assetdiff: '资产变更',
  report: '汇总',
}
const KIND_LABEL = {
  site: '站点', domain: '域名', ip: 'IP', service: '服务', port: '端口', cidr: 'C段', email: '邮箱',
  leak: '泄露', equity: '股权', app: 'APP', applet: '小程序', wxmp: '公众号',
  enterprise: '企业', mailinfo: '邮箱信息', url: 'URL', takeover: '子域接管',
  mobile: 'APP安装包', api: '接口', component: '组件', js: 'JS', leakfile: '敏感文件',
  git: 'Git泄露', netblock: '网段', sibling: '旁站', icp: '备案', branch: '分支机构',
  holds: '控股企业', invest: '对外投资', partner: '股东', copyright: '软著',
  weibo: '微博', mobileapp: '企业APP', wechatoa: '企业公众号', job: '招聘岗位',
  supplier: '供应商',
}
const STATUS_TEXT = {
  pending: '排队中',
  running: '执行中',
  done: '已完成',
  stopped: '已停止',
  error: '异常',
}

const info = ref(null)
const logs = ref([])
const box = ref(null)
const elapsed = ref(0)
const finished = ref(false)
const streamClosed = ref(false)
const seen = new Set()
let closeStream = null
let tick = null
let poller = null

const status = computed(() => info.value?.status || '')
const statusText = computed(() => STATUS_TEXT[status.value] || status.value || '已提交')
const statusCls = computed(
  () => ({ done: 'ok', error: 'err', running: 'cyan', pending: 'warn' })[status.value] || '',
)
const alive = computed(() => ['pending', 'running', ''].includes(status.value) && !finished.value)
const pct = computed(() => {
  const p = Number(info.value?.progress)
  if (!Number.isFinite(p)) return 0
  return Math.max(0, Math.min(100, Math.round(p)))
})
const phaseLabel = computed(() => PHASE_LABEL[info.value?.phase] || info.value?.phase || '')
const elapsedText = computed(() => {
  const s = Math.max(0, Math.round(elapsed.value / 1000))
  return s >= 60 ? `${Math.floor(s / 60)} 分 ${String(s % 60).padStart(2, '0')} 秒` : `${s} 秒`
})
const kinds = computed(() => {
  const st = info.value?.stats
  if (!st || typeof st !== 'object') return []
  return Object.entries(st)
    .filter(([, v]) => Number(v) > 0)
    .map(([k, v]) => ({ kind: k, label: KIND_LABEL[k] || k, count: Number(v) }))
    .sort((a, b) => b.count - a.count)
})
const totalAssets = computed(() => kinds.value.reduce((n, k) => n + k.count, 0))
const lastMsg = computed(() => (logs.value.length ? logs.value[logs.value.length - 1] : null))
// 当前 phase 落在第几段：前面的标完成，当前的标亮
const stepRows = computed(() => {
  const steps = props.steps || []
  if (!steps.length) return []
  const cur = steps.findIndex((s) => s.key === info.value?.phase)
  return steps.map((s, i) => ({
    ...s,
    state: cur < 0 ? '' : i < cur ? 'done' : i === cur ? 'on' : '',
  }))
})

function hhmmss(ts) {
  const n = Number(ts) || 0
  if (!n) return ''
  const d = new Date(n > 1e12 ? n : n * 1000)
  return d.toLocaleTimeString('zh-CN', { hour12: false })
}

function scrollBottom() {
  const el = box.value
  if (el) el.scrollTop = el.scrollHeight
}

function pushLog(row) {
  if (!row || row.id === undefined || row.id === null) return
  if (seen.has(row.id)) return
  seen.add(row.id)
  logs.value.push(row)
  if (logs.value.length > props.max) logs.value.splice(0, logs.value.length - props.max)
}

function stop() {
  if (closeStream) {
    try {
      closeStream()
    } catch (e) {
      /* 关流失败不影响页面 */
    }
    closeStream = null
  }
  if (tick) {
    clearInterval(tick)
    tick = null
  }
  if (poller) {
    clearInterval(poller)
    poller = null
  }
}

function applyState(s) {
  if (!s) return
  const now = {
    ...(info.value || {}),
    status: s.status ?? info.value?.status,
    progress: s.progress ?? info.value?.progress,
    message: s.message ?? info.value?.message,
    phase: s.phase ?? info.value?.phase,
    stats: s.stats || info.value?.stats,
  }
  info.value = now
  if (['done', 'error', 'stopped'].includes(now.status)) finish()
}

function finish() {
  if (finished.value) return
  finished.value = true
  stop()
  emit('done', {
    status: info.value?.status,
    stats: info.value?.stats || {},
    total: totalAssets.value,
  })
}

async function poll() {
  if (!props.taskId) return
  try {
    const t = await getTask(props.taskId)
    info.value = t
    if (['done', 'error', 'stopped'].includes(t.status)) finish()
  } catch (e) {
    /* 这一轮没拉到，下一轮继续 */
  }
}

async function kick() {
  stop()
  info.value = null
  logs.value = []
  seen.clear()
  finished.value = false
  streamClosed.value = false
  elapsed.value = 0
  if (!props.taskId) return
  const t0 = Date.now()
  tick = setInterval(() => {
    if (alive.value) elapsed.value = Date.now() - t0
  }, 1000)
  // 先补一次已经落库的日志：从建任务到页面接上流之间那几句也不漏
  try {
    const res = await taskLogs(props.taskId, 0, 800)
    for (const row of res.items || []) pushLog(row)
    scrollBottom()
  } catch (e) {
    /* 拿不到历史就只靠流 */
  }
  await poll()
  if (alive.value) {
    try {
      closeStream = subscribeTask(props.taskId, (ev) => {
        if (ev.type === 'log') pushLog(ev.data)
        else if (ev.type === 'state') applyState(ev.data)
        else if (ev.type === 'stream-closed') streamClosed.value = true
      })
    } catch (e) {
      /* 流开不了就靠轮询 */
    }
  }
  if (!finished.value) poller = setInterval(poll, 3000)
}

watch(() => logs.value.length, () => scrollBottom())
watch(() => props.taskId, kick, { immediate: true })
onBeforeUnmount(stop)
</script>

<template>
  <div class="live">
    <div class="live-top">
      <span class="live-pulse" :class="{ on: alive }" />
      <span class="tag" :class="statusCls">{{ statusText }}</span>
      <span v-if="phaseLabel" class="tag info">{{ phaseLabel }}</span>
      <span class="live-msg ellipsis" :title="lastMsg?.msg || info?.message || ''">
        {{ lastMsg?.msg || info?.message || '已提交，等第一句日志…' }}
      </span>
      <span class="mono muted live-clock">{{ elapsedText }}</span>
    </div>

    <div class="live-bar"><i :style="{ width: pct + '%' }" /></div>

    <div class="live-meta">
      <span class="tag">{{ pct }}%</span>
      <span v-if="stepRows.length" class="live-steps">
        <span v-for="(s, i) in stepRows" :key="s.key" class="step" :class="s.state">
          <span class="step-no">{{ i + 1 }}</span>{{ s.label }}
        </span>
      </span>
      <span class="flex-1" />
      <span class="muted live-count">
        产出资产 <b class="mono">{{ totalAssets }}</b>
      </span>
      <router-link class="btn xs" :to="`/tasks/${taskId}`">
        <Icon name="external" :size="11" />任务详情
      </router-link>
    </div>

    <div v-if="kinds.length" class="live-kinds">
      <span v-for="k in kinds.slice(0, 16)" :key="k.kind" class="tag cyan">
        {{ k.label }} <span class="mono">{{ k.count }}</span>
      </span>
    </div>

    <div ref="box" class="logbox live-log">
      <div v-for="l in logs" :key="l.id" class="logline" :class="l.level">
        <span class="lt mono">{{ hhmmss(l.ts) }}</span>
        <span class="lm">{{ l.module }}</span>
        <span class="lx">{{ l.msg }}</span>
      </div>
      <div v-if="!logs.length" class="empty" style="padding: 14px">
        <Icon name="clock" :size="16" />{{ alive ? '正在排队，日志马上出现' : '这次没有日志' }}
      </div>
    </div>

    <span v-if="streamClosed && alive" class="field-hint">
      实时流已断开，进度改成每 3 秒问一次，结果不受影响。
    </span>
  </div>
</template>

<style scoped>
.live {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: rgba(6, 12, 18, 0.5);
}
.live-top {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.live-pulse {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--muted-2);
  flex: 0 0 auto;
}
.live-pulse.on {
  background: var(--cyan);
  box-shadow: 0 0 0 3px rgba(52, 229, 200, 0.16);
  animation: live-blink 1.4s ease-in-out infinite;
}
@keyframes live-blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}
.live-msg {
  flex: 1;
  min-width: 0;
  font-size: 12px;
  color: var(--text-2);
}
.live-clock {
  font-size: 11px;
  flex: 0 0 auto;
}
.live-bar {
  height: 4px;
  border-radius: 3px;
  background: rgba(120, 200, 220, 0.12);
  overflow: hidden;
}
.live-bar i {
  display: block;
  height: 100%;
  border-radius: 3px;
  background: linear-gradient(90deg, var(--cyan-2), var(--cyan));
  transition: width 0.4s ease;
}
.live-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.live-count {
  font-size: 11.5px;
}
.live-steps {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  flex-wrap: wrap;
}
.step {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 2px 8px 2px 3px;
  border-radius: 999px;
  border: 1px solid var(--line);
  font-size: 11px;
  color: var(--muted);
}
.step-no {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 15px;
  height: 15px;
  border-radius: 50%;
  background: rgba(120, 200, 220, 0.12);
  font-size: 9.5px;
  color: var(--muted);
}
.step.on {
  border-color: rgba(52, 229, 200, 0.5);
  background: rgba(52, 229, 200, 0.1);
  color: var(--cyan-ink);
}
.step.on .step-no {
  background: rgba(52, 229, 200, 0.28);
  color: var(--cyan-ink);
}
.step.done {
  border-color: var(--ok-line);
  color: var(--ok-text);
}
.step.done .step-no {
  background: var(--ok-bg);
  color: var(--ok-text);
}
.live-kinds {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.live-log {
  height: 240px;
  padding: 6px 2px 6px 6px;
}
.live-log .logline {
  padding: 1px 0;
}
</style>
