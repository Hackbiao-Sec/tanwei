<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import Icon from '@/components/Icon.vue'

const props = defineProps({
  kinds: { type: Array, default: () => [] },
  modules: { type: Array, default: () => [] },
  total: { type: Number, default: 0 },
  active: { type: Boolean, default: true },
})
const emit = defineEmits(['pick-kind'])

const donutEl = ref(null)
const barEl = ref(null)
let donut = null
let bar = null
let themeObs = null
let ro = null
let seq = 0
const tick = ref(0)

const empty = computed(() => !props.kinds.length && !props.modules.length)
const kindSum = computed(() => props.kinds.reduce((n, k) => n + (k.count || 0), 0))

function isLight() {
  return (document.documentElement.getAttribute('data-theme') || 'dark') === 'light'
}
function ink() {
  return isLight() ? '#102028' : '#e2f0f7'
}
function sub() {
  return isLight() ? '#63798a' : '#7d97a6'
}
function board() {
  return isLight() ? '#ffffff' : '#08121a'
}
function track() {
  return isLight() ? 'rgba(24, 62, 82, .07)' : 'rgba(120, 200, 220, .07)'
}

function donutOption() {
  const items = props.kinds.map((k) => ({
    name: k.label,
    value: k.count,
    itemStyle: { color: k.color },
  }))
  return {
    backgroundColor: 'transparent',
    animationDuration: 420,
    tooltip: {
      trigger: 'item',
      confine: true,
      backgroundColor: isLight() ? 'rgba(255,255,255,.97)' : 'rgba(8,18,27,.96)',
      borderColor: isLight() ? 'rgba(20,60,80,.16)' : 'rgba(52,229,200,.28)',
      textStyle: { color: isLight() ? '#1d2f3a' : '#d8eef5', fontSize: 12 },
      formatter: (p) => `${p.name}<br/><b>${p.value}</b> 条 · ${p.percent}%`,
    },
    title: {
      text: String(props.total || kindSum.value),
      subtext: '资产合计',
      left: '30%',
      top: '40%',
      textAlign: 'center',
      textStyle: {
        color: ink(), fontSize: 23, fontWeight: 600,
        fontFamily: 'JetBrains Mono, Cascadia Mono, Consolas, monospace',
      },
      subtextStyle: { color: sub(), fontSize: 11, lineHeight: 18 },
    },
    series: [{
      type: 'pie',
      radius: ['56%', '78%'],
      center: ['30%', '50%'],
      avoidLabelOverlap: true,
      label: { show: false },
      labelLine: { show: false },
      itemStyle: { borderColor: board(), borderWidth: 2, borderRadius: 3 },
      emphasis: {
        scaleSize: 6,
        itemStyle: { shadowBlur: 14, shadowColor: 'rgba(52, 229, 200, .32)' },
      },
      data: items,
    }],
  }
}

function barOption() {
  const rows = [...props.modules].reverse()
  const max = Math.max(1, ...rows.map((r) => r.assets || 0))
  return {
    backgroundColor: 'transparent',
    animationDuration: 420,
    grid: { left: 6, right: 46, top: 6, bottom: 4, containLabel: true },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      confine: true,
      backgroundColor: isLight() ? 'rgba(255,255,255,.97)' : 'rgba(8,18,27,.96)',
      borderColor: isLight() ? 'rgba(20,60,80,.16)' : 'rgba(52,229,200,.28)',
      textStyle: { color: isLight() ? '#1d2f3a' : '#d8eef5', fontSize: 12 },
      formatter: (ps) => {
        const i = ps[0]?.dataIndex ?? 0
        const r = rows[i] || {}
        return `${r.label || ''}<br/>本段入库 <b>${r.assets || 0}</b> 条<br/>状态 ${r.stateLabel || '—'}`
      },
    },
    xAxis: { type: 'value', max, show: false },
    yAxis: {
      type: 'category',
      data: rows.map((r) => r.label),
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: sub(), fontSize: 11, margin: 10 },
    },
    series: [
      {
        type: 'bar',
        silent: true,
        barWidth: 13,
        barGap: '-100%',
        z: 1,
        itemStyle: { color: track(), borderRadius: 7 },
        emphasis: { disabled: true },
        data: rows.map(() => max),
      },
      {
        type: 'bar',
        barWidth: 13,
        z: 2,
        itemStyle: { borderRadius: 7 },
        label: {
          show: true,
          position: 'right',
          distance: 8,
          color: sub(),
          fontSize: 11,
          fontFamily: 'JetBrains Mono, Consolas, monospace',
          formatter: (p) => (p.value ? String(p.value) : '—'),
        },
        data: rows.map((r) => ({
          value: r.assets || 0,
          itemStyle: { color: r.color },
        })),
      },
    ],
  }
}

function mount(el, prev) {
  const exist = echarts.getInstanceByDom(el)
  if (exist)
    return exist
  if (prev)
    prev.dispose()
  el.innerHTML = ''
  return echarts.init(el)
}

async function render() {
  if (empty.value)
    return
  const my = ++seq
  await nextTick()
  if (my !== seq)
    return
  const de = donutEl.value
  const be = barEl.value
  if (!de || !be)
    return
  donut = mount(de, donut)
  donut.setOption(donutOption(), true)
  donut.resize()
  bar = mount(be, bar)
  bar.setOption(barOption(), true)
  bar.resize()
}

watch(
  () => [props.kinds, props.modules, props.active, tick.value],
  () => {
    if (props.active)
      render()
  },
  { deep: false },
)

onMounted(() => {
  themeObs = new MutationObserver(() => {
    tick.value += 1
  })
  themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
  if (typeof ResizeObserver !== 'undefined') {
    ro = new ResizeObserver(() => {
      donut?.resize()
      bar?.resize()
    })
    if (donutEl.value)
      ro.observe(donutEl.value.parentElement)
  }
  render()
})

onBeforeUnmount(() => {
  themeObs?.disconnect()
  ro?.disconnect()
  donut?.dispose()
  bar?.dispose()
  donut = null
  bar = null
})
</script>

<template>
  <div class="oc-grid">
    <section class="panel oc-panel">
      <div class="panel-head">
        <span><Icon name="chart" :size="13" />资产构成</span>
        <span class="oc-note">点任一类跳到资产页</span>
      </div>
      <div class="panel-body oc-body">
        <div v-show="!empty" ref="donutEl" class="oc-donut" />
        <div v-if="kinds.length" class="oc-legend">
          <button
            v-for="k in kinds" :key="'ok-' + k.key"
            class="oc-lg" :title="`${k.label} ${k.count} 条`"
            @click="emit('pick-kind', k.key)"
          >
            <i :style="{ background: k.color }" />
            <span class="oc-lg-name">{{ k.label }}</span>
            <b class="mono">{{ k.count }}</b>
            <em class="mono">{{ k.pct.toFixed(1) }}%</em>
          </button>
        </div>
        <div v-else class="oc-empty">这趟还没有入库资产，去「阶段轨迹」看卡在哪一步</div>
      </div>
    </section>

    <section class="panel oc-panel">
      <div class="panel-head">
        <span><Icon name="layers" :size="13" />五段产出</span>
        <span class="oc-note">每段实际入库条数</span>
      </div>
      <div class="panel-body oc-body oc-body-bar">
        <div v-show="!empty" ref="barEl" class="oc-bar" />
        <div v-if="!modules.length" class="oc-empty">这个任务没有分段记录</div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.oc-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr);
  gap: 12px;
}
.oc-panel {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.oc-note {
  font-size: 10.5px;
  color: var(--muted-2);
  letter-spacing: 0.02em;
}
.oc-body {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 208px;
}
.oc-body-bar {
  align-items: stretch;
}
.oc-donut {
  flex: 0 0 44%;
  height: 196px;
  min-width: 0;
}
.oc-bar {
  flex: 1 1 auto;
  width: 100%;
  height: 196px;
  min-width: 0;
}
.oc-legend {
  flex: 1 1 auto;
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
  max-height: 200px;
  overflow-y: auto;
  padding-right: 2px;
}
.oc-lg {
  display: grid;
  grid-template-columns: 8px minmax(0, 1fr) auto 46px;
  align-items: center;
  gap: 8px;
  padding: 4px 6px;
  border-radius: 6px;
  border: 1px solid transparent;
  text-align: left;
  font-size: 11.5px;
  color: var(--text-2);
  transition: background 0.14s, border-color 0.14s, color 0.14s;
}
.oc-lg:hover {
  background: rgba(52, 229, 200, 0.07);
  border-color: var(--line);
  color: var(--text);
}
.oc-lg i {
  width: 8px;
  height: 8px;
  border-radius: 2px;
  box-shadow: 0 0 6px currentColor;
}
.oc-lg-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.oc-lg b {
  font-size: 11.5px;
  color: var(--text);
  font-weight: 500;
}
.oc-lg em {
  font-style: normal;
  font-size: 10.5px;
  color: var(--muted-2);
  text-align: right;
}
.oc-empty {
  flex: 1 1 auto;
  padding: 26px 4px;
  text-align: center;
  font-size: 12px;
  color: var(--muted);
}
@media (max-width: 900px) {
  .oc-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .oc-body {
    flex-wrap: wrap;
  }
  .oc-donut {
    flex: 1 1 100%;
  }
}
html[data-theme="light"] .oc-lg:hover {
  background: rgba(14, 155, 136, 0.08);
}
</style>
