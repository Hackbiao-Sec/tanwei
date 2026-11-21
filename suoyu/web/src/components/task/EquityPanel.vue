<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import Icon from '@/components/Icon.vue'

const props = defineProps({
  trees: { type: Array, default: () => [] },
  taskId: { type: String, default: '' },
  active: { type: Boolean, default: false },
})

const idx = ref(0)
const inlineEl = ref(null)
const inlineWrap = ref(null)
const fullEl = ref(null)
const fullWrap = ref(null)
const full = ref(false)
const busy = ref('')
const outerH = ref(360)
const innerH = ref(360)
const fullOuterH = ref(560)
const fullInnerH = ref(560)
let chart = null
let fullChart = null
let themeObs = null
const themeTick = ref(0)

const cur = computed(() => props.trees[idx.value] || null)
const hasTree = computed(() => !!(cur.value?.tree && (cur.value.tree.children || []).length))

const SOURCE_LABEL = {
  aiqicha: '爱企查（主源）',
  tianyancha: '天眼查（主源）',
  xiaolanben: '小蓝本（辅助）',
  qichacha: '企查查',
  qcc: '企查查',
  backup: '工商辅助源',
  icp: '备案库（兜底）',
}
const STATUS_LABEL = {
  ok: '已取到数据',
  empty: '主体无数据',
  no_credential: '登录态无效（未配置或已过期）',
  not_found: '未检索到该主体',
  quota: '查询额度已用尽',
  blocked: '被风控 / 冷却中',
  error: '请求失败',
  skip: '主源已出数，本轮未调用',
}

// 深浅主题各一套节点色谱：浅色下亮青会发白，换成压暗的同一色相
const DARK_COLORS = ['#34e5c8', '#4fb6ff', '#9d8cff', '#f5b544', '#4ade80', '#ff6470', '#f08a4b', '#7d93a8']
const LIGHT_COLORS = ['#0e9b88', '#2f7ed8', '#7057e0', '#b87a0c', '#1f9d55', '#d64550', '#c2691a', '#5a7180']

function isLight() {
  return (document.documentElement.getAttribute('data-theme') || 'dark') === 'light'
}
function palette() {
  return isLight() ? LIGHT_COLORS : DARK_COLORS
}
function labelColor() {
  return isLight() ? '#1d2f3a' : '#cfe9f1'
}
function linkColor() {
  return isLight() ? 'rgba(14,155,136,0.42)' : 'rgba(52,229,200,0.45)'
}
// 累计比例达到门槛用主色、没达到用琥珀色，图上直接能分清「控股 / 参股」
function fullRatioColor() {
  return isLight() ? '#0b8a79' : '#5fe3cb'
}
function partRatioColor() {
  return isLight() ? '#a86a08' : '#f0b452'
}

function nodesOf(n) {
  if (!n)
    return 0
  return 1 + (n.children || []).reduce((s, c) => s + nodesOf(c), 0)
}
function depthOf(n) {
  if (!n)
    return 0
  const kids = n.children || []
  return 1 + kids.reduce((m, c) => Math.max(m, depthOf(c)), 0)
}
function shortName(s, max = 20) {
  const t = String(s || '')
  return t.length > max ? `${t.slice(0, max)}…` : t
}
// ECharts 的 truncate 会连整行尾部一起切掉，比例也会跟着消失。
// 这里先按像素预算截名字（中文按 1em、ASCII 按 0.56em 估），把比例留在可见范围内。
function fitName(s, maxPx, fs) {
  const t = String(s || '')
  let px = 0
  let i = 0
  for (; i < t.length; i++) {
    const w = /[\x00-\xff]/.test(t[i]) ? fs * 0.56 : fs
    if (px + w > maxPx)
      break
    px += w
  }
  return i >= t.length ? t : `${t.slice(0, Math.max(1, i - 1))}…`
}
function leafCount(n) {
  if (!n)
    return 0
  const kids = n.children || []
  return kids.length ? kids.reduce((s, c) => s + leafCount(c), 0) : 1
}
function treeHeight(tree) {
  // 树是按叶子均分纵轴的，按节点数算会留出一大截空白。
  // ECharts 在同一父节点相邻叶子间只留 1 份间隔、跨父节点留 2 份，
  // 所以实际行距会比「高度 / 叶子数」略小，按 30px 预留才不会让单行标签贴住。
  const rows = Math.max(1, leafCount(tree))
  return Math.min(4800, Math.max(420, rows * 30 + 70))
}
function toNode(n, d = 0, floor = 51) {
  const pal = palette()
  const color = pal[d % pal.length]
  const dom = (n.children || []).length
  const acc = n.acc ?? n.ratio ?? null
  // 没到门槛的子公司画空心，一眼区分「控股 / 参股」
  const thin = d > 0 && !dom && acc != null && acc < floor
  return {
    name: n.name,
    value: acc,
    ratio: n.ratio,
    acc: n.acc,
    depth: d,
    itemStyle: thin
      ? { color: 'transparent', borderColor: color, borderWidth: 1.8 }
      : { color, borderColor: color, borderWidth: d === 0 ? 2 : 1 },
    symbolSize: d === 0 ? 12 : dom ? 7 : thin ? 6 : 5.5,
    label: {
      color: labelColor(),
      fontSize: d === 0 ? 12.5 : 11,
      fontWeight: d === 0 ? 700 : 400,
    },
    children: (n.children || []).map((c) => toNode(c, d + 1, floor)),
  }
}

function treeOption(tree, roam = true) {
  const tot = nodesOf(tree)
  const fs = tot > 60 ? 10 : 11
  const floor = cur.value?.ratio_line ?? 51
  const ratioRich = {
    n: { color: labelColor() },
    vf: { color: fullRatioColor(), fontSize: Math.max(9.5, fs - 0.5), fontWeight: 600 },
    vp: { color: partRatioColor(), fontSize: Math.max(9.5, fs - 0.5) },
  }
  const leafPx = 300
  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      triggerOn: 'mousemove',
      confine: true,
      backgroundColor: isLight() ? 'rgba(255,255,255,.97)' : 'rgba(8,18,27,.96)',
      borderColor: isLight() ? 'rgba(20,60,80,.16)' : 'rgba(52,229,200,.28)',
      textStyle: { color: isLight() ? '#1d2f3a' : '#d8eef5', fontSize: 12 },
      formatter: (p) => {
        const d = (p.data && p.data.depth) || 0
        const own = p.data && p.data.ratio
        return `<b>${p.name}</b><br/>层级 ${d} · 累计 ${p.value == null ? '未知' : p.value + '%'}`
          + (own != null ? `<br/>直接持股 ${own}%` : '')
      },
    },
    series: [{
      type: 'tree',
      data: [toNode(tree, 0, floor)],
      orient: 'LR',
      left: 212,
      right: 420,
      top: 26,
      bottom: 26,
      roam,
      symbol: 'circle',
      initialTreeDepth: -1,
      expandAndCollapse: true,
      animationDuration: 220,
      label: {
        position: 'left',
        verticalAlign: 'middle',
        align: 'right',
        width: 208,
        overflow: 'truncate',
        fontSize: fs,
        // 根节点是穿透主体，名字要完整；中间层压到 13 字，比例永远露出来
        formatter: (p) => {
          if (p.data && p.data.depth === 0)
            return String(p.name || '')
          const nm = shortName(p.name, 13)
          if (p.value == null)
            return nm
          return `{n|${nm}}{${p.value >= floor ? 'vf' : 'vp'}| ${p.value}%}`
        },
        rich: { ...ratioRich },
      },
      leaves: {
        label: {
          position: 'right',
          align: 'left',
          verticalAlign: 'middle',
          width: leafPx,
          overflow: 'truncate',
          lineHeight: 13,
          fontSize: fs,
          // 叶子名字按像素预算先截，比例（含 % 号）始终留在行尾
          formatter: (p) => {
            const nm = fitName(p.name, leafPx - 48, fs)
            if (p.value == null)
              return nm
            return `{n|${nm}}{${p.value >= floor ? 'vf' : 'vp'}| ${p.value}%}`
          },
          rich: { ...ratioRich },
        },
      },
      lineStyle: { color: linkColor(), width: 1.2, curveness: 0.42 },
      emphasis: { focus: 'descendant' },
    }],
  }
}

const stat = computed(() => {
  const t = cur.value?.tree
  return {
    nodes: t ? nodesOf(t) - 1 : 0,
    depth: t ? depthOf(t) - 1 : 0,
    owned: (cur.value?.full_owned || []).length,
    source: cur.value?.source ? (SOURCE_LABEL[cur.value.source] || cur.value.source) : '无',
  }
})
const sourceChips = computed(() => {
  const st = cur.value?.source_status || {}
  return Object.entries(st)
    .filter(([, v]) => v !== 'skip')
    .map(([k, v]) => ({
      key: k,
      label: SOURCE_LABEL[k] || k,
      text: STATUS_LABEL[v] || v,
      bad: ['no_credential', 'quota', 'blocked', 'error', 'not_found'].includes(v),
    }))
})
const issue = computed(() => {
  const st = cur.value?.source_status || {}
  const codes = Object.values(st).filter((c) => c !== 'skip')
  const okSrc = Object.entries(st).filter(([, v]) => v === 'ok').map(([k]) => SOURCE_LABEL[k] || k)
  const childN = (cur.value?.full_owned || []).length
  const got = childN ? `本轮靠${okSrc.join('、') || '其余来源'}拿到 ${childN} 家达标子公司` : ''
  if (codes.includes('quota'))
    return `爱企查这轮额度用尽（登录态本身有效）；${got || '股权链路这轮被截断'}。额度按日恢复，次日或换账号重跑「股权穿透」这一阶段即可补全`
  if (codes.includes('blocked'))
    return '工商接口这一轮被风控，链路暂停；采集会自动拉长间隔，稍后重跑「股权穿透」阶段'
  if (codes.length && codes.every((c) => c === 'no_credential'))
    return '两家工商来源的登录态都不可用（未配置或 Cookie 已失效），只能按主体名往下采；到「设置 → 数据来源」重新取一份 Cookie 再重跑'
  return ''
})

// 后台标签页里浏览器会暂停 requestAnimationFrame，光等 rAF 会把图卡在初始化之前
function raf2() {
  return new Promise((resolve) => {
    let done = false
    const fin = () => {
      if (done)
        return
      done = true
      resolve()
    }
    requestAnimationFrame(() => requestAnimationFrame(fin))
    setTimeout(fin, document.visibilityState === 'hidden' ? 60 : 220)
  })
}
function centerScroll(el) {
  if (!el)
    return
  el.scrollTop = Math.max(0, Math.round((el.scrollHeight - el.clientHeight) / 2))
}

// 多个 watch 会并发触发渲染；没有令牌时两条协程都通过 `!chart` 检查，
// 同一容器上会叠两个实例（标签重影）。用序号让后发起的渲染独占。
let renderSeq = 0
let fullSeq = 0

function mount(el, prev) {
  const exist = echarts.getInstanceByDom(el)
  if (exist) {
    if (prev && prev !== exist)
      prev.dispose()
    // 被 dispose 的旧实例会留下一个空壳 div，顺手清掉
    for (const c of [...el.children])
      if (!c.children.length)
        c.remove()
    return exist
  }
  if (prev)
    prev.dispose()
  el.innerHTML = ''
  return echarts.init(el)
}

async function renderInline() {
  if (!props.active || !hasTree.value)
    return
  const my = ++renderSeq
  const tree = cur.value.tree
  const need = treeHeight(tree)
  innerH.value = need
  outerH.value = Math.min(need, 580)
  await nextTick()
  await raf2()
  if (my !== renderSeq)
    return
  const el = inlineEl.value
  if (!el)
    return
  chart = mount(el, chart)
  chart.setOption(treeOption(tree, false), true)
  chart.resize()
  centerScroll(inlineWrap.value)
}

function pick(i) {
  idx.value = i
  nextTick(renderInline)
}

async function openFull() {
  if (!hasTree.value)
    return
  const my = ++fullSeq
  full.value = true
  const need = treeHeight(cur.value.tree)
  fullInnerH.value = need
  fullOuterH.value = Math.round(Math.max(480, Math.min(window.innerHeight * 0.78, need)))
  await nextTick()
  await raf2()
  if (my !== fullSeq)
    return
  const el = fullEl.value
  if (!el)
    return
  fullChart = mount(el, fullChart)
  fullChart.setOption(treeOption(cur.value.tree, true), true)
  fullChart.resize()
  centerScroll(fullWrap.value)
}
function closeFull() {
  full.value = false
  fullSeq += 1
  fullChart?.dispose()
  fullChart = null
}

// ── 导出 ─────────────────────────────────────────
function themeBg() {
  return isLight() ? '#f5f8fa' : '#060b11'
}
function stamp() {
  const d = new Date()
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}`
}
function safeName(s) {
  return String(s || '主体').replace(/[\\/:*?"<>|\s]+/g, '_').slice(0, 40)
}
function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 2000)
}

// 导出用的画布单独建在屏幕外：当前没切到股权页、或没初始化过内联图，也能照样出图
async function exportPng() {
  if (!hasTree.value || busy.value)
    return
  busy.value = 'png'
  let box = null
  let inst = null
  try {
    const tree = cur.value.tree
    const rows = Math.max(1, nodesOf(tree) - 1)
    const w = 1500
    const h = Math.min(4200, Math.max(760, rows * 34 + 140))
    box = document.createElement('div')
    box.style.cssText = `position:fixed;left:-20000px;top:0;width:${w}px;height:${h}px;`
    document.body.appendChild(box)
    inst = echarts.init(box, null, { renderer: 'canvas' })
    inst.setOption(treeOption(tree, false), true)
    await raf2()
    inst.resize()
    const url = inst.getDataURL({ type: 'png', pixelRatio: 2, backgroundColor: themeBg() })
    const a = document.createElement('a')
    a.href = url
    a.download = `股权穿透_${safeName(cur.value.name)}_${stamp()}.png`
    a.click()
  } finally {
    inst?.dispose()
    box?.remove()
    busy.value = ''
  }
}

function flatten(n, parent = '', depth = 0, out = []) {
  out.push({
    name: n.name,
    parent,
    depth,
    ratio: n.ratio ?? '',
    acc: n.acc ?? n.ratio ?? '',
    children: (n.children || []).length,
  })
  for (const c of n.children || [])
    flatten(c, n.name, depth + 1, out)
  return out
}

function exportJson() {
  if (!cur.value)
    return
  const payload = {
    task_id: props.taskId,
    root: cur.value.name,
    source: cur.value.source || '',
    ratio_line: cur.value.ratio_line ?? null,
    depth: cur.value.depth ?? null,
    full_owned: cur.value.full_owned || [],
    holders: cur.value.holders || [],
    ubo: cur.value.ubo || null,
    tree: cur.value.tree || null,
    exported_at: new Date().toISOString(),
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' })
  saveBlob(blob, `股权穿透_${safeName(cur.value.name)}_${stamp()}.json`)
}

function exportCsv() {
  if (!hasTree.value)
    return
  const rows = flatten(cur.value.tree)
  const q = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`
  const lines = [['层级', '主体', '母公司', '直接持股%', '累计持股%', '子公司数'].map(q).join(',')]
  for (const r of rows)
    lines.push([r.depth, r.name, r.parent, r.ratio, r.acc, r.children].map(q).join(','))
  const blob = new Blob([`\uFEFF${lines.join('\r\n')}\r\n`], { type: 'text/csv;charset=utf-8' })
  saveBlob(blob, `股权穿透_${safeName(cur.value.name)}_${stamp()}.csv`)
}

let rzTimer = null
function onResize() {
  clearTimeout(rzTimer)
  rzTimer = setTimeout(() => {
    chart?.resize()
    fullChart?.resize()
  }, 120)
}

watch(() => props.active, (v) => {
  if (v)
    nextTick(renderInline)
})
watch(() => props.trees, () => {
  if (idx.value >= props.trees.length)
    idx.value = 0
  if (props.active)
    nextTick(renderInline)
}, { deep: false })
watch(cur, () => {
  if (props.active)
    nextTick(renderInline)
})
watch(themeTick, () => {
  if (props.active)
    nextTick(renderInline)
})

onMounted(() => {
  window.addEventListener('resize', onResize)
  themeObs = new MutationObserver(() => { themeTick.value += 1 })
  themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
  if (props.active)
    nextTick(renderInline)
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  themeObs?.disconnect()
  clearTimeout(rzTimer)
  chart?.dispose()
  fullChart?.dispose()
  chart = null
  fullChart = null
})
</script>

<template>
  <div class="eq">
    <div v-if="!trees.length" class="eq-empty">
      <Icon name="layers" :size="26" />
      <div class="eq-empty-t">这个任务还没有股权穿透结果</div>
      <div class="eq-empty-s">只有选了「主体穿透」这一阶段、并且工商来源取到数据，才会在这里出现树</div>
    </div>

    <template v-else>
      <div class="eq-bar">
        <div class="eq-chips">
          <button
            v-for="(t, i) in trees"
            :key="t.name"
            class="eq-chip"
            :class="{ on: idx === i }"
            :title="t.name"
            @click="pick(i)"
          >
            {{ t.name }}
            <b>{{ (t.full_owned || []).length }}</b>
          </button>
        </div>
        <div class="eq-actions">
          <button class="btn xs" :disabled="!hasTree" @click="openFull">
            <Icon name="external" :size="11" />放大
          </button>
          <button class="btn xs primary" :disabled="!hasTree || !!busy" @click="exportPng">
            <Icon name="download" :size="11" />{{ busy === 'png' ? '生成中' : '导出 PNG' }}
          </button>
          <button class="btn xs" :disabled="!hasTree" @click="exportCsv">
            <Icon name="file" :size="11" />CSV
          </button>
          <button class="btn xs" :disabled="!cur" @click="exportJson">
            <Icon name="file" :size="11" />JSON
          </button>
        </div>
      </div>

      <div class="eq-meta">
        <span class="eq-key">门槛 ≥{{ cur?.ratio_line ?? 100 }}%</span>
        <span class="eq-sep">·</span>
        <span class="eq-key">深度 {{ cur?.depth ?? '-' }}</span>
        <span class="eq-sep">·</span>
        <span class="eq-key">来源 {{ stat.source }}</span>
        <span v-if="cur?.partial" class="tag warn" style="margin-left: 6px">截断</span>
        <span class="eq-sep">·</span>
        <span class="eq-legend">
          <i class="eq-dot solid" />≥{{ cur?.ratio_line ?? 51 }}% 控股
          <i class="eq-dot hollow" />未达标
        </span>
      </div>

      <div class="eq-stats">
        <div class="eq-stat">
          <span class="eq-stat-l">穿透主体</span>
          <span class="eq-stat-v eq-name" :title="cur?.name">{{ cur?.name || '-' }}</span>
        </div>
        <div class="eq-stat">
          <span class="eq-stat-l">达标控股子公司</span>
          <span class="eq-stat-v">{{ stat.owned }}</span>
        </div>
        <div class="eq-stat">
          <span class="eq-stat-l">树节点</span>
          <span class="eq-stat-v">{{ stat.nodes }}</span>
        </div>
        <div class="eq-stat">
          <span class="eq-stat-l">最大层级</span>
          <span class="eq-stat-v">{{ stat.depth }}</span>
        </div>
      </div>

      <div v-if="hasTree" ref="inlineWrap" class="eq-wrap" :style="{ height: outerH + 'px' }">
        <div class="eq-inner" :style="{ height: innerH + 'px' }">
          <div ref="inlineEl" class="eq-chart" />
        </div>
      </div>
      <div v-else class="eq-empty small">
        <Icon name="layers" :size="20" />
        <div class="eq-empty-t">链路只到主体自己，没有拿到子公司的持股关系</div>
      </div>

      <div v-if="sourceChips.length" class="eq-tags">
        <span
          v-for="s in sourceChips"
          :key="s.key"
          class="tag"
          :class="s.bad ? 'warn' : 'ok'"
          :title="`${s.label}：${s.text}`"
        >{{ s.label }} · {{ s.text }}</span>
      </div>
      <div v-if="issue" class="eq-issue">{{ issue }}</div>

      <div v-if="(cur?.ubo?.holders || []).length" class="eq-block">
        <div class="eq-sub">最终受益人（累计持股 ≥{{ cur.ubo.threshold }}% 视为控制）</div>
        <div class="eq-tags">
          <span
            v-for="u in cur.ubo.holders.slice(0, 14)"
            :key="u.name"
            class="tag"
            :class="{ warn: u.control }"
            :title="(u.paths || []).join(' ｜ ')"
          >{{ u.name }}<i class="eq-dim"> · {{ u.ratio }}%</i><i v-if="u.control" class="eq-dim"> · 控制</i></span>
        </div>
      </div>

      <div v-if="(cur?.holders || []).length" class="eq-block">
        <div class="eq-sub">股东（{{ cur.holders.length }}）</div>
        <div class="eq-tags">
          <span v-for="h in cur.holders.slice(0, 20)" :key="h.name" class="tag">
            {{ h.name }}<i v-if="h.ratio != null" class="eq-dim"> · {{ h.ratio }}%</i>
          </span>
        </div>
      </div>

      <div v-if="(cur?.full_owned || []).length" class="eq-block">
        <div class="eq-sub">达标全资子公司（{{ cur.full_owned.length }}）</div>
        <div class="eq-tags">
          <span v-for="n in cur.full_owned.slice(0, 40)" :key="n" class="tag ok">{{ n }}</span>
          <span v-if="cur.full_owned.length > 40" class="tag">+{{ cur.full_owned.length - 40 }}</span>
        </div>
      </div>

      <div v-if="(cur?.notes || []).length" class="eq-note">{{ cur.notes.join('；') }}</div>
    </template>

    <div v-if="full" class="overlay" @click.self="closeFull">
      <div class="modal wide">
        <div class="modal-head">
          <Icon name="layers" :size="15" style="color: var(--cyan)" />
          <span class="flex-1 ellipsis">股权穿透图 · {{ cur?.name }}</span>
          <button class="btn xs primary" :disabled="!!busy" @click="exportPng">
            <Icon name="download" :size="11" />导出 PNG
          </button>
          <button class="btn ghost sm" @click="closeFull"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body">
          <div ref="fullWrap" class="eq-wrap" :style="{ height: fullOuterH + 'px' }">
            <div class="eq-inner" :style="{ height: fullInnerH + 'px' }">
              <div ref="fullEl" class="eq-chart" />
            </div>
          </div>
          <div class="eq-hint">滚轮缩放、拖拽平移，点节点可收起 / 展开子树；导出 PNG 按整棵树出图</div>
        </div>
        <div class="modal-foot">
          <button class="btn sm" @click="closeFull">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.eq { display: flex; flex-direction: column; gap: 10px; }
.eq-bar { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.eq-chips { display: flex; flex-wrap: wrap; gap: 6px; flex: 1 1 320px; min-width: 0; }
.eq-chip {
  display: inline-flex; align-items: center; gap: 6px;
  max-width: 260px; height: 27px; padding: 0 11px;
  border-radius: 999px; border: 1px solid var(--line);
  background: var(--surface-2); color: var(--text-2);
  font-size: 11.5px; font-family: inherit; cursor: pointer;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  transition: border-color .16s, background .16s, color .16s;
}
.eq-chip:hover { border-color: var(--line-strong); color: var(--text); }
.eq-chip.on { border-color: rgba(52, 229, 200, 0.6); background: rgba(52, 229, 200, 0.13); color: var(--cyan-ink); }
.eq-chip b {
  font-family: var(--mono); font-size: 10px; font-weight: 600;
  padding: 0 5px; height: 15px; line-height: 15px; border-radius: 5px;
  background: rgba(255, 255, 255, 0.07); color: var(--muted);
}
.eq-chip.on b { background: rgba(52, 229, 200, 0.2); color: var(--cyan-ink); }
.eq-actions { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.eq-actions .btn { white-space: nowrap; }

.eq-meta { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; font-size: 11px; color: var(--muted); }
.eq-key { font-family: var(--mono); }
.eq-legend { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; color: var(--muted); }
.eq-dot { width: 7px; height: 7px; border-radius: 50%; margin-left: 6px; display: inline-block; }
.eq-dot.solid { background: var(--cyan); box-shadow: 0 0 0 2px rgba(52, 229, 200, 0.16); }
.eq-dot.hollow { border: 1.5px solid var(--amber-ink); background: transparent; }
.eq-sep { color: var(--muted-2); }

.eq-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; }
.eq-stat {
  display: flex; flex-direction: column; gap: 3px;
  padding: 9px 11px; border-radius: var(--radius);
  border: 1px solid var(--line); background: var(--surface-2);
}
.eq-stat-l { font-size: 10.5px; color: var(--muted); letter-spacing: .04em; }
.eq-stat-v { font-size: 17px; font-weight: 600; color: var(--text); font-family: var(--mono); }
.eq-stat-v.eq-name { font-family: var(--sans); font-size: 13px; line-height: 1.4; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* 外壳定高滚动，内层张成整棵树；ECharts 会改写最里层容器的行内样式，高度只能挂中间层 */
.eq-wrap {
  width: 100%; overflow: auto;
  border: 1px solid var(--line); border-radius: 10px;
  background:
    radial-gradient(120% 120% at 0% 0%, rgba(52, 229, 200, 0.06), transparent 60%),
    var(--surface-2);
}
.eq-inner { width: 100%; min-width: 640px; }
.eq-chart { width: 100%; height: 100%; }
.eq-hint { margin-top: 8px; font-size: 11px; color: var(--muted); }

.eq-tags { display: flex; flex-wrap: wrap; gap: 5px; }
.eq-dim { font-style: normal; color: var(--muted); }
.eq-block { display: flex; flex-direction: column; gap: 5px; }
.eq-sub { font-size: 11px; letter-spacing: .05em; color: var(--muted); }
.eq-issue {
  font-size: 11.5px; line-height: 1.7; color: var(--amber-ink, #f0c274);
  padding: 7px 10px; border-radius: 8px;
  border: 1px solid rgba(245, 181, 68, 0.28); background: rgba(245, 181, 68, 0.08);
}
.eq-note { font-size: 11.5px; line-height: 1.7; color: var(--muted); }

.eq-empty {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 5px; padding: 34px 16px; text-align: center;
  border: 1px dashed var(--line-strong); border-radius: var(--radius);
  color: var(--muted);
}
.eq-empty svg { color: var(--muted-2); }
.eq-empty.small { padding: 20px 16px; }
.eq-empty-t { font-size: 12.5px; color: var(--text-2); }
.eq-empty-s { font-size: 11px; color: var(--muted-2); max-width: 460px; line-height: 1.7; }

:global(html[data-theme="light"]) .eq-chip.on { color: #0b7d6e; }
:global(html[data-theme="light"]) .eq-wrap { background: #f7fbfc; }
:global(html[data-theme="light"]) .eq-issue { color: #96660d; }
</style>
