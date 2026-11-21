<script setup>
// 单跑一项的返回：先说这一枪调了哪几路来源、哪几路是死的，再把数据铺成表。
// 功能自检页里模块卡和底部工具都复用这一块，免得两处各写一遍还会长得不一样。
import { computed } from 'vue'

const props = defineProps({
  res: { type: Object, default: null },
})

const chanRows = computed(() => props.res?.sources || [])
const chanBad = computed(
  () => chanRows.value.filter((c) => ['dead', 'config'].includes(c.state)).length,
)

function chanCls(c) {
  if (c.state === 'dead') return 'err'
  if (c.state === 'config') return 'warn'
  if (c.state === 'ok') return 'ok'
  return ''
}

// 只把标量和小数组摊成标签：嵌套对象在这里说不出人话，留给原始结果
const metrics = computed(() => {
  const out = []
  const saved = props.res?.saved || {}
  for (const [k, v] of Object.entries(saved)) out.push({ label: `入库 ${k}`, value: `${v} 条` })
  const d = props.res?.result
  if (!d || typeof d !== 'object') return out
  for (const [k, v] of Object.entries(d)) {
    if (v === null || v === undefined) continue
    if (Array.isArray(v)) out.push({ label: k, value: `${v.length} 项` })
    else if (typeof v === 'object') continue
    else out.push({ label: k, value: String(v).slice(0, 60) })
  }
  return out.slice(0, 14)
})

const rowsView = computed(() => {
  const arr = props.res?.result?.items
  if (!Array.isArray(arr) || !arr.length) return null
  const first = arr[0]
  if (!first || typeof first !== 'object' || Array.isArray(first)) return null
  const cols = Object.keys(first).slice(0, 6)
  return {
    cols,
    rows: arr.slice(0, 200).map((r) =>
      cols.map((c) => {
        const v = r?.[c]
        if (v === null || v === undefined) return ''
        if (typeof v === 'object') return JSON.stringify(v).slice(0, 120)
        return String(v).slice(0, 160)
      }),
    ),
    total: arr.length,
  }
})

const resultJson = computed(() => {
  if (!props.res) return ''
  const txt = JSON.stringify(props.res.result, null, 2)
  return txt.length > 40000 ? `${txt.slice(0, 40000)}\n…（已截断，共 ${txt.length} 字符）` : txt
})
</script>

<template>
  <div v-if="res" class="od stack" style="gap: 8px">
    <div class="row" style="gap: 10px; align-items: center">
      <span class="tag ok">请求已返回</span>
      <span class="muted mono" style="font-size: 11.5px">耗时 {{ res.elapsed_ms }} ms</span>
    </div>

    <div v-if="metrics.length" class="od-chips">
      <span v-for="m in metrics" :key="m.label" class="tag">
        {{ m.label }}: <span class="mono">{{ m.value }}</span>
      </span>
    </div>

    <div v-if="chanRows.length" class="od-chan">
      <span class="muted" style="font-size: 11px">
        数据渠道 {{ chanRows.length }} 路<span v-if="chanBad"> · 失效 {{ chanBad }}</span>
      </span>
      <div class="table-wrap" style="max-height: 200px">
        <table class="table">
          <thead>
            <tr><th>渠道</th><th>状态</th><th>条数</th><th>说明</th></tr>
          </thead>
          <tbody>
            <tr v-for="c in chanRows" :key="c.source">
              <td>
                {{ c.label }}
                <span class="mono muted" style="margin-left: 6px; font-size: 10.5px">{{ c.source }}</span>
              </td>
              <td><span class="tag" :class="chanCls(c)">{{ c.status_text }}</span></td>
              <td class="mono">{{ c.items || '-' }}</td>
              <td class="ellipsis muted" style="max-width: 260px" :title="c.note">{{ c.note }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="rowsView" class="table-wrap" style="max-height: 300px">
      <table class="table">
        <thead>
          <tr><th v-for="c in rowsView.cols" :key="c">{{ c }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="(r, i) in rowsView.rows" :key="i">
            <td v-for="(cell, j) in r" :key="j" class="ellipsis" style="max-width: 260px">{{ cell }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="rowsView" class="muted" style="font-size: 11.5px">
      共 {{ rowsView.total }} 条，表格最多展示 200 行
    </div>

    <details v-if="resultJson" class="od-json">
      <summary class="muted">原始返回</summary>
      <pre class="od-pre">{{ resultJson }}</pre>
    </details>
  </div>
</template>

<style scoped>
.od-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.od-chan { display: flex; flex-direction: column; gap: 4px; }
.od-json { margin: 0; }
.od-pre {
  margin: 6px 0 0; padding: 10px; max-height: 320px; overflow: auto;
  background: rgba(0, 0, 0, 0.28); border-radius: 6px;
  font: 11.5px/1.6 ui-monospace, Consolas, monospace; color: var(--text-2);
  white-space: pre-wrap; word-break: break-all;
}
</style>
