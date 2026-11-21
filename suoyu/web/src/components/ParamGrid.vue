<script setup>
// 参数网格：整段流程和单项查询共用一套，只按后端给的参数表铺控件。
// 常用项直接摆出来，标了 adv 的调优项收进「高级参数」。
import { computed, ref, watch } from 'vue'
import Icon from '@/components/Icon.vue'

const props = defineProps({
  params: { type: Array, default: () => [] },
  model: { type: Object, required: true },
})
const emit = defineEmits(['reset'])

const showAdv = ref(false)
const common = computed(() => (props.params || []).filter((p) => !p.adv))
const adv = computed(() => (props.params || []).filter((p) => p.adv))
const rows = computed(() => {
  const out = common.value.map((p) => ({ p, head: false }))
  if (showAdv.value) adv.value.forEach((p, i) => out.push({ p, head: i === 0 }))
  return out
})

function set(p, v) {
  props.model[p.key] = v
}
function str(p) {
  const v = props.model[p.key]
  return v === undefined || v === null ? '' : String(v)
}
function arrText(p) {
  const v = props.model[p.key]
  return Array.isArray(v) ? v.join(',') : str(p)
}
function picked(p, value) {
  const v = props.model[p.key]
  if (Array.isArray(v)) return v.map(String).includes(String(value))
  return String(v ?? '') === String(value)
}
function toggle(p, value) {
  const cur = Array.isArray(props.model[p.key]) ? [...props.model[p.key]] : []
  const i = cur.map(String).indexOf(String(value))
  if (i >= 0) cur.splice(i, 1)
  else cur.push(value)
  set(p, cur)
}
function splitTo(p, text) {
  set(p, String(text || '').split(',').map((x) => x.trim()).filter(Boolean))
}

// 换了一项功能，高级区自动收起，免得上一个功能的调优项摊在眼前
watch(() => props.params, () => { showAdv.value = false })
</script>

<template>
  <div v-if="rows.length" class="pgrid-wrap">
    <div class="pgrid-head">
      <span class="muted">
        参数 {{ common.length }} 项
        <template v-if="adv.length"> · 调优 {{ adv.length }} 项</template>
        ，不填就用全局配置里的同名值
      </span>
      <span class="flex-1" />
      <button
        v-if="adv.length"
        class="btn xs"
        :class="{ primary: showAdv }"
        @click="showAdv = !showAdv"
      >
        <Icon name="chevron" :size="11" />{{ showAdv ? '收起调优项' : `调优项（${adv.length}）` }}
      </button>
      <button class="btn xs" @click="emit('reset')">
        <Icon name="refresh" :size="11" />恢复默认
      </button>
    </div>

    <div class="pgrid">
      <template v-for="row in rows" :key="row.p.key">
        <div v-if="row.head" class="pgrid-sep">调优项 · 超时 / 并发 / 各类上限，一般不用动</div>
        <div class="pgrid-cell" :class="{ wide: row.p.type === 'multi' || row.p.type === 'textarea' }">
          <span class="pgrid-label" :title="row.p.help || ''">{{ row.p.label }}</span>

          <select
            v-if="row.p.type === 'select' && (row.p.options || []).length"
            class="select"
            :value="str(row.p)"
            @change="set(row.p, $event.target.value)"
          >
            <option v-for="o in row.p.options" :key="o.value" :value="o.value">{{ o.label }}</option>
          </select>

          <div v-else-if="row.p.type === 'multi'" class="pgrid-multi">
            <template v-if="(row.p.options || []).length">
              <button
                v-for="o in row.p.options"
                :key="o.value"
                class="pgrid-chip"
                :class="{ on: picked(row.p, o.value) }"
                :title="o.label"
                @click="toggle(row.p, o.value)"
              >
                {{ o.label }}
              </button>
            </template>
            <input
              v-else
              class="input"
              :value="arrText(row.p)"
              placeholder="多个用逗号分隔"
              @input="splitTo(row.p, $event.target.value)"
            />
          </div>

          <textarea
            v-else-if="row.p.type === 'textarea'"
            class="textarea"
            rows="2"
            :value="str(row.p)"
            :placeholder="row.p.help || ''"
            @input="set(row.p, $event.target.value)"
          />

          <input
            v-else-if="row.p.type === 'number'"
            class="input"
            type="number"
            :value="str(row.p)"
            :min="row.p.min"
            :max="row.p.max"
            :title="row.p.help || ''"
            @input="set(row.p, $event.target.value)"
          />

          <input
            v-else-if="row.p.type === 'text' || row.p.type === 'select'"
            class="input"
            :value="str(row.p)"
            :placeholder="row.p.help || ''"
            @input="set(row.p, $event.target.value)"
          />

          <span
            v-else
            class="switch"
            :class="{ on: props.model[row.p.key] }"
            :title="row.p.help || ''"
            @click="set(row.p, !props.model[row.p.key])"
          />
        </div>
      </template>
    </div>
  </div>
</template>

<style scoped>
.pgrid-wrap {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.pgrid-head {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11px;
}
.pgrid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(214px, 1fr));
  gap: 8px 14px;
}
.pgrid-cell {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.pgrid-cell.wide {
  grid-column: 1 / -1;
  align-items: flex-start;
}
.pgrid-label {
  flex: 0 0 84px;
  font-size: 11.5px;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.pgrid-cell .input,
.pgrid-cell .select,
.pgrid-cell .textarea {
  flex: 1;
  min-width: 0;
}
.pgrid-sep {
  grid-column: 1 / -1;
  margin-top: 4px;
  padding-top: 8px;
  border-top: 1px dashed rgba(255, 255, 255, 0.1);
  font-size: 10.5px;
  color: var(--muted);
}
.pgrid-multi {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  flex: 1;
  min-width: 0;
  align-items: center;
}
.pgrid-chip {
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(255, 255, 255, 0.04);
  color: var(--text-2);
  font-size: 11px;
  line-height: 1.6;
}
.pgrid-chip:hover {
  border-color: rgba(52, 229, 200, 0.45);
}
.pgrid-chip.on {
  background: rgba(52, 229, 200, 0.16);
  border-color: rgba(52, 229, 200, 0.5);
  color: var(--cyan-ink);
}
</style>
