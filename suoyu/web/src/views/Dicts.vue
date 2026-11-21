<script setup>
import { computed, onMounted, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { listDicts, readDict, createDict, saveDict, deleteDict, bindDict } from '@/api/endpoints'

const items = ref([])
const bindings = ref([])
const dirs = ref({ user: '', builtin: '' })
const loading = ref(false)
const error = ref('')
const notice = ref('')

// 编辑面板
const editor = ref({ open: false, name: '', source: '', text: '', mode: 'replace', busy: false, creating: false })
// 绑定下拉里可选的字典名
const names = computed(() => items.value.map((d) => d.name))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await listDicts()
    items.value = res.items || []
    bindings.value = res.bindings || []
    dirs.value = { user: res.user_dir || '', builtin: res.builtin_dir || '' }
  } catch (e) {
    error.value = e?.response?.data?.detail || e.message || '字典列表加载失败'
  } finally {
    loading.value = false
  }
}

function flash(msg) {
  notice.value = msg
  setTimeout(() => { if (notice.value === msg) notice.value = '' }, 3200)
}

async function openEdit(d) {
  error.value = ''
  editor.value = { open: true, name: d.name, source: d.source, text: '', mode: 'replace', busy: false, creating: false }
  try {
    const res = await readDict(d.name, { raw: 1 })
    editor.value.text = res.text || ''
    editor.value.source = res.source
  } catch (e) {
    error.value = e?.response?.data?.detail || '读取字典失败'
    editor.value.open = false
  }
}

function openNew() {
  error.value = ''
  editor.value = {
    open: true, name: '', source: '', text: '', mode: 'replace', busy: false, creating: true,
  }
}

async function submit() {
  const name = (editor.value.name || '').trim()
  if (!name) {
    error.value = '字典名不能为空'
    return
  }
  editor.value.busy = true
  error.value = ''
  try {
    if (editor.value.creating) {
      const res = await createDict({ name, content: editor.value.text })
      flash(`已新建 ${name}（${res.lines} 行）`)
    } else {
      const res = await saveDict(name, { content: editor.value.text, mode: editor.value.mode })
      flash(`已保存 ${name}（${res.lines} 行）`)
    }
    editor.value.open = false
    await load()
  } catch (e) {
    error.value = e?.response?.data?.detail || e.message || '保存失败'
  } finally {
    editor.value.busy = false
  }
}

function cleanUp() {
  // 前端先洗一遍：去空行、去注释、保序去重，省一次往返
  const seen = new Set()
  const out = []
  for (const raw of (editor.value.text || '').split('\n')) {
    const w = raw.trim()
    if (!w || w.startsWith('#') || seen.has(w)) continue
    seen.add(w)
    out.push(w)
  }
  editor.value.text = out.join('\n')
  flash(`已清洗：${out.length} 行`)
}

async function remove(d) {
  if (!confirm(`删除用户字典「${d.name}」？内置原件不会被删。`)) return
  error.value = ''
  try {
    const res = await deleteDict(d.name)
    flash(res.fallback_builtin ? `已删除用户覆盖，回落到内置 ${d.name}` : `已删除 ${d.name}`)
    await load()
  } catch (e) {
    error.value = e?.response?.data?.detail || '删除失败'
  }
}

async function doBind(b, name) {
  if (!name || name === b.current) return
  error.value = ''
  try {
    await bindDict(name, b.key)
    flash(`「${b.label}」已切换到 ${name}`)
    await load()
  } catch (e) {
    error.value = e?.response?.data?.detail || '绑定失败'
  }
}

function sizeText(n) {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}

onMounted(load)
</script>

<template>
  <div class="stack">
    <PageHead title="字典管理" desc="子域名爆破、敏感文件探测等采集字典集中管理；改过的字典写到 data/dicts，同名会覆盖内置那份，内置原件始终可回退">
      <template #actions>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="13" />刷新</button>
        <button class="btn primary sm" @click="openNew"><Icon name="plus" :size="13" />新建字典</button>
      </template>
    </PageHead>

    <div v-if="error" class="panel" style="border-color: rgba(255, 100, 112, 0.36)">
      <div class="panel-body" style="color: var(--red-ink); font-size: 12px">{{ error }}</div>
    </div>
    <div v-if="notice" class="panel">
      <div class="panel-body" style="color: var(--ok-text); font-size: 12px">{{ notice }}</div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <span><Icon name="control" :size="13" />采集绑定</span>
        <span class="mono muted">{{ bindings.length }}</span>
      </div>
      <div class="panel-body stack" style="gap: 10px">
        <div v-for="b in bindings" :key="b.key" class="bind-row">
          <div class="bind-text">
            <div class="bind-label">{{ b.label }}</div>
            <div class="bind-scene">{{ b.scene }}</div>
          </div>
          <select class="select" style="width: 260px" :value="b.current" @change="doBind(b, $event.target.value)">
            <option v-for="n in names" :key="n" :value="n">{{ n }}</option>
            <option v-if="b.current && !names.includes(b.current)" :value="b.current">{{ b.current }}（文件缺失）</option>
          </select>
          <span class="tag" :class="b.present ? (b.source === 'user' ? 'cyan' : 'info') : 'err'">
            {{ b.present ? (b.source === 'user' ? '用户覆盖' : '内置') : '缺失' }}
          </span>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <span><Icon name="file" :size="13" />字典文件</span>
        <span class="mono muted">{{ items.length }}</span>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>字典名</th>
              <th>用途</th>
              <th style="width: 90px">行数</th>
              <th style="width: 90px">大小</th>
              <th style="width: 150px">来源</th>
              <th>被引用</th>
              <th style="width: 150px"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in items" :key="d.name">
              <td style="color: var(--text)" class="mono">{{ d.name }}</td>
              <td>{{ d.label || '-' }}</td>
              <td class="mono">{{ d.lines }}</td>
              <td class="mono muted">{{ sizeText(d.bytes) }}</td>
              <td>
                <span class="tag" :class="d.source === 'user' ? 'cyan' : 'info'">
                  {{ d.source === 'user' ? (d.shadowed ? '用户覆盖 · 有内置同名' : '用户新建') : '内置' }}
                </span>
              </td>
              <td>
                <span v-for="b in d.bindings" :key="b" class="tag ok" style="margin-right: 4px">{{ b }}</span>
                <span v-if="!d.bindings.length" class="muted">-</span>
              </td>
              <td style="text-align: right; white-space: nowrap">
                <button class="btn xs" @click="openEdit(d)"><Icon name="terminal" :size="11" />编辑</button>
                <button v-if="d.source === 'user'" class="btn xs danger" style="margin-left: 4px" @click="remove(d)">
                  <Icon name="trash" :size="11" />
                </button>
              </td>
            </tr>
            <tr v-if="!items.length && !loading">
              <td colspan="7"><div class="empty"><Icon name="file" :size="22" />还没有字典文件</div></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="panel-body" style="padding-top: 0">
        <div class="muted mono" style="font-size: 10.5px; line-height: 1.7">
          用户目录：{{ dirs.user || '-' }}<br />
          内置目录：{{ dirs.builtin || '-' }}
        </div>
      </div>
    </div>

    <div v-if="editor.open" class="overlay" @click.self="editor.open = false">
      <div class="modal modal-lg">
        <div class="modal-head">
          <Icon name="file" :size="15" style="color: var(--cyan)" />
          <span class="flex-1">{{ editor.creating ? '新建字典' : `编辑 ${editor.name}` }}</span>
          <button class="btn ghost sm" @click="editor.open = false"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body stack" style="gap: 10px">
          <div v-if="editor.creating" class="field">
            <span class="field-label">字典名</span>
            <input v-model="editor.name" class="input mono" placeholder="例如：domain_extra.txt" />
            <span class="field-hint">字母、数字、下划线、点、横线，必须以 .txt 结尾；与内置同名即覆盖内置那份</span>
          </div>
          <div class="field">
            <span class="field-label">内容（一行一个词或路径）</span>
            <textarea v-model="editor.text" class="textarea mono" rows="18" spellcheck="false"
                      placeholder="www&#10;mail&#10;admin"></textarea>
            <span class="field-hint">
              当前 {{ (editor.text || '').split('\n').filter((x) => x.trim()).length }} 行 ·
              保存时自动去空行、去 # 注释、保序去重
            </span>
          </div>
          <div class="row" style="justify-content: space-between">
            <div class="row">
              <button class="btn sm" @click="cleanUp"><Icon name="refresh" :size="12" />清洗去重</button>
              <div v-if="!editor.creating" class="seg">
                <button :class="{ on: editor.mode === 'replace' }" @click="editor.mode = 'replace'">覆盖</button>
                <button :class="{ on: editor.mode === 'append' }" @click="editor.mode = 'append'">追加到末尾</button>
              </div>
            </div>
            <div class="row">
              <button class="btn sm" @click="editor.open = false">取消</button>
              <button class="btn primary sm" :disabled="editor.busy" @click="submit">
                <Icon name="check" :size="12" />{{ editor.busy ? '保存中…' : '保存' }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.bind-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.bind-text { min-width: 220px; flex: 1; }
.bind-label { font-size: 12.5px; color: var(--text); }
.bind-scene { font-size: 11px; color: var(--muted); margin-top: 2px; }
.modal-lg { width: min(860px, 94vw); }
</style>
