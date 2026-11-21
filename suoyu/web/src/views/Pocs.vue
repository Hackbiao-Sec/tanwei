<script setup>
import { onMounted, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { listTemplates, saveTemplate, deleteTemplate } from '@/api/endpoints'

const templates = ref([])
const loading = ref(false)
const showForm = ref(false)
const form = ref({ name: '', json: '' })
const error = ref('')

const DEFAULT_JSON = `{
  "domain_brute": true,
  "domain_dict": "domain_2w.txt",
  "port_type": "top100",
  "site_spider": true,
  "file_leak": true,
  "sibling": true,
  "deep": true,
  "vhost_collision": false
}`

async function load() {
  loading.value = true
  try {
    const res = await listTemplates()
    templates.value = (res.items || []).map((t) => ({ ...t, text: JSON.stringify(t.options || {}, null, 2) }))
  } finally {
    loading.value = false
  }
}

function openNew() {
  form.value = { name: '', json: DEFAULT_JSON }
  error.value = ''
  showForm.value = true
}

function edit(t) {
  form.value = { name: t.name, json: t.text }
  error.value = ''
  showForm.value = true
}

async function submit() {
  error.value = ''
  if (!form.value.name.trim()) {
    error.value = '模板名不能为空'
    return
  }
  let options
  try {
    options = JSON.parse(form.value.json)
  } catch (e) {
    error.value = `JSON 解析失败：${e.message}`
    return
  }
  await saveTemplate({ name: form.value.name.trim(), options })
  showForm.value = false
  load()
}

async function remove(t) {
  if (!confirm(`删除模板「${t.name}」？`)) return
  await deleteTemplate(t.name)
  load()
}

onMounted(load)
</script>

<template>
  <div class="stack">
    <PageHead title="模板与策略集" desc="把常用的扫描参数存成模板，一键套用到新任务；同一套参数也会被周期任务复用">
      <template #actions>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="13" />刷新</button>
        <button class="btn primary sm" @click="openNew"><Icon name="plus" :size="13" />新建模板</button>
      </template>
    </PageHead>

    <div class="panel">
      <div class="panel-head">
        <span><Icon name="file" :size="13" />任务参数模板</span>
        <span class="mono muted">{{ templates.length }}</span>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>模板名</th><th>参数</th><th style="width: 120px"></th></tr></thead>
          <tbody>
            <tr v-for="t in templates" :key="t.name">
              <td style="color: var(--text)">{{ t.name }}</td>
              <td>
                <pre class="mono" style="margin: 0; font-size: 10.5px; color: var(--muted); white-space: pre-wrap">{{ t.text }}</pre>
              </td>
              <td style="text-align: right; white-space: nowrap">
                <button class="btn xs" @click="edit(t)"><Icon name="terminal" :size="11" />编辑</button>
                <button class="btn xs danger" style="margin-left: 4px" @click="remove(t)"><Icon name="trash" :size="11" /></button>
              </td>
            </tr>
            <tr v-if="!templates.length && !loading">
              <td colspan="3"><div class="empty"><Icon name="file" :size="22" />还没有模板。新建一个保存你的常用参数组合</div></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="showForm" class="overlay" @click.self="showForm = false">
      <div class="modal">
        <div class="modal-head">
          <Icon name="file" :size="15" style="color: var(--cyan)" />
          <span class="flex-1">参数模板</span>
          <button class="btn ghost sm" @click="showForm = false"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body stack" style="gap: 10px">
          <div class="field">
            <span class="field-label">模板名</span>
            <input v-model="form.name" class="input" placeholder="例如：全量深挖" />
          </div>
          <div class="field">
            <span class="field-label">参数 JSON</span>
            <textarea v-model="form.json" class="textarea" style="min-height: 240px" spellcheck="false" />
            <span class="field-hint">可用键：domain_brute / domain_dict / port_type / port_custom / site_spider / file_leak / sibling / asn_expand / asn_scan_blocks / asn_block_limit / deep / vhost_collision / enterprise / fuzz_dict</span>
          </div>
          <div v-if="error" class="tag err" style="height: auto; padding: 6px 8px; white-space: normal">{{ error }}</div>
        </div>
        <div class="modal-foot">
          <button class="btn sm" @click="showForm = false">取消</button>
          <button class="btn primary sm" @click="submit"><Icon name="check" :size="12" />保存</button>
        </div>
      </div>
    </div>
  </div>
</template>
