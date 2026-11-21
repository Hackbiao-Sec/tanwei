<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { addFingerprint, deleteFingerprint, listFingerprints, verifyFingerprint } from '@/api/endpoints'

const tab = ref('tpl')
const builtin = ref([])
const templates = ref([])
const custom = ref([])
const builtinTotal = ref(0)
const templateTotal = ref(0)
const templateAll = ref(0)
const tplStats = ref({})
const tags = ref([])
const keyword = ref('')
const tag = ref('')
const offset = ref(0)
const limit = 60
const loading = ref(false)
const showForm = ref(false)
const form = reactive({ name: '', keyword: '', cms: '', body: '', header: '', server: '', tag: '', note: '' })
const verifyUrl = ref('')
const verifyResult = ref(null)

const matcherTypes = computed(() => {
  const m = tplStats.value?.matchers || {}
  return Object.entries(m).map(([k, v]) => ({ kind: k, count: v }))
})
const pages = computed(() => Math.max(1, Math.ceil(templateTotal.value / limit)))
const page = computed(() => Math.floor(offset.value / limit) + 1)

async function load(reset = true) {
  if (reset) offset.value = 0
  loading.value = true
  try {
    const res = await listFingerprints({
      keyword: keyword.value.trim() || undefined,
      tag: tag.value || undefined,
      limit,
      offset: offset.value,
    })
    builtin.value = res.builtin || []
    builtinTotal.value = res.builtin_total || 0
    templates.value = res.templates || []
    templateTotal.value = res.template_total || 0
    templateAll.value = res.template_all || 0
    tplStats.value = res.tpl_stats || {}
    tags.value = res.tags || []
    custom.value = res.custom || []
  } finally {
    loading.value = false
  }
}

function pickTag(t) {
  tag.value = tag.value === t ? '' : t
  load()
}

function goPage(n) {
  offset.value = (n - 1) * limit
  load(false)
}

async function submit() {
  if (!form.name.trim()) return
  await addFingerprint({ ...form })
  Object.assign(form, { name: '', keyword: '', cms: '', body: '', header: '', server: '', tag: '', note: '' })
  showForm.value = false
  load()
}

async function remove(f) {
  if (!confirm(`删除自定义指纹「${f.name}」？`)) return
  await deleteFingerprint(f.name)
  load()
}

async function verify() {
  verifyResult.value = null
  if (!verifyUrl.value.trim()) return
  try {
    verifyResult.value = await verifyFingerprint({ url: verifyUrl.value.trim() })
  } catch (e) {
    verifyResult.value = { error: e?.response?.data?.detail || '探测失败' }
  }
}

onMounted(() => load())
</script>

<template>
  <div class="stack">
    <PageHead title="指纹管理" desc="名称库 + 模板库 + 自定义规则三路合并，同一套引擎跑存活探测；现场验证能直接看命中证据">
      <template #actions>
        <input v-model="keyword" class="input" style="width: 200px" placeholder="搜索指纹名 / 模板 ID，回车" @keyup.enter="load()" />
        <button class="btn sm" @click="showForm = true"><Icon name="plus" :size="13" />新增规则</button>
      </template>
    </PageHead>

    <div class="metric-row">
      <div class="metric">
        <span class="metric-label">模板库</span><span class="metric-value mono">{{ templateAll.toLocaleString() }}</span><span class="metric-foot">规则总数</span>
      </div>
      <div class="metric">
        <span class="metric-label">筛选命中</span><span class="metric-value mono">{{ templateTotal.toLocaleString() }}</span><span class="metric-foot">当前条件</span>
      </div>
      <div class="metric">
        <span class="metric-label">名称库</span><span class="metric-value mono">{{ builtinTotal.toLocaleString() }}</span><span class="metric-foot">内置名称</span>
      </div>
      <div class="metric">
        <span class="metric-label">自定义</span><span class="metric-value mono">{{ custom.length }}</span><span class="metric-foot">本地规则</span>
      </div>
      <div class="metric">
        <span class="metric-label">匹配器</span>
        <span class="metric-value mono">{{ matcherTypes.reduce((s, m) => s + m.count, 0).toLocaleString() }}</span>
        <span class="metric-foot">
          <span v-for="m in matcherTypes" :key="m.kind" style="margin-right: 6px">{{ m.kind }} {{ m.count }}</span>
        </span>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><span><Icon name="aim" :size="13" />现场验证</span></div>
      <div class="panel-body stack" style="gap: 8px">
        <div class="row">
          <input v-model="verifyUrl" class="input flex-1" placeholder="http://example.com 或域名" @keyup.enter="verify" />
          <button class="btn sm primary" @click="verify"><Icon name="bolt" :size="12" />探测</button>
        </div>
        <div v-if="verifyResult" class="panel" style="background: rgba(3,7,11,.5)">
          <div class="panel-body" style="font-size: 11.5px">
            <div class="row" style="gap: 14px">
              <span>状态码 <span class="mono">{{ verifyResult.status_code || '-' }}</span></span>
              <span>标题 <span class="mono">{{ verifyResult.title || '-' }}</span></span>
              <span>Server <span class="mono">{{ verifyResult.server || '-' }}</span></span>
            </div>
            <div v-if="verifyResult.error" class="tag err" style="margin-top: 6px">{{ verifyResult.error }}</div>
            <div class="row" style="margin-top: 8px">
              <span v-for="f in verifyResult.fingerprints || []" :key="f" class="tag cyan">{{ f }}</span>
              <span v-if="!(verifyResult.fingerprints || []).length && !verifyResult.error" class="muted">未命中任何指纹</span>
            </div>
            <div v-if="(verifyResult.template_hits || []).length" style="margin-top: 8px">
              <div class="field-label" style="margin-bottom: 4px">模板命中</div>
              <div v-for="h in verifyResult.template_hits" :key="h.name" class="hit-row">
                <span class="hit-name">{{ h.name }}</span>
                <span v-for="t in h.tags || []" :key="t" class="tag" style="font-size: 9.5px">{{ t }}</span>
                <span class="mono muted ellipsis" style="font-size: 10px">{{ (h.evidence || []).join(' | ') }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="seg">
          <button :class="{ on: tab === 'tpl' }" @click="tab = 'tpl'">模板库</button>
          <button :class="{ on: tab === 'builtin' }" @click="tab = 'builtin'">名称库</button>
          <button :class="{ on: tab === 'custom' }" @click="tab = 'custom'">自定义</button>
        </div>
        <div class="flex gap-8">
          <span class="mono muted" style="font-size: 10.5px">{{ page }} / {{ pages }}</span>
          <button class="btn xs" :disabled="page <= 1" @click="goPage(page - 1)">上一页</button>
          <button class="btn xs" :disabled="page >= pages" @click="goPage(page + 1)">下一页</button>
        </div>
      </div>

      <div v-if="tab === 'tpl'" class="panel-body" style="border-bottom: 1px solid var(--line)">
        <div class="tag-row">
          <button class="tag pick" :class="{ on: !tag }" @click="pickTag('')">全部标签</button>
          <button v-for="t in tags" :key="t.tag" class="tag pick" :class="{ on: tag === t.tag }" @click="pickTag(t.tag)">
            {{ t.tag }} <span class="muted">{{ t.count }}</span>
          </button>
        </div>
      </div>

      <div v-if="tab === 'tpl'" class="table-wrap">
        <table class="table">
          <thead><tr><th>模板</th><th>标签</th><th>严重度</th><th>路径</th><th>条件</th><th>匹配器</th></tr></thead>
          <tbody>
            <tr v-for="t in templates" :key="t.id">
              <td style="max-width: 260px">
                <div class="ellipsis" style="color: var(--text)">{{ t.name }}</div>
                <div class="mono muted" style="font-size: 10px">{{ t.id }}</div>
              </td>
              <td>
                <span v-for="g in (t.tags || []).slice(0, 4)" :key="g" class="tag" style="font-size: 9.5px; margin-right: 3px">{{ g }}</span>
              </td>
              <td class="mono">{{ t.severity || '-' }}</td>
              <td class="mono ellipsis" style="max-width: 180px" :title="(t.paths || []).join(' ')">{{ (t.paths || []).join(' ') || '/' }}</td>
              <td class="mono">{{ t.condition }}</td>
              <td class="mono ellipsis" style="max-width: 140px">{{ (t.matchers || []).join('+') }} <span class="muted">({{ t.matcher_total }})</span></td>
            </tr>
            <tr v-if="!templates.length && !loading">
              <td colspan="6"><div class="empty"><Icon name="search" :size="20" />没有匹配的模板</div></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="tab === 'builtin'" class="panel-body">
        <div class="chips">
          <span v-for="b in builtin" :key="b.name" class="tag">{{ b.name }}</span>
          <span v-if="!builtin.length && !loading" class="muted">没有匹配的名称</span>
        </div>
      </div>

      <div v-if="tab === 'custom'" class="table-wrap">
        <table class="table">
          <thead><tr><th>名称</th><th>关键字</th><th>标签</th><th></th></tr></thead>
          <tbody>
            <tr v-for="c in custom" :key="c.name">
              <td style="color: var(--text)">{{ c.name }}</td>
              <td class="mono ellipsis" style="max-width: 180px">{{ c.keyword || c.body || c.header }}</td>
              <td><span class="tag">{{ c.tag || '-' }}</span></td>
              <td style="text-align: right">
                <button class="btn xs danger" @click="remove(c)"><Icon name="trash" :size="11" /></button>
              </td>
            </tr>
            <tr v-if="!custom.length">
              <td colspan="4"><div class="empty" style="padding: 20px"><Icon name="tags" :size="20" />还没有自定义规则</div></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="showForm" class="overlay" @click.self="showForm = false">
      <div class="modal">
        <div class="modal-head">
          <Icon name="tags" :size="15" style="color: var(--cyan)" />
          <span class="flex-1">新增指纹规则</span>
          <button class="btn ghost sm" @click="showForm = false"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px">
          <div class="field"><span class="field-label">指纹名 *</span><input v-model="form.name" class="input" placeholder="例如：某 OA 系统" /></div>
          <div class="field"><span class="field-label">标签</span><input v-model="form.tag" class="input" placeholder="例如：OA" /></div>
          <div class="field"><span class="field-label">标题关键字</span><input v-model="form.keyword" class="input" placeholder="页面标题包含" /></div>
          <div class="field"><span class="field-label">响应头关键字</span><input v-model="form.header" class="input" placeholder="如 X-Powered-By" /></div>
          <div class="field"><span class="field-label">Server</span><input v-model="form.server" class="input" placeholder="如 nginx/1.2" /></div>
          <div class="field"><span class="field-label">指纹 favicon hash</span><input v-model="form.cms" class="input" placeholder="mmh3 hash" /></div>
          <div class="field" style="grid-column: 1 / -1">
            <span class="field-label">正文关键字</span>
            <textarea v-model="form.body" class="textarea" style="min-height: 70px" placeholder="HTML 里出现的特征串" />
          </div>
          <div class="field" style="grid-column: 1 / -1">
            <span class="field-label">备注</span><input v-model="form.note" class="input" placeholder="可选" />
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn sm" @click="showForm = false">取消</button>
          <button class="btn primary sm" @click="submit"><Icon name="check" :size="12" />保存规则</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.chips { display: flex; flex-wrap: wrap; gap: 6px; max-height: 420px; overflow-y: auto; }
.tag-row { display: flex; flex-wrap: wrap; gap: 5px; max-height: 92px; overflow-y: auto; }
.tag.pick { cursor: pointer; border: 1px solid var(--line); background: transparent; }
.tag.pick.on { border-color: rgba(52, 229, 200, 0.6); background: rgba(52, 229, 200, 0.12); color: #b9f4ea; }
.hit-row { display: flex; align-items: center; gap: 6px; padding: 2px 0; }
.hit-name { color: #b9f4ea; font-size: 11.5px; }
</style>
