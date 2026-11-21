<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import {
  aiFingerprint,
  aiQuery,
  aiStatus,
  aiSummary,
  aiTriage,
  fofaHot,
  listTasks,
  searchSpace,
  testAi,
} from '@/api/endpoints'

const router = useRouter()

const status = reactive({ ready: false, engine: '', base: '', model: '', msg: '', features: [] })
const tab = ref('query')
const testing = ref(false)
const busy = reactive({ query: false, triage: false, summary: false, fp: false })
const tasks = ref([])

// ── 1 测绘语法 ──
const qText = ref('')
const qEngine = ref('fofa')
const qResult = ref(null)
const qSearching = ref('')
const qHits = ref({})
const engines = [
  { k: 'fofa', label: 'FOFA' },
  { k: 'hunter', label: 'Hunter' },
  { k: 'quake', label: 'Quake' },
  { k: 'zoomeye', label: 'ZoomEye' },
]

// ── 1b 热点榜（免 key，不需要大模型）──
const hotKeyword = ref('')
const hotBusy = ref(false)
const hotRows = ref([])
const hotErr = ref('')
const hotLoaded = ref(false)

async function loadHot() {
  hotBusy.value = true
  hotErr.value = ''
  try {
    const res = await fofaHot({ keyword: hotKeyword.value.trim(), limit: 30 })
    hotRows.value = res.rows || []
    if (!res.ok) hotErr.value = res.msg || '热点榜暂不可用'
    else if (!hotRows.value.length) hotErr.value = '没有匹配的产品'
    hotLoaded.value = true
  } catch (e) {
    hotErr.value = e?.response?.data?.detail || e?.message || '热点榜请求失败'
  } finally {
    hotBusy.value = false
  }
}

function useHot(row) {
  qText.value = row.app || ''
  if (row.query) runQuery(row.query)
}

async function copyQuery(q) {
  await copy(q)
}

// ── 2 研判 ──
const triageKind = ref('')
const triageRoot = ref('')
const triageResult = ref(null)
const kinds = ['', 'leak', 'leakfile', 'git', 'api', 'site', 'domain', 'js', 'email', 'bucket']

// ── 3 小结 ──
const taskId = ref('')
const summaryResult = ref(null)

// ── 4 指纹 ──
const fpUrl = ref('')
const fpResult = ref(null)

const tabs = [
  { k: 'query', label: '测绘语法生成', icon: 'aim' },
  { k: 'triage', label: '资产研判排序', icon: 'layers' },
  { k: 'summary', label: '任务侦察小结', icon: 'file' },
  { k: 'fingerprint', label: '指纹规则建议', icon: 'tags' },
]

function err(e) {
  const msg = e?.response?.data?.detail || e?.message || '调用失败'
  ElMessage.error(msg)
}

async function loadStatus() {
  try {
    Object.assign(status, await aiStatus())
  } catch {
    /* 未登录或后端未就绪 */
  }
}

async function loadTasks() {
  try {
    const res = await listTasks({ limit: 50 })
    tasks.value = res.items || []
    if (!taskId.value && tasks.value.length) taskId.value = tasks.value[0].id
  } catch {
    /* ignore */
  }
}

async function test() {
  testing.value = true
  try {
    const res = await testAi()
    status.ready = Boolean(res.ok)
    ElMessage[res.ok ? 'success' : 'warning'](res.msg || '已发送')
  } catch (e) {
    err(e)
  } finally {
    testing.value = false
  }
}

async function genQuery() {
  if (!qText.value.trim()) return ElMessage.warning('先写目标或一句描述，例如「某某科技有限公司 官网」')
  busy.query = true
  try {
    qResult.value = await aiQuery({ text: qText.value.trim(), engine: qEngine.value })
    qHits.value = {}
  } catch (e) {
    err(e)
  } finally {
    busy.query = false
  }
}

async function runQuery(q) {
  qSearching.value = q
  try {
    const res = await searchSpace({ query: q, engine: qEngine.value, size: 50 })
    qHits.value = { ...qHits.value, [q]: res }
    if (!res.ok) ElMessage.warning(res.msg || '该引擎暂不支持通用语法检索')
  } catch (e) {
    err(e)
  } finally {
    qSearching.value = ''
  }
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch {
    ElMessage.warning('浏览器拒绝复制，请手动选中')
  }
}

async function doTriage() {
  busy.triage = true
  try {
    triageResult.value = await aiTriage({ kind: triageKind.value, root_domain: triageRoot.value.trim(), limit: 120 })
  } catch (e) {
    err(e)
  } finally {
    busy.triage = false
  }
}

async function doSummary() {
  if (!taskId.value) return ElMessage.warning('先选一个任务')
  busy.summary = true
  try {
    summaryResult.value = await aiSummary({ task_id: taskId.value })
  } catch (e) {
    err(e)
  } finally {
    busy.summary = false
  }
}

async function doFingerprint() {
  if (!fpUrl.value.trim()) return ElMessage.warning('填一个目标 URL')
  busy.fp = true
  try {
    fpResult.value = await aiFingerprint({ url: fpUrl.value.trim() })
  } catch (e) {
    err(e)
  } finally {
    busy.fp = false
  }
}

const riskClass = computed(() => (r) => (r === '高' ? 'bad' : r === '中' ? 'warn' : 'ok'))

onMounted(() => {
  loadStatus()
  loadTasks()
  loadHot()
})
</script>

<template>
  <div class="stack">
    <PageHead title="AI 工坊" desc="大模型接入后，这四件事可以直接用：生成测绘语法、给资产排队、写侦察小结、反推指纹规则">
      <template #actions>
        <span class="tag" :class="status.ready ? 'ok' : 'warn'">
          {{ status.ready ? `${status.engine} · ${status.model}` : '未接入大模型' }}
        </span>
        <button class="btn sm" :disabled="testing" @click="test"><Icon name="bolt" :size="13" />测试</button>
        <button class="btn sm" @click="router.push('/settings')"><Icon name="settings" :size="13" />去配置</button>
      </template>
    </PageHead>

    <div v-if="!status.ready" class="panel">
      <div class="panel-body stack" style="gap: 8px">
        <span class="warn-text">大模型还没接入：系统设置 → AI → 填 API Key（DeepSeek / OpenAI / 任何 OpenAI 兼容中转站）→ 保存 → 点「测试」。</span>
        <span class="field-hint">{{ status.msg }}</span>
      </div>
    </div>

    <div class="row">
      <div class="seg">
        <button v-for="t in tabs" :key="t.k" :class="{ on: tab === t.k }" @click="tab = t.k">{{ t.label }}</button>
      </div>
    </div>

    <!-- 1 测绘语法 -->
    <div v-if="tab === 'query'" class="stack">
      <div class="panel">
        <div class="panel-head"><span><Icon name="aim" :size="13" />告诉我你要找谁</span></div>
        <div class="panel-body stack" style="gap: 10px">
          <textarea
            v-model="qText"
            class="textarea"
            style="min-height: 84px"
            placeholder="例：某某科技有限公司 官网；或：这个站用友 NC，想找同产品资产；或：手机号 138xxx 关联的企业域名"
          />
          <div class="row" style="gap: 10px; align-items: center">
            <div class="seg">
              <button v-for="e in engines" :key="e.k" :class="{ on: qEngine === e.k }" @click="qEngine = e.k">{{ e.label }}</button>
            </div>
            <button class="btn primary sm right" :disabled="busy.query" @click="genQuery">
              <Icon name="spark" :size="13" />{{ busy.query ? '生成中…' : '生成语法' }}
            </button>
          </div>
          <span class="field-hint">大模型没接入也能用：下面的热点榜免 key，直接给出近期高增长产品的现成查询语法。</span>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span><Icon name="bolt" :size="13" />近期高增长产品 · 现成语法</span>
          <span class="mono muted">免 key · 只给起手灵感，不产资产</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="row" style="gap: 8px">
            <input
              v-model="hotKeyword"
              class="input mono flex-1"
              placeholder="按产品名过滤，留空看全部"
              @keyup.enter="loadHot"
            />
            <button class="btn sm" :disabled="hotBusy" @click="loadHot">
              <Icon name="search" :size="12" />{{ hotBusy ? '拉取中…' : hotLoaded ? '刷新' : '加载热点榜' }}
            </button>
          </div>
          <span v-if="hotErr" class="field-hint">{{ hotErr }}</span>
          <div v-for="(r, i) in hotRows" :key="r.app + i" class="query-card">
            <div class="row" style="gap: 8px; align-items: center">
              <span class="tag cyan">{{ i + 1 }}</span>
              <strong>{{ r.app }}</strong>
              <span class="mono muted">{{ r.total }} 资产 · 近 7 天 {{ r.last7 }} · 环比 {{ r.growth }} 倍</span>
            </div>
            <code class="mono">{{ r.query }}</code>
            <span class="field-hint">{{ r.why }}</span>
            <div class="row" style="gap: 6px">
              <button class="btn xs" @click="copyQuery(r.query)"><Icon name="copy" :size="11" />复制</button>
              <button
                v-if="qEngine === 'fofa'"
                class="btn xs"
                :disabled="qSearching === r.query"
                @click="runQuery(r.query)"
              >
                <Icon name="play" :size="11" />{{ qSearching === r.query ? '检索中…' : '执行' }}
              </button>
            </div>
            <div v-if="qHits[r.query]" class="mono muted">
              命中 {{ qHits[r.query].count }} 条
              <span v-for="h in (qHits[r.query].items || []).slice(0, 3)" :key="h.url" class="hit">{{ h.url }} {{ h.title }}</span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="qResult" class="panel">
        <div class="panel-head">
          <span><Icon name="terminal" :size="13" />{{ qEngine.toUpperCase() }} 建议语法</span>
          <span class="mono muted">{{ qEngine === 'fofa' || qEngine === 'hunter' ? '可点「执行」直接打到资产库' : '复制到对应站点使用' }}</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div v-for="(q, i) in qResult.queries" :key="i" class="query-card">
            <code class="mono">{{ q.q }}</code>
            <span class="field-hint">{{ q.why }}</span>
            <div class="row" style="gap: 6px">
              <button class="btn xs" @click="copy(q.q)"><Icon name="copy" :size="11" />复制</button>
              <button
                v-if="qEngine === 'fofa'"
                class="btn xs"
                :disabled="qSearching === q.q"
                @click="runQuery(q.q)"
              >
                <Icon name="play" :size="11" />{{ qSearching === q.q ? '检索中…' : '执行' }}
              </button>
            </div>
            <div v-if="qHits[q.q]" class="mono muted">
              命中 {{ qHits[q.q].count }} 条
              <span v-for="h in (qHits[q.q].items || []).slice(0, 3)" :key="h.url" class="hit">{{ h.url }} {{ h.title }}</span>
            </div>
          </div>
          <pre v-if="!qResult.queries?.length" class="raw">{{ qResult.text }}</pre>
        </div>
      </div>
    </div>

    <!-- 2 研判 -->
    <div v-if="tab === 'triage'" class="stack">
      <div class="panel">
        <div class="panel-head"><span><Icon name="layers" :size="13" />给现有资产排队</span></div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="row" style="gap: 10px; align-items: flex-end">
            <div class="field" style="width: 160px">
              <span class="field-label">类型</span>
              <select v-model="triageKind" class="input">
                <option v-for="k in kinds" :key="k" :value="k">{{ k || '全部' }}</option>
              </select>
            </div>
            <div class="field flex-1">
              <span class="field-label">根域（可留空）</span>
              <input v-model="triageRoot" class="input mono" placeholder="example.com" />
            </div>
            <button class="btn primary sm" :disabled="busy.triage" @click="doTriage">
              <Icon name="spark" :size="13" />{{ busy.triage ? '研判中…' : '开始研判' }}
            </button>
          </div>
          <span class="field-hint">取最近 120 条资产交给模型排序，重点看泄露、接口、后台与暴露服务；结果里的地址可直接点进资产搜索。</span>
        </div>
      </div>

      <div v-if="triageResult" class="panel">
        <div class="panel-head">
          <span><Icon name="chart" :size="13" />AI 结论</span>
          <span class="mono muted">取样 {{ triageResult.count }} 条</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <p class="summary">{{ triageResult.summary }}</p>
          <div v-for="it in triageResult.items" :key="it.id" class="triage-row">
            <span class="tag" :class="riskClass(it.risk)">{{ it.risk }}</span>
            <div class="stack" style="gap: 2px; flex: 1">
              <button class="link mono" @click="router.push({ path: '/assets', query: { keyword: it.url } })">{{ it.url }}</button>
              <span class="field-hint">{{ it.kind }} · {{ it.title }}</span>
            </div>
            <span class="why">{{ it.why }}</span>
          </div>
          <pre v-if="!triageResult.items?.length" class="raw">{{ triageResult.text }}</pre>
        </div>
      </div>
    </div>

    <!-- 3 小结 -->
    <div v-if="tab === 'summary'" class="stack">
      <div class="panel">
        <div class="panel-head"><span><Icon name="file" :size="13" />选一个任务写小结</span></div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="row" style="gap: 10px; align-items: flex-end">
            <div class="field flex-1">
              <span class="field-label">任务</span>
              <select v-model="taskId" class="input mono">
                <option v-for="t in tasks" :key="t.id" :value="t.id">{{ t.name || t.id }} · {{ (t.targets || []).join(', ').slice(0, 40) }}</option>
              </select>
            </div>
            <button class="btn primary sm" :disabled="busy.summary" @click="doSummary">
              <Icon name="spark" :size="13" />{{ busy.summary ? '生成中…' : '生成小结' }}
            </button>
          </div>
          <span class="field-hint">任务跑完勾了「AI 侦察小结」会自己写一份，这里可以随时重写或补写。</span>
        </div>
      </div>

      <div v-if="summaryResult" class="panel">
        <div class="panel-head">
          <span><Icon name="chart" :size="13" />侦察小结</span>
          <span class="mono muted">{{ summaryResult.kinds?.map((k) => `${k.kind} ${k.count}`).join(' · ') }}</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <pre class="raw">{{ summaryResult.summary }}</pre>
          <div class="row" style="flex-wrap: wrap; gap: 6px">
            <span v-for="r in summaryResult.roots" :key="r.root_domain" class="tag">{{ r.root_domain }} · {{ r.count }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 4 指纹 -->
    <div v-if="tab === 'fingerprint'" class="stack">
      <div class="panel">
        <div class="panel-head"><span><Icon name="tags" :size="13" />从一个 URL 反推指纹</span></div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="row" style="gap: 10px">
            <input v-model="fpUrl" class="input mono flex-1" placeholder="https://target.example.com" />
            <button class="btn primary sm" :disabled="busy.fp" @click="doFingerprint">
              <Icon name="spark" :size="13" />{{ busy.fp ? '分析中…' : '生成规则' }}
            </button>
          </div>
          <span class="field-hint">会实时请求该页面，取标题 / 响应头 / 正文交给模型，输出能稳定识别的正则；可直接粘到「指纹管理」。</span>
        </div>
      </div>

      <div v-if="fpResult" class="panel">
        <div class="panel-head">
          <span><Icon name="check" :size="13" />建议指纹</span>
          <span class="mono muted">HTTP {{ fpResult.status_code }} · {{ fpResult.server }}</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <p class="muted">{{ fpResult.msg || fpResult.title }}</p>
          <div v-if="fpResult.regex" class="stack" style="gap: 6px">
            <span class="field-label">产品名</span><code class="mono">{{ fpResult.name }}</code>
            <span class="field-label">匹配正则</span><code class="mono">{{ fpResult.regex }}</code>
            <button class="btn xs" @click="copy(fpResult.regex)"><Icon name="copy" :size="11" />复制正则</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.query-card {
  display: grid;
  gap: 6px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel-solid);
}
.query-card code {
  color: var(--cyan);
  word-break: break-all;
}
.hit {
  display: block;
  color: var(--text-2);
}
.triage-row {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  padding: 8px 0;
  border-bottom: 1px solid var(--line-soft);
}
.why {
  max-width: 320px;
  color: var(--text-2);
  font-size: 12px;
}
.raw {
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text);
  font-family: inherit;
  margin: 0;
  line-height: 1.7;
}
.summary {
  margin: 0;
  color: var(--text);
  line-height: 1.7;
}
.link {
  background: none;
  border: 0;
  padding: 0;
  color: var(--cyan);
  cursor: pointer;
  text-align: left;
  word-break: break-all;
}
.warn-text {
  color: var(--amber-ink);
}
.tag.bad {
  color: var(--red);
  border-color: var(--red);
}
.tag.warn {
  color: var(--amber);
  border-color: var(--amber);
}
</style>
