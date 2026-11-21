<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { oneClick, presets as fetchPresets } from '@/api/endpoints'

const router = useRouter()

const raw = ref('')
const presetKey = ref('standard')
const expandEnterprise = ref(true)
const expandMobile = ref(true)
const taskName = ref('')
const equityRatio = ref(100)
// 控股门槛候选：对齐工商穿透的常用口径，比让用户裸填数字更省事
const uboThreshold = ref(25)
// 最终受益人控制线：股东树逐级折算后的累计持股达到这条线，就标成控制
const UBO_CHOICES = [
  { v: 50, label: '50% 过半' },
  { v: 34, label: '34% 重大影响' },
  { v: 25, label: '25% 工商口径' },
  { v: 10, label: '10% 重要股东' },
  { v: 5, label: '5% 举牌线' },
]
const EQUITY_CHOICES = [
  { v: 100, label: '100% 全资' },
  { v: 67, label: '67% 绝对控股' },
  { v: 51, label: '51% 控盘' },
  { v: 34, label: '34% 重大影响' },
  { v: 0, label: '0% 全部持股' },
]
const loading = ref(false)
const result = ref(null)
const error = ref('')
const presetList = ref([])

const options = reactive({
  domain_brute: true,
  port_type: 'top100',
  site_spider: true,
  file_leak: true,
  sibling: true,
  asn_expand: true,
  deep: true,
  vhost_collision: false,
})

const lines = computed(() => raw.value.split('\n').filter((l) => l.trim()).length)

// 五个步骤默认全选，点卡片取消；只勾部分时后端整组跳过没勾的阶段。
const STEPS = [
  { k: 'p1', name: '主体穿透', desc: 'ICP 反查 · 全资穿透 · 小程序 App', hint: () => (expandEnterprise.value ? '' : '主体扩展已关') },
  { k: 'p2', name: '域名收集', desc: '26 源被动 · CT 镜像 · 字典爆破', hint: () => (options.domain_brute ? '' : '字典爆破已关') },
  { k: 'p3', name: '空间测绘', desc: '按已收根域查测绘源', hint: () => '' },
  { k: 'p4', name: '主动探测', desc: '端口 · 存活 · 指纹 · 证书', hint: () => `端口 ${options.port_type}` },
  { k: 'p5', name: '深度挖掘', desc: 'JS 接口 · 敏感文件 · 代码泄露 · 邮箱', hint: () => (options.deep ? '' : '深度项已关') },
]
const picked = ref(STEPS.map((s) => s.k))

function has(k) {
  return picked.value.includes(k)
}
function toggleStep(k) {
  picked.value = has(k) ? picked.value.filter((x) => x !== k) : [...picked.value, k]
}
function pickAll() {
  picked.value = picked.value.length === STEPS.length ? [] : STEPS.map((s) => s.k)
}

const est = computed(() => {
  const n = lines.value
  if (!n) return '—'
  const base = { quick: 6, standard: 14, deep: 30, hunt: 4 }[presetKey.value] || 14
  const share = Math.max(1, picked.value.length) / STEPS.length
  return `约 ${Math.max(1, Math.round((base * share * n) / (n > 3 ? 3 : 1)))} 分钟`
})

async function loadPresets() {
  try {
    const res = await fetchPresets()
    presetList.value = res.items || []
    applyPreset('standard')
  } catch {
    /* 预设拿不到就用默认选项 */
  }
}

function applyPreset(key) {
  presetKey.value = key
  const p = presetList.value.find((x) => x.key === key)
  if (!p) return
  const o = p.options || {}
  options.domain_brute = o.domain_brute ?? true
  options.port_type = o.port_type || 'top100'
  options.site_spider = o.site_spider ?? true
  options.file_leak = o.file_leak ?? true
  options.sibling = o.sibling ?? true
  options.asn_expand = o.asn_expand ?? true
  options.deep = o.deep ?? true
  options.vhost_collision = o.vhost_collision ?? false
}

async function run() {
  error.value = ''
  result.value = null
  if (!raw.value.trim()) {
    error.value = '请先填写目标：企业全称、域名或 IP，一行一个'
    return
  }
  if (!picked.value.length) {
    error.value = '至少选一个执行步骤'
    return
  }
  loading.value = true
  try {
    const res = await oneClick({
      targets: raw.value,
      preset: presetKey.value,
      steps: picked.value,
      expand_enterprise: expandEnterprise.value,
      expand_mobile: expandMobile.value,
      name: taskName.value.trim() || undefined,
      equity_ratio: has('p1') && expandEnterprise.value ? equityRatio.value : undefined,
      equity_ubo_threshold: has('p1') && expandEnterprise.value ? uboThreshold.value : undefined,
      options: { ...options },
    })
    result.value = res
  } catch (e) {
    error.value = e?.response?.data?.detail || '下发失败，请查看服务日志'
  } finally {
    loading.value = false
  }
}

function openTask() {
  if (result.value?.task_id) router.push(`/tasks/${result.value.task_id}`)
}

// 逐域打分：确认 / 待核验 / 拒绝一眼分开，避免「打偏了还以为挖到了」
const evidenceRows = computed(() => {
  const rows = []
  for (const e of result.value?.entities || []) {
    for (const [domain, ev] of Object.entries(e.evidence || {})) {
      const st = ev.status || 'pending'
      rows.push({
        domain,
        score: ev.score ?? 0,
        reasons: ev.reasons || [],
        statusText: st === 'confirmed' ? '确认' : st === 'rejected' ? '剔除' : '待核验',
        cls: st === 'confirmed' ? 'ok' : st === 'rejected' ? 'err' : 'warn',
      })
    }
  }
  return rows.sort((a, b) => b.score - a.score)
})

const mobileBlock = computed(() => {
  const m = result.value?.mobile
  return m && ((m.apps || []).length || (m.applets || []).length || (m.domains || []).length)
})

onMounted(loadPresets)
</script>

<template>
  <div class="stack">
    <PageHead title="一键收集全" desc="企业全称、品牌名、域名、IP 混着丢进来：先扩主体得到域名清单，再一轮跑完五个阶段">
      <template #actions>
        <button class="btn sm" @click="router.push('/tasks')"><Icon name="tasks" :size="13" />任务列表</button>
      </template>
    </PageHead>

    <div class="grid-main">
      <div class="stack">
        <div class="panel">
          <div class="panel-head">
            <span><Icon name="aim" :size="13" />侦察目标</span>
            <span class="mono muted">{{ lines }} 个目标 · {{ est }}</span>
          </div>
          <div class="panel-body stack" style="gap: 9px">
            <textarea
              v-model="raw"
              class="textarea"
              style="min-height: 120px"
              placeholder="示例：&#10;某某科技有限公司&#10;example.com&#10;1.2.3.4"
            />
            <div class="row" style="gap: 8px; flex-wrap: wrap">
              <input v-model="taskName" class="input flex-1" style="min-width: 180px" placeholder="任务名称（可选，留空自动命名）" />
              <label class="chk">
                <span class="switch" :class="{ on: expandEnterprise }" @click="expandEnterprise = !expandEnterprise" />
                企业主体扩展
              </label>
              <label class="chk">
                <span class="switch" :class="{ on: expandMobile }" @click="expandMobile = !expandMobile" />
                小程序 / App
              </label>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span><Icon name="flow" :size="13" />执行步骤</span>
            <span class="flex gap-8" style="align-items: center">
              <span class="mono muted">{{ picked.length }}/{{ STEPS.length }}</span>
              <button class="btn xs" @click="pickAll">{{ picked.length === STEPS.length ? '全不选' : '全选' }}</button>
            </span>
          </div>
          <div class="panel-body stack" style="gap: 10px">
            <div class="step-grid">
              <button
                v-for="(s, i) in STEPS"
                :key="s.k"
                class="step-card"
                :class="{ on: has(s.k) }"
                @click="toggleStep(s.k)"
              >
                <span class="step-idx">{{ i + 1 }}</span>
                <span class="step-name">{{ s.name }}</span>
                <span class="step-desc">{{ s.desc }}</span>
                <span class="step-hint">{{ s.hint() }}</span>
              </button>
            </div>
            <div class="row" style="gap: 10px; flex-wrap: wrap">
              <div class="field" style="width: 148px">
                <span class="field-label">控股门槛</span>
                <select v-model.number="equityRatio" class="input" :disabled="!has('p1') || !expandEnterprise">
                  <option v-for="r in EQUITY_CHOICES" :key="r.v" :value="r.v">{{ r.label }}</option>
                </select>
              </div>
              <div class="field" style="width: 148px">
                <span class="field-label">实控线</span>
                <select v-model.number="uboThreshold" class="input" :disabled="!has('p1') || !expandEnterprise">
                  <option v-for="r in UBO_CHOICES" :key="r.v" :value="r.v">{{ r.label }}</option>
                </select>
              </div>
              <span class="tip flex-1">控股门槛决定收哪些子公司（100% 只收全资，0 收全部持股）；实控线是股东树折算后判定控制的线。</span>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head"><span><Icon name="control" :size="13" />采集强度</span></div>
          <div class="panel-body">
            <div class="preset-grid">
              <button
                v-for="p in presetList"
                :key="p.key"
                class="preset"
                :class="{ on: presetKey === p.key }"
                @click="applyPreset(p.key)"
              >
                <span class="preset-name">{{ p.label }}</span>
                <span class="preset-desc">{{ p.desc }}</span>
              </button>
            </div>
          </div>
        </div>

        <details class="adv">
          <summary>高级选项<span class="mono muted">字典爆破 · 爬虫 · 敏感文件 · 旁站 C 段 · ASN · 端口</span></summary>
          <div class="adv-body">
            <label class="chk"><span class="switch" :class="{ on: options.domain_brute }" @click.prevent="options.domain_brute = !options.domain_brute" />字典爆破</label>
            <label class="chk"><span class="switch" :class="{ on: options.site_spider }" @click.prevent="options.site_spider = !options.site_spider" />站点爬虫</label>
            <label class="chk"><span class="switch" :class="{ on: options.file_leak }" @click.prevent="options.file_leak = !options.file_leak" />敏感文件</label>
            <label class="chk"><span class="switch" :class="{ on: options.sibling }" @click.prevent="options.sibling = !options.sibling" />旁站 C 段</label>
            <label class="chk"><span class="switch" :class="{ on: options.asn_expand }" @click.prevent="options.asn_expand = !options.asn_expand" />ASN 网段</label>
            <label class="chk"><span class="switch" :class="{ on: options.deep }" @click.prevent="options.deep = !options.deep" />深度挖掘</label>
            <label class="chk"><span class="switch" :class="{ on: options.vhost_collision }" @click.prevent="options.vhost_collision = !options.vhost_collision" />VHost 碰撞</label>
            <label class="chk">
              端口
              <select v-model="options.port_type" class="input" style="height: 26px; width: 118px">
                <option value="enterprise">企业端口 90</option>
                <option value="slim">精简端口 30</option>
                <option value="top10">TOP 10</option>
                <option value="top100">TOP 100</option>
                <option value="top1000">TOP 1000</option>
                <option value="all">全端口</option>
              </select>
            </label>
          </div>
        </details>

        <div v-if="error" class="tag err" style="height: auto; padding: 8px 10px; white-space: normal">{{ error }}</div>

        <!-- 主按钮跟着滚动一直停在底部：左侧步骤多了也不用往下翻才能开跑 -->
        <div class="action-bar">
          <button class="btn primary" style="height: 36px; padding: 0 18px" :disabled="loading || !picked.length" @click="run">
            <Icon name="bolt" :size="15" />
            <span>{{ loading ? '下发中…' : `开始收集（${picked.length} 步）` }}</span>
          </button>
          <button v-if="result && result.task_id" class="btn" style="height: 36px" @click="openTask">
            <Icon name="eye" :size="14" />查看任务
          </button>
          <span class="action-tip">目标 {{ lines }} 个 · {{ picked.length }}/{{ STEPS.length }} 步 · {{ est }}</span>
        </div>

        <div v-if="result" class="panel">
          <div class="panel-head">
            <span><Icon :name="result.count && result.domain_count !== 0 ? 'check' : 'alert'" :size="13" />{{ result.count ? (result.domain_count === 0 ? '已下发（无确认域名）' : '已下发') : '没有解析出目标' }}</span>
            <span class="tag" :class="result.count && result.domain_count !== 0 ? 'ok' : 'warn'">{{ result.count }} 个目标</span>
          </div>
          <div class="panel-body stack" style="gap: 8px">
            <div v-if="result.message" class="field">
              <span class="field-label">这一轮的情况</span>
              <div style="font-size: 11.5px; color: var(--text-2); white-space: normal; line-height: 1.9">
                {{ result.message }}
              </div>
            </div>
            <div v-if="(result.entities || []).length" class="field">
              <span class="field-label">主体解析</span>
              <div v-for="(e, i) in result.entities" :key="i" style="font-size: 11.5px; color: var(--text-2)">
                <span class="mono">{{ e.name }}</span>
                <span class="muted"> → {{ (e.domains || []).length }} 个域名</span>
                <span v-if="(e.sources || []).length" class="tag" style="margin-left: 6px">
                  {{ e.sources.join('+') }}
                </span>
                <span v-if="e.error" class="tag err" style="margin-left: 6px">{{ e.error }}</span>
                <div v-if="(e.notes || []).length" class="muted" style="font-size: 11px">
                  {{ e.notes.join(' / ') }}
                </div>
              </div>
            </div>

            <div v-if="evidenceRows.length" class="field">
              <span class="field-label">域名归属证据（只有「确认」才会进入收集链）</span>
              <div class="ev-table">
                <div v-for="r in evidenceRows" :key="r.domain" class="ev-row">
                  <span class="mono ev-dom">{{ r.domain }}</span>
                  <span class="tag" :class="r.cls">{{ r.statusText }}</span>
                  <span class="ev-score mono">{{ r.score }}</span>
                  <span class="ev-why">{{ (r.reasons || []).slice(0, 3).join('；') }}</span>
                </div>
              </div>
            </div>

            <div v-if="mobileBlock" class="field">
              <span class="field-label">移动端（小程序 / App）</span>
              <div style="font-size: 11.5px; color: var(--text-2); line-height: 1.9">
                <div>
                  小程序 <b>{{ (result.mobile?.applets || []).length }}</b> 个 ·
                  App <b>{{ (result.mobile?.apps || []).length }}</b> 个 ·
                  新增域 <b>{{ (result.mobile?.domains || []).length }}</b> 个
                </div>
                <div v-for="(a, i) in (result.mobile?.applets || []).slice(0, 6)" :key="'al' + i" class="muted">
                  小程序 · {{ a.name || '(无名)' }}<span v-if="a.appid" class="mono"> {{ a.appid }}</span>
                  <span v-if="a.subject"> · {{ a.subject }}</span>
                </div>
                <div v-for="(a, i) in (result.mobile?.apps || []).slice(0, 6)" :key="'ap' + i" class="muted">
                  {{ a.platform === 'ios' ? 'iOS' : 'Android' }} · {{ a.name }}<span class="mono"> {{ a.package }}</span>
                </div>
                <div v-if="(result.mobile?.notes || []).length" class="muted" style="font-size: 11px">
                  {{ (result.mobile.notes || []).join(' / ') }}
                </div>
              </div>
            </div>
            <div class="field">
              <span class="field-label">最终目标清单</span>
              <div class="mono" style="font-size: 11.5px; color: var(--text-2); max-height: 160px; overflow-y: auto; line-height: 1.8">
                {{ (result.targets || []).join('　') }}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="stack">
        <div class="panel">
          <div class="panel-head">
            <span><Icon name="flow" :size="13" />本轮执行</span>
            <span class="mono muted">{{ est }}</span>
          </div>
          <div class="panel-body stack" style="gap: 0">
            <div v-for="(s, i) in STEPS" :key="s.k" class="step" :class="{ off: !has(s.k) }">
              <span class="step-idx">{{ i + 1 }}</span>
              <div class="flex-1">
                <div class="step-name">{{ s.name }}</div>
                <div class="step-desc">{{ has(s.k) ? (s.hint() || s.desc) : '本轮跳过' }}</div>
              </div>
              <span class="status-dot" :class="has(s.k) ? 'ok' : ''" />
            </div>
            <div class="note">
              各阶段产出的穿透图与资产会在汇总时合并去重；启用了大模型就走 AI 辅助判别名，没启用或调用失败自动用规则合并。
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head"><span><Icon name="alert" :size="13" />会收集到什么</span></div>
          <div class="panel-body stack" style="gap: 7px; font-size: 11.5px; color: var(--text-2); line-height: 1.7">
            <div><span class="tag cyan">主体</span> 备案主体、统一社会信用代码、全资子公司、公众号 / 小程序 / APP</div>
            <div><span class="tag cyan">域名</span> 被动源、证书透明度多镜像、字典爆破、历史解析</div>
            <div><span class="tag cyan">空间</span> 测绘结果并入、favicon 反查、C 段与旁站（可单独导出）</div>
            <div><span class="tag cyan">探测</span> 端口服务、标题、证书 SAN、CDN 判定</div>
            <div><span class="tag cyan">深挖</span> JS 接口、敏感文件、Git 泄露、邮箱与 MX、存储桶</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.grid-main {
  display: grid;
  grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr);
  gap: 12px;
  align-items: start;
}
@media (max-width: 1180px) {
  .grid-main { grid-template-columns: minmax(0, 1fr); }
}
.chk {
  display: inline-flex; align-items: center; gap: 8px;
  font-size: 12px; color: var(--text-2); cursor: pointer; white-space: nowrap;
}
.preset-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; }
.preset {
  display: flex; flex-direction: column; gap: 3px;
  padding: 9px 11px; text-align: left;
  border-radius: 9px; border: 1px solid var(--line);
  background: var(--panel-2, rgba(120, 200, 220, 0.03));
  transition: border-color 0.15s, background 0.15s;
}
.preset:hover { border-color: var(--line-strong); }
.preset.on { border-color: rgba(52, 229, 200, 0.45); background: rgba(52, 229, 200, 0.09); }
.preset-name { font-size: 12.5px; color: var(--text); font-weight: 600; }
.preset.on .preset-name { color: var(--cyan-ink); }
.preset-desc { font-size: 11px; color: var(--muted); line-height: 1.6; }
.preset.on .preset-desc { color: var(--text-2); }

.step-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(186px, 1fr)); gap: 8px; }
.step-card {
  display: grid; grid-template-columns: 18px 1fr; grid-template-areas: 'idx name' 'idx desc' 'idx hint';
  align-content: start; gap: 2px 7px;
  padding: 9px 10px; text-align: left;
  border-radius: 9px; border: 1px solid var(--line);
  background: var(--panel-2, rgba(120, 200, 220, 0.03));
  transition: border-color 0.15s, background 0.15s;
}
.step-card:hover { border-color: var(--line-strong); }
.step-card.on { border-color: rgba(52, 229, 200, 0.42); background: rgba(52, 229, 200, 0.08); }
.step-idx {
  grid-area: idx;
  display: grid; place-items: center;
  width: 18px; height: 18px; margin-top: 1px; border-radius: 6px;
  border: 1px solid var(--line); font-family: var(--mono); font-size: 10.5px; color: var(--muted);
}
.step-card.on .step-idx { border-color: rgba(52, 229, 200, 0.5); color: var(--cyan-ink); }
.step-name { grid-area: name; font-size: 12.5px; color: var(--text); }
.step-desc { grid-area: desc; font-size: 10.5px; color: var(--muted); line-height: 1.55; }
.step-hint { grid-area: hint; font-size: 10px; color: var(--warn, #f0c36d); line-height: 1.5; min-height: 0; }
.step-card:not(.on) { opacity: 0.78; border-style: dashed; }

/* 底部操作条：左侧面板再长，开跑按钮也一直可见 */
.action-bar {
  position: sticky; bottom: -1px; z-index: 5;
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  padding: 10px 12px; margin: 0 -2px;
  border: 1px solid var(--line); border-radius: 10px;
  background: var(--surface-2, rgba(16, 26, 32, 0.92));
  backdrop-filter: blur(6px);
  box-shadow: 0 -8px 18px rgba(0, 0, 0, 0.16);
}
.action-tip { font-size: 10.5px; color: var(--muted); margin-left: auto; }

.tip { font-size: 10.5px; color: var(--muted); line-height: 1.7; align-self: flex-end; min-width: 220px; }

.adv {
  border: 1px solid var(--line); border-radius: 10px;
  background: var(--panel-2, rgba(120, 200, 220, 0.03));
}
.adv > summary {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 13px; cursor: pointer; list-style: none;
  font-size: 12.5px; color: var(--text);
}
.adv > summary::-webkit-details-marker { display: none; }
.adv > summary::before { content: '＋'; color: var(--muted); font-size: 11px; }
.adv[open] > summary::before { content: '－'; }
.adv > summary .mono { font-size: 10.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.adv-body {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px;
  padding: 2px 13px 12px;
}

.ev-table { display: flex; flex-direction: column; gap: 5px; max-height: 190px; overflow-y: auto; }
.ev-row {
  display: grid; grid-template-columns: minmax(120px, 1.1fr) 52px 34px minmax(0, 2.4fr);
  align-items: center; gap: 8px; font-size: 11px;
}
.ev-dom { color: var(--text); overflow: hidden; text-overflow: ellipsis; }
.ev-score { color: var(--muted); text-align: right; }
.ev-why { color: var(--muted); line-height: 1.6; }
.tag.warn { color: var(--warn, #f0c36d); border-color: rgba(240, 195, 109, 0.35); background: rgba(240, 195, 109, 0.09); }

.step { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--line-soft); }
.step:last-of-type { border-bottom: none; }
.step.off { opacity: 0.45; }
.step-name { font-size: 12.5px; color: var(--text); }
.step-desc { font-size: 10.5px; color: var(--muted); }
.note {
  margin-top: 8px; padding: 8px 10px; border-radius: 8px;
  border: 1px solid var(--line-soft); background: rgba(120, 200, 220, 0.04);
  font-size: 10.5px; color: var(--muted); line-height: 1.75;
}
</style>
