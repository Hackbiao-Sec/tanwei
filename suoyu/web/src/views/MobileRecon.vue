<script setup>
import { computed, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { searchApplet, searchMobile, appletLocal, searchMp } from '@/api/endpoints'

// 三条移动端面：微信小程序（名称 / 主体 / AppID）、公众号（昵称 / 主体 / 文章链接）、
// 应用（应用名 / 包名 / 本地包）
// 全部走公开渠道与本地静态提取，不需要任何 key，也不需要 AI
const tab = ref('applet')

function fmtSize(n) {
  const v = Number(n) || 0
  if (v >= 1048576) return `${(v / 1048576).toFixed(1)} MB`
  if (v >= 1024) return `${(v / 1024).toFixed(0)} KB`
  return `${v} B`
}

const appletQuery = ref('')
const appletRes = ref(null)
const appletErr = ref('')
const appletLoading = ref(false)

const appQuery = ref('')
const appPkg = ref('')
const appRes = ref(null)
const appErr = ref('')
const appLoading = ref(false)

// 公众号：昵称 / 主体名 / 品牌 / gh_ / __biz / 文章链接
const mpQuery = ref('')
const mpRes = ref(null)
const mpErr = ref('')
const mpLoading = ref(false)
const mps = computed(() => mpRes.value?.items || [])
// 昵称对得上检索词的才叫命中；low 相关的是同期文章只提到品牌，列出来但单独标
const mpHigh = computed(() => mps.value.filter((m) => m.relevance === 'high'))
const mpLow = computed(() => mps.value.filter((m) => m.relevance !== 'high'))
const mpDomainCount = computed(() => {
  const all = new Set()
  for (const m of mps.value) for (const d of m.domains || []) all.add(d)
  if (!all.size) for (const d of mpRes.value?.domains || []) all.add(d)
  return all.size
})

async function runMp() {
  mpErr.value = ''
  mpRes.value = null
  if (!mpQuery.value.trim()) {
    mpErr.value = '请输入公众号名、主体名，或粘贴一篇 mp.weixin.qq.com 文章链接'
    return
  }
  mpLoading.value = true
  try {
    mpRes.value = await searchMp({ target: mpQuery.value.trim(), limit: 8 })
  } catch (e) {
    mpErr.value = e?.response?.data?.detail || '查询失败，请查看服务日志'
  } finally {
    mpLoading.value = false
  }
}

const applets = computed(() => appletRes.value?.items || [])
const apps = computed(() => appRes.value?.items || [])
// 条目里列的是带子域的全名，顶层 domains 是根域；数字要对上列表，不然「11 个自有域」旁边
// 挂着 21 条看着像算错
const appDomainCount = computed(() => {
  const all = new Set()
  for (const a of apps.value) for (const d of a.domains || []) all.add(d)
  // 一条应用都没采到时只有顶层根域可数，两处取并会让徽标比列表多出几条
  if (!all.size) for (const d of appRes.value?.domains || []) all.add(d)
  return all.size
})

// 本机缓存：微信客户端会把用过的小程序包落在用户目录，解开即可拿接口与域名
const localRes = ref(null)
const localErr = ref('')
const localLoading = ref(false)

const localApps = computed(() => localRes.value?.apps || [])

async function runLocal() {
  localErr.value = ''
  localRes.value = null
  localLoading.value = true
  try {
    localRes.value = await appletLocal({ limit: 50 })
  } catch (e) {
    localErr.value = e?.response?.data?.detail || '扫描失败，请查看服务日志'
  } finally {
    localLoading.value = false
  }
}

async function runApplet() {
  appletErr.value = ''
  appletRes.value = null
  if (!appletQuery.value.trim()) {
    appletErr.value = '请输入小程序名、公司主体名，或 wx 开头的 AppID'
    return
  }
  appletLoading.value = true
  try {
    appletRes.value = await searchApplet({ target: appletQuery.value.trim(), limit: 8 })
  } catch (e) {
    appletErr.value = e?.response?.data?.detail || '查询失败，请查看服务日志'
  } finally {
    appletLoading.value = false
  }
}

async function runApp() {
  appErr.value = ''
  appRes.value = null
  if (!appQuery.value.trim() && !appPkg.value.trim()) {
    appErr.value = '请输入应用名、包名（com.xxx.yyy），或填本地 apk/ipa 路径'
    return
  }
  appLoading.value = true
  try {
    appRes.value = await searchMobile({
      target: appQuery.value.trim() || appPkg.value.trim(),
      package_path: appPkg.value.trim(),
      limit: 8,
    })
  } catch (e) {
    appErr.value = e?.response?.data?.detail || '查询失败，请查看服务日志'
  } finally {
    appLoading.value = false
  }
}
</script>

<template>
  <div class="stack">
    <PageHead
      title="移动端测绘"
      desc="小程序、公众号与应用三条面：名称/AppID/包名/文章链接 → 主体、下发域名、第三方 SDK。全部公开渠道，不依赖 AI 与 key"
    />

    <div class="tabs">
      <button class="tab" :class="{ on: tab === 'applet' }" @click="tab = 'applet'">
        <Icon name="control" :size="13" />微信小程序
      </button>
      <button class="tab" :class="{ on: tab === 'mp' }" @click="tab = 'mp'">
        <Icon name="chat" :size="13" />公众号
      </button>
      <button class="tab" :class="{ on: tab === 'app' }" @click="tab = 'app'">
        <Icon name="grid" :size="13" />App（Android / iOS）
      </button>
    </div>

    <div v-if="tab === 'applet'" class="stack">
      <div class="panel">
        <div class="panel-head"><span><Icon name="search" :size="13" />小程序检索</span></div>
        <div class="panel-body stack" style="gap: 10px">
          <input
            v-model="appletQuery"
            class="input"
            placeholder="小程序名 / 公司主体名 / wx 开头 18 位 AppID"
            @keyup.enter="runApplet"
          />
          <div class="row">
            <button class="btn primary" :disabled="appletLoading" @click="runApplet">
              <Icon name="bolt" :size="14" /><span>{{ appletLoading ? '查询中…' : '开始检索' }}</span>
            </button>
            <span class="muted" style="font-size: 11px">
              AppID 直查走微信公开档案页；名称检索取分享链、明文 AppID、收录页登记主体
            </span>
          </div>
        </div>
      </div>

      <div v-if="appletErr" class="tag err" style="height: auto; padding: 8px 10px; white-space: normal">{{ appletErr }}</div>

      <div class="panel">
        <div class="panel-head">
          <span><Icon name="control" :size="13" />本机缓存扫描</span>
          <span v-if="localRes" class="tag ok">{{ localApps.length }} 个包</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="row">
            <button class="btn" :disabled="localLoading" @click="runLocal">
              <Icon name="bolt" :size="14" /><span>{{ localLoading ? '扫描中…' : '扫描本机小程序缓存' }}</span>
            </button>
            <span class="muted" style="font-size: 11px">
              只读当前用户目录下的 wxapkg，离线解包后抽接口、域名、密钥命中
            </span>
          </div>

          <div v-if="localErr" class="tag err" style="height: auto; padding: 8px 10px; white-space: normal">{{ localErr }}</div>

          <div v-if="(localRes?.roots || []).length" class="field">
            <span class="field-label">发现的缓存根</span>
            <div class="mono" style="font-size: 11px; color: var(--text-2); line-height: 1.8">
              <div v-for="(r, i) in localRes.roots" :key="i">{{ r }}</div>
            </div>
          </div>

          <div v-for="(a, i) in localApps" :key="i" class="item">
            <div class="row">
              <span class="tag mono">{{ a.appid || '(无 AppID)' }}</span>
              <span v-if="a.version" class="tag">v{{ a.version }}</span>
              <span class="tag" :class="a.encrypted ? 'warn' : 'ok'">
                {{ a.encrypted ? '加密封装' : `解出 ${a.unpacked || 0} 文件` }}
              </span>
              <span class="muted" style="font-size: 11px">{{ fmtSize(a.bytes) }}</span>
            </div>
            <div v-if="(a.apis || []).length" class="mono muted" style="font-size: 11px">
              接口 {{ a.apis.length }}：{{ a.apis.slice(0, 6).join('　') }}
            </div>
            <div v-if="(a.domains || []).length" class="mono muted" style="font-size: 11px">
              域名 {{ a.domains.length }}：{{ a.domains.slice(0, 8).join('　') }}
            </div>
            <div v-if="(a.notes || []).length" class="muted" style="font-size: 11px">
              {{ (a.notes || []).join(' / ') }}
            </div>
          </div>

          <div v-if="(localRes?.errors || []).length" class="muted" style="font-size: 11px">
            {{ (localRes.errors || []).join(' / ') }}
          </div>
        </div>
      </div>

      <div v-if="appletRes" class="panel">
        <div class="panel-head">
          <span><Icon name="check" :size="13" />结果</span>
          <span class="tag ok">{{ applets.length }} 个小程序 · {{ (appletRes.domains || []).length }} 个域</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div v-for="(a, i) in applets" :key="i" class="item">
            <div class="row">
              <span style="font-size: 12.5px; color: var(--text)">{{ a.name || '(未取到名称)' }}</span>
              <span v-if="a.appid" class="tag mono">{{ a.appid }}</span>
              <span v-if="a.subject" class="tag cyan">{{ a.subject }}</span>
            </div>
            <div v-if="(a.domains || []).length" class="mono muted" style="font-size: 11px">
              {{ (a.domains || []).join('　') }}
            </div>
            <div v-if="(a.evidence || []).length" class="muted" style="font-size: 11px">
              {{ (a.evidence || []).join(' / ') }}
            </div>
            <div v-if="(a.notes || []).length" class="muted" style="font-size: 11px">
              {{ (a.notes || []).join(' / ') }}
            </div>
          </div>
          <div v-if="(appletRes.domains || []).length" class="field">
            <span class="field-label">下发域名（已过证据闸）</span>
            <div class="mono" style="font-size: 11.5px; color: var(--text-2)">{{ (appletRes.domains || []).join('　') }}</div>
          </div>
          <div v-if="(appletRes.notes || []).length" class="muted" style="font-size: 11px">
            {{ (appletRes.notes || []).join(' / ') }}
          </div>
        </div>
      </div>
    </div>

    <div v-else-if="tab === 'mp'" class="stack">
      <div class="panel">
        <div class="panel-head"><span><Icon name="search" :size="13" />公众号检索</span></div>
        <div class="panel-body stack" style="gap: 10px">
          <input
            v-model="mpQuery"
            class="input"
            placeholder="公众号名 / 公司主体名 / 品牌名 / gh_ 原始 ID / 文章链接"
            @keyup.enter="runMp"
          />
          <div class="row">
            <button class="btn primary" :disabled="mpLoading" @click="runMp">
              <Icon name="bolt" :size="14" /><span>{{ mpLoading ? '查询中…' : '开始检索' }}</span>
            </button>
            <span class="muted" style="font-size: 11px">
              站内检索拿文章直链 → 按 __biz 归号 → 主页取昵称与 gh_ → 代表文章抽「阅读原文」域
            </span>
          </div>
        </div>
      </div>

      <div v-if="mpErr" class="tag err" style="height: auto; padding: 8px 10px; white-space: normal">{{ mpErr }}</div>

      <div v-if="mpRes" class="panel">
        <div class="panel-head">
          <span><Icon name="check" :size="13" />结果</span>
          <span class="tag ok">{{ mps.length }} 个号 · {{ mpDomainCount }} 个域</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div v-if="!mps.length" class="muted" style="font-size: 12px">
            这次没采到号。检索通道被要求人机校验时也会是这个结果，先看下面的备注。
          </div>
          <div v-for="(m, i) in mpHigh" :key="'h' + i" class="item">
            <div class="row">
              <span class="tag ok">命中</span>
              <span style="font-size: 12.5px; color: var(--text)">{{ m.name || '(未取到昵称)' }}</span>
              <span v-if="m.wxid" class="tag mono">{{ m.wxid }}</span>
              <span v-if="m.subject" class="tag cyan">{{ m.subject }}</span>
            </div>
            <div v-if="m.biz" class="mono muted" style="font-size: 11px">__biz={{ m.biz }}</div>
            <div v-if="m.intro" class="muted" style="font-size: 11px">{{ m.intro }}</div>
            <div v-if="(m.domains || []).length" class="mono muted" style="font-size: 11px">
              下发域：{{ (m.domains || []).join('　') }}
            </div>
            <div v-if="(m.articles || []).length" class="muted" style="font-size: 11px">
              <div v-for="(a, j) in m.articles" :key="j">· {{ a.title || a.url }}</div>
            </div>
            <div v-if="(m.notes || []).length" class="muted" style="font-size: 11px">
              {{ (m.notes || []).join(' / ') }}
            </div>
          </div>
          <div v-if="mpLow.length" class="field">
            <span class="field-label">昵称对不上检索词（同期文章提到品牌，留作旁证）</span>
            <div class="muted" style="font-size: 11px; line-height: 1.9">
              <div v-for="(m, i) in mpLow" :key="'l' + i">
                {{ m.name || m.biz }} <span class="mono">{{ m.biz ? '__biz=' + m.biz : '' }}</span>
              </div>
            </div>
          </div>
          <div v-if="(mpRes.domains || []).length" class="field">
            <span class="field-label">下发域名（已过第三方过滤）</span>
            <div class="mono" style="font-size: 11.5px; color: var(--text-2)">{{ (mpRes.domains || []).join('　') }}</div>
          </div>
          <div v-if="(mpRes.notes || []).length" class="muted" style="font-size: 11px">
            {{ (mpRes.notes || []).join(' / ') }}
          </div>
        </div>
      </div>
    </div>

    <div v-else class="stack">
      <div class="panel">
        <div class="panel-head"><span><Icon name="search" :size="13" />应用检索</span></div>
        <div class="panel-body stack" style="gap: 10px">
          <input v-model="appQuery" class="input" placeholder="应用名 / 品牌名 / 包名（如 com.tencent.mm）" @keyup.enter="runApp" />
          <div class="field">
            <span class="field-label">本地包（可选）：apk / ipa 绝对路径，走离线静态提取</span>
            <input v-model="appPkg" class="input" placeholder="D:\samples\app.apk" />
          </div>
          <div class="row">
            <button class="btn primary" :disabled="appLoading" @click="runApp">
              <Icon name="bolt" :size="14" /><span>{{ appLoading ? '查询中…' : '开始检索' }}</span>
            </button>
            <span class="muted" style="font-size: 11px">iTunes 公开接口 · Google Play · 应用宝 / 华为 / 小米 等国内渠道</span>
          </div>
        </div>
      </div>

      <div v-if="appErr" class="tag err" style="height: auto; padding: 8px 10px; white-space: normal">{{ appErr }}</div>

      <div v-if="appRes" class="panel">
        <div class="panel-head">
          <span><Icon name="check" :size="13" />结果</span>
          <span class="tag ok">{{ apps.length }} 个应用 · {{ appDomainCount }} 个自有域</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div v-for="(a, i) in apps" :key="i" class="item">
            <div class="row">
              <span class="tag">{{ a.platform === 'ios' ? 'iOS' : 'Android' }}</span>
              <span style="font-size: 12.5px; color: var(--text)">{{ a.name }}</span>
              <span v-if="a.package" class="tag mono">{{ a.package }}</span>
              <span v-if="a.developer" class="tag cyan">{{ a.developer }}</span>
            </div>
            <div v-if="a.store_url" class="mono muted" style="font-size: 11px">{{ a.store_url }}</div>
            <!-- 商店登记的四列：分类 / 版本 / 更新时间 / 上架备案。备案是 APP 这条线唯一
                 不靠工信部接口就能拿到的号，藏起来等于白采 -->
            <div class="row" style="gap: 6px; flex-wrap: wrap">
              <span v-if="a.category" class="tag">{{ a.category }}</span>
              <span v-if="a.version" class="tag mono">v{{ a.version }}</span>
              <span v-if="a.updated" class="tag">更新 {{ a.updated }}</span>
              <span v-if="a.icp" class="tag ok">备案 {{ a.icp }}</span>
            </div>
            <div v-if="a.intro" class="muted" style="font-size: 11px">{{ a.intro }}</div>
            <div v-if="(a.domains || []).length" class="mono muted" style="font-size: 11px">
              自有域：{{ (a.domains || []).join('　') }}
            </div>
            <div v-if="(a.evidence || []).length" class="muted" style="font-size: 11px">
              {{ (a.evidence || []).join(' / ') }}
            </div>
          </div>
          <div v-if="Object.keys(appRes.sdk_domains || {}).length" class="field">
            <span class="field-label">第三方 SDK 域（不进资产库）</span>
            <div style="font-size: 11.5px; color: var(--text-2); line-height: 1.8">
              <span v-for="(tag, d) in appRes.sdk_domains" :key="d" class="tag" style="margin-right: 6px">
                {{ d }} · {{ tag }}
              </span>
            </div>
          </div>
          <div v-if="(appRes.notes || []).length" class="muted" style="font-size: 11px">
            {{ (appRes.notes || []).join(' / ') }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.tabs { display: flex; gap: 8px; }
.tab {
  display: flex; align-items: center; gap: 6px;
  height: 30px; padding: 0 13px; border-radius: 8px;
  border: 1px solid var(--line); background: rgba(6, 12, 18, 0.5);
  font-size: 12px; color: var(--text-2); cursor: pointer;
}
.tab.on { border-color: rgba(52, 229, 200, 0.45); background: rgba(52, 229, 200, 0.09); color: var(--cyan-ink); }
.item {
  display: flex; flex-direction: column; gap: 4px;
  padding: 9px 10px; border-radius: 8px;
  border: 1px solid var(--line-soft); background: rgba(6, 12, 18, 0.4);
}
</style>
