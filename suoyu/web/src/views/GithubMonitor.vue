<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { getConfig, listAssets, saveConfig } from '@/api/endpoints'

const router = useRouter()
const token = ref('')
const saving = ref(false)
const leaks = ref([])
const loading = ref(false)
const keyword = ref('')

const ready = computed(() => Boolean(token.value && !token.value.includes('*')))

async function loadToken() {
  try {
    const res = await getConfig()
    token.value = res.config?.sources?.github?.token || ''
  } catch {
    /* 配置拉不到时保持空 */
  }
}

async function save() {
  saving.value = true
  try {
    await saveConfig({ sources: { github: { token: token.value.trim(), enabled: true } } })
  } finally {
    saving.value = false
  }
}

async function loadLeaks() {
  loading.value = true
  try {
    const res = await listAssets({ kind: 'leak', limit: 300, keyword: keyword.value.trim() || undefined })
    leaks.value = res.items || []
  } finally {
    loading.value = false
  }
}

function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

onMounted(() => {
  loadToken()
  loadLeaks()
})
</script>

<template>
  <div class="stack">
    <PageHead title="GitHub 监控" desc="用 GitHub 代码搜索持续找泄露：仓库里出现的域名、密钥、内部地址都会进资产库的 leak 类型">
      <template #actions>
        <button class="btn sm" @click="loadLeaks"><Icon name="refresh" :size="13" />刷新泄露</button>
        <button class="btn primary sm" @click="router.push('/oneclick')"><Icon name="bolt" :size="13" />跑一轮任务</button>
      </template>
    </PageHead>

    <div class="cards two">
      <div class="panel">
        <div class="panel-head">
          <span><Icon name="github" :size="13" />代码搜索凭据</span>
          <span class="tag" :class="ready ? 'ok' : 'warn'">{{ ready ? '已配置' : '未配置' }}</span>
        </div>
        <div class="panel-body stack" style="gap: 10px">
          <div class="field">
            <span class="field-label">GitHub Personal Access Token</span>
            <input v-model="token" class="input mono" type="password" placeholder="ghp_…" />
            <span class="field-hint">只需 public_repo / read 权限的只读 token。已保存的值会打码显示，不改动就保持原值。</span>
          </div>
          <div class="row">
            <button class="btn sm primary" :disabled="saving" @click="save"><Icon name="check" :size="12" />保存</button>
            <a class="btn sm" href="https://github.com/settings/tokens" target="_blank" rel="noopener">
              <Icon name="external" :size="12" />去申请
            </a>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head"><span><Icon name="shield" :size="13" />监控范围说明</span></div>
        <div class="panel-body" style="font-size: 11.5px; color: var(--text-2); line-height: 1.9">
          任务在「深度挖掘」阶段会对每个根域执行三类检索：仓库描述与 README、代码内容里的域名 / 邮箱 / 内部主机、
          以及常见密钥格式（AK/SK、私钥头、连接串）。命中的条目按 <span class="mono">leak</span> 类型入库，
          并在任务详情「任务资产」里按类型筛选查看。<br />
          配合「计划与调度」周期跑，就能持续看到新冒出来的泄露。
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <span><Icon name="alert" :size="13" />泄露条目</span>
        <div class="flex gap-8">
          <input v-model="keyword" class="input" style="height: 24px; width: 200px" placeholder="过滤关键字" @keyup.enter="loadLeaks" />
          <span class="mono muted">{{ leaks.length }}</span>
        </div>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>类型</th><th>地址 / 内容</th><th>标题</th><th>来源</th><th>发现时间</th></tr></thead>
          <tbody>
            <tr v-for="a in leaks" :key="a.id">
              <td><span class="tag err">{{ a.kind }}</span></td>
              <td class="mono cell-url" :title="a.url">
                <a v-if="String(a.url).startsWith('http')" :href="a.url" target="_blank" rel="noopener">{{ a.url }}</a>
                <span v-else>{{ a.url }}</span>
              </td>
              <td class="ellipsis" style="max-width: 260px">{{ a.title }}</td>
              <td class="muted ellipsis" style="max-width: 160px">{{ a.sources }}</td>
              <td class="mono muted">{{ fmtTime(a.first_seen) }}</td>
            </tr>
            <tr v-if="!leaks.length && !loading">
              <td colspan="5"><div class="empty"><Icon name="github" :size="22" />还没有泄露条目，先配置 token 再跑一轮深度任务</div></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
