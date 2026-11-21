<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores'
import Icon from '@/components/Icon.vue'
import WindowControls from '@/components/WindowControls.vue'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const form = reactive({ username: 'admin', password: '' })
const loading = ref(false)
const error = ref('')

async function submit() {
  if (!form.username || !form.password) {
    error.value = '请输入账号和密码'
    return
  }
  loading.value = true
  error.value = ''
  try {
    await auth.login(form.username.trim(), form.password)
    router.replace(route.query.from || '/dashboard')
  } catch (e) {
    error.value = e?.response?.data?.detail || '登录失败，请检查账号密码'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-wrap">
    <WindowControls class="floating" />
    <div class="login-card">
      <div class="brand-mark"><Icon name="radar" :size="21" /></div>
      <h1 class="login-title">天鉴 · 索舆</h1>
      <p class="login-sub">TianJian SUOYU · 资产侦察平台</p>

      <form class="login-form" @submit.prevent="submit">
        <div class="field">
          <label class="field-label">账号</label>
          <input v-model="form.username" class="input" placeholder="admin" autocomplete="username" />
        </div>
        <div class="field">
          <label class="field-label">密码</label>
          <input
            v-model="form.password"
            class="input"
            type="password"
            placeholder="请输入密码"
            autocomplete="current-password"
            autofocus
          />
        </div>

        <div v-if="error" class="tag err" style="height: auto; padding: 6px 8px; white-space: normal">
          {{ error }}
        </div>

        <button class="btn primary" style="height: 36px; justify-content: center" :disabled="loading">
          <Icon name="key" :size="14" />
          <span>{{ loading ? '登录中…' : '进入作战台' }}</span>
        </button>
      </form>

      <p class="field-hint" style="margin-top: 18px; line-height: 1.7">
        企业主体 · 被动子域 · 空间测绘 · 端口指纹 · 站点爬虫 · 代码泄露<br />
        单进程运行，数据全部落在本机。
      </p>
    </div>
  </div>
</template>
