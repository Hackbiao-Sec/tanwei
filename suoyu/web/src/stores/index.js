import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { login as apiLogin, me as apiMe, logout as apiLogout } from '@/api/endpoints'
import { TOKEN_KEY } from '@/api/http'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem(TOKEN_KEY) || '')
  const user = ref('')
  const ready = ref(false)

  // 401 只清了 localStorage 的话，这里的内存副本还在，路由守卫会以为仍登录着：
  // 跳登录页又被弹回仪表盘，用户看到的是满屏空白。
  window.addEventListener('suoyu:unauthorized', () => {
    token.value = ''
    user.value = ''
    ready.value = true
  })

  const logged = computed(() => Boolean(token.value || user.value))

  async function login(username, password) {
    const res = await apiLogin(username, password)
    token.value = res.token
    localStorage.setItem(TOKEN_KEY, res.token)
    user.value = res.username || username
    return res
  }

  async function refresh() {
    if (!token.value) {
      // 登录接口同时种了 HttpOnly Cookie，重启前端后可以靠它恢复会话
      try {
        const res = await apiMe()
        user.value = res.username || ''
        ready.value = true
        return true
      } catch {
        ready.value = true
        return false
      }
    }
    try {
      const res = await apiMe()
      user.value = res.username || user.value
      ready.value = true
      return true
    } catch {
      token.value = ''
      localStorage.removeItem(TOKEN_KEY)
      ready.value = true
      return false
    }
  }

  async function logout() {
    await apiLogout()
    token.value = ''
    user.value = ''
    localStorage.removeItem(TOKEN_KEY)
  }

  return { token, user, ready, logged, login, refresh, logout }
})

export const useUiStore = defineStore('ui', () => {
  const theme = ref(localStorage.getItem('suoyu_theme') || 'dark')
  const collapsed = ref(localStorage.getItem('suoyu_collapsed') === '1')

  function setTheme(next) {
    theme.value = next
    localStorage.setItem('suoyu_theme', next)
    document.documentElement.dataset.theme = next
  }
  function toggleTheme() {
    setTheme(theme.value === 'dark' ? 'light' : 'dark')
  }
  function toggleCollapsed() {
    collapsed.value = !collapsed.value
    localStorage.setItem('suoyu_collapsed', collapsed.value ? '1' : '0')
  }
  function boot() {
    document.documentElement.dataset.theme = theme.value
  }

  return { theme, collapsed, setTheme, toggleTheme, toggleCollapsed, boot }
})
