import axios from 'axios'
import { ElMessage } from 'element-plus'

export const TOKEN_KEY = 'suoyu_token'

const http = axios.create({ baseURL: '', timeout: 120000 })

http.interceptors.request.use((cfg) => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

let expiredAt = 0
// 一个页面会并发发十几个请求，后端重启或大任务压着时它们会一起超时，只提示一次
let slowAt = 0

http.interceptors.response.use(
  // blob 也统一返回 res.data：下载调用点要的是 Blob 本身，返回整个 AxiosResponse 会被串成 [object Object]
  (res) => res.data,
  (err) => {
    const status = err?.response?.status
    const detail = err?.response?.data?.detail
    if (err?.code === 'ECONNABORTED' && Date.now() - slowAt > 5000) {
      slowAt = Date.now()
      ElMessage.warning('请求超时：后端可能在重启或正忙，稍后会自动重试')
    }
    if (status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      // 通知登录态 store 一起清空，否则路由守卫仍认为已登录，登录页会被弹回仪表盘
      window.dispatchEvent(new CustomEvent('suoyu:unauthorized'))
      // 一个页面会并发发好几个请求，401 会一起来，只提示一次
      if (!location.hash.includes('/login') && Date.now() - expiredAt > 3000) {
        expiredAt = Date.now()
        ElMessage.warning('登录已过期，请重新登录')
        location.hash = '#/login'
      }
    }
    if (detail && status !== 401) ElMessage.error(typeof detail === 'string' ? detail : '请求失败')
    else if (!detail && status && status >= 500) ElMessage.error(`服务异常 ${status}`)
    return Promise.reject(err)
  },
)

export default http
