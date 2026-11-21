import { createRouter, createWebHashHistory } from 'vue-router'
import { useAuthStore } from '@/stores'

// 菜单与路由同源：ARL-Next 的导航分层，视觉与交互对齐天鉴探微
export const NAV = [
  {
    group: '侦察',
    items: [
      { path: '/dashboard', name: 'Dashboard', title: '仪表盘', icon: 'dashboard', desc: '全局侦察态势' },
      { path: '/groups', name: 'Groups', title: '资产组', icon: 'group', desc: '按根域聚合的资产簇' },
      { path: '/tasks', name: 'Tasks', title: '任务', icon: 'tasks', desc: '侦察任务与进度' },
      { path: '/ops', name: 'Ops', title: '功能自检', icon: 'flow', desc: '每一项能力单独跑一次' },
      { path: '/assets', name: 'Assets', title: '资产搜索', icon: 'search', desc: '全量资产检索' },
      { path: '/risk', name: 'Risk', title: '脆弱资产', icon: 'shield', desc: '整体预览与按任务分隔' },
      { path: '/mobile', name: 'MobileRecon', title: '移动端', icon: 'globe', desc: '小程序 / App 测绘' },
    ],
  },
  {
    group: '编排',
    items: [
      { path: '/schedules', name: 'Schedules', title: '计划与调度', icon: 'clock', desc: '周期任务与变更监控' },
      { path: '/github', name: 'Github', title: 'GitHub 监控', icon: 'github', desc: '代码泄露持续监控' },
    ],
  },
  {
    group: '配置',
    items: [
      { path: '/ai', name: 'AiWorkshop', title: 'AI 工坊', icon: 'spark', desc: '语法生成 / 研判 / 小结 / 指纹' },
      { path: '/pocs', name: 'Pocs', title: 'POC 管理', icon: 'bug', desc: 'Nuclei 模板库' },
      { path: '/fingerprints', name: 'Fingerprints', title: '指纹管理', icon: 'tags', desc: 'Web 指纹规则' },
      { path: '/dicts', name: 'Dicts', title: '字典管理', icon: 'list', desc: '爆破与探测字典' },
      { path: '/policies', name: 'Policies', title: '策略配置', icon: 'control', desc: '扫描策略与采集开关' },
      { path: '/settings', name: 'Settings', title: '系统设置', icon: 'settings', desc: '数据源 / 通知 / 账号' },
    ],
  },
]

const routes = [
  { path: '/login', name: 'Login', component: () => import('@/views/Login.vue'), meta: { public: true } },
  {
    path: '/',
    component: () => import('@/views/Layout.vue'),
    redirect: '/dashboard',
    children: [
      { path: '/oneclick', name: 'OneClick', component: () => import('@/views/OneClick.vue'), meta: { title: '一键收集', parent: '/tasks' } },
      // ownActions：页面页头已有「刷新 / 一键收集全」，顶栏不再重复放同名按钮
      { path: '/dashboard', name: 'Dashboard', component: () => import('@/views/Dashboard.vue'), meta: { title: '仪表盘', ownActions: true } },
      { path: '/groups', name: 'Groups', component: () => import('@/views/Groups.vue'), meta: { title: '资产组' } },
      { path: '/group/:root', name: 'GroupDetail', component: () => import('@/views/GroupDetail.vue'), meta: { title: '资产组详情', parent: '/groups' } },
      { path: '/tasks', name: 'Tasks', component: () => import('@/views/Tasks.vue'), meta: { title: '任务', ownActions: true } },
      { path: '/tasks/:id', name: 'TaskDetail', component: () => import('@/views/TaskDetail.vue'), meta: { title: '任务详情', parent: '/tasks' } },
      { path: '/ops', name: 'Ops', component: () => import('@/views/Ops.vue'), meta: { title: '功能自检', ownActions: true } },
      { path: '/assets', name: 'Assets', component: () => import('@/views/Assets.vue'), meta: { title: '资产搜索', ownActions: true } },
      { path: '/risk', name: 'Risk', component: () => import('@/views/Risk.vue'), meta: { title: '脆弱资产' } },
      { path: '/mobile', name: 'MobileRecon', component: () => import('@/views/MobileRecon.vue'), meta: { title: '移动端测绘', ownActions: true } },
      { path: '/schedules', name: 'Schedules', component: () => import('@/views/Schedules.vue'), meta: { title: '计划与调度' } },
      { path: '/github', name: 'Github', component: () => import('@/views/GithubMonitor.vue'), meta: { title: 'GitHub 监控' } },
      { path: '/ai', name: 'AiWorkshop', component: () => import('@/views/AiWorkshop.vue'), meta: { title: 'AI 工坊' } },
      { path: '/pocs', name: 'Pocs', component: () => import('@/views/Pocs.vue'), meta: { title: 'POC 管理' } },
      { path: '/fingerprints', name: 'Fingerprints', component: () => import('@/views/Fingerprints.vue'), meta: { title: '指纹管理' } },
      { path: '/dicts', name: 'Dicts', component: () => import('@/views/Dicts.vue'), meta: { title: '字典管理' } },
      { path: '/policies', name: 'Policies', component: () => import('@/views/Policies.vue'), meta: { title: '策略配置' } },
      { path: '/settings', name: 'Settings', component: () => import('@/views/Settings.vue'), meta: { title: '系统设置' } },    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
]

const router = createRouter({ history: createWebHashHistory(), routes })

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  if (!auth.ready) await auth.refresh()
  if (!to.meta.public && !auth.logged) return { path: '/login', query: { from: to.fullPath } }
  if (to.path === '/login' && auth.logged) return { path: '/dashboard' }
  return true
})

export default router
