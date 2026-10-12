import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/login', component: () => import('../views/Login.vue'), meta: { public: true } },
  {
    path: '/',
    component: () => import('../views/Layout.vue'),
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', component: () => import('../views/Dashboard.vue'), meta: { perm: 'dashboard', title: '作战仪表盘' } },
      { path: 'waf/app', component: () => import('../views/Apps.vue'), meta: { perm: 'waf:app:list', title: '防护应用' } },
      { path: 'waf/log', component: () => import('../views/Logs.vue'), meta: { perm: 'waf:log:list', title: '日志管理' } },
      { path: 'waf/rule', component: () => import('../views/Rules.vue'), meta: { perm: 'waf:rule:list', title: '规则管理' } },
      { path: 'waf/ioc', component: () => import('../views/Ioc.vue'), meta: { perm: 'waf:ioc:list', title: '威胁情报' } },
      { path: 'system/user', component: () => import('../views/Users.vue'), meta: { perm: 'sys:user:list', title: '用户管理' } },
      { path: 'system/log', component: () => import('../views/AuditLog.vue'), meta: { perm: 'sys:log:list', title: '审计日志' } }
    ]
  }
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach(async (to) => {
  const token = localStorage.getItem('nova_token')
  if (to.meta.public) {
    if (token && to.path === '/login') return '/dashboard'
    return true
  }
  if (!token) return '/login'
  return true
})

export default router
