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
      { path: 'waf/iplist', component: () => import('../views/Iplist.vue'), meta: { perm: 'waf:iplist:list', title: '黑白名单' } },
      { path: 'common/protect/api-policy', component: () => import('../views/ApiPolicy.vue'), meta: { perm: 'waf:apipolicy:list', title: 'API防护策略' } },
      { path: 'common/deploy', component: () => import('../views/Deploy.vue'), meta: { perm: 'system:deploy:view', title: '部署方式' } },
      { path: 'common/ipgroup', component: () => import('../views/IpGroup.vue'), meta: { perm: 'waf:ipgroup:list', title: 'IP 组' } },
      { path: 'common/accel', component: () => import('../views/Accel.vue'), meta: { perm: 'system:accel:list', title: '硬件加速' } },
      { path: 'system/user', component: () => import('../views/Users.vue'), meta: { perm: 'sys:user:list', title: '用户管理' } },
      { path: 'system/log', component: () => import('../views/AuditLog.vue'), meta: { perm: 'sys:log:list', title: '审计日志' } }
    ]
  }
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach(async (to) => {
  // HttpOnly Cookie JS 不可读，用非敏感登录标志做路由拦截；真实鉴权由后端 Cookie 校验，失效则 401 拦截器跳登录
  const authed = localStorage.getItem('nova_authed') === '1'
  if (to.meta.public) {
    if (authed && to.path === '/login') return '/dashboard'
    return true
  }
  if (!authed) return '/login'
  return true
})

export default router
