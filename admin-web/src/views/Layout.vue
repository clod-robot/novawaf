<template>
  <el-container class="layout">
    <el-aside width="220px" class="aside mecha-panel">
      <div class="logo"><span class="glow-cyan">◈ NOVA</span>WAF</div>
      <el-menu :default-active="$route.path" router background-color="transparent" text-color="#9fc4e8" active-text-color="#00e5ff">
        <el-menu-item v-for="m in menus" :key="m.path" :index="m.path">
          <el-icon><component :is="m.icon" /></el-icon><span>{{ m.title }}</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="hud-title">// {{ $route.meta.title || 'SYSTEM ONLINE' }}</div>
        <div class="right">
          <span class="dot on"></span> 引擎在线
          <el-dropdown @command="onCmd">
            <span class="user">{{ user }}<el-icon><ArrowDown /></el-icon></span>
            <template #dropdown>
              <el-dropdown-menu><el-dropdown-item command="logout">退出登录</el-dropdown-item></el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      <el-main class="main"><router-view /></el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'
const router = useRouter()
const user = localStorage.getItem('nova_user') || 'operator'
const perms = computed(() => { try { return JSON.parse(localStorage.getItem('nova_perms') || '[]') } catch { return [] } })
const isAdmin = localStorage.getItem('nova_admin') === '1'
function has(p) { return isAdmin || perms.value.includes(p) }
const all = [
  { path: '/dashboard', title: '作战仪表盘', perm: 'dashboard', icon: 'Odometer' },
  { path: '/waf/app', title: '防护应用', perm: 'waf:app:list', icon: 'Grid' },
  { path: '/waf/log', title: '攻击日志', perm: 'waf:log:list', icon: 'Document' },
  { path: '/waf/rule', title: '规则管理', perm: 'waf:rule:list', icon: 'Setting' },
  { path: '/waf/ioc', title: '威胁情报', perm: 'waf:ioc:list', icon: 'Warning' },
  { path: '/system/user', title: '用户管理', perm: 'sys:user:list', icon: 'User' },
  { path: '/system/log', title: '审计日志', perm: 'sys:log:list', icon: 'Tickets' }
]
const menus = computed(() => all.filter(m => has(m.perm)))
async function onCmd(c) {
  if (c === 'logout') { await api.logout().catch(()=>{}); localStorage.clear(); router.replace('/login') }
}
</script>

<style scoped>
.layout { height: 100vh; }
.aside { margin: 10px; }
.logo { font-size: 20px; font-weight: 700; padding: 18px 16px; letter-spacing: 1px; }
.header { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--line); }
.right { display: flex; align-items: center; gap: 16px; color: var(--muted); font-size: 13px; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 4px; }
.dot.on { background: var(--green); box-shadow: 0 0 8px var(--green); }
.user { color: var(--cyan); cursor: pointer; display: flex; align-items: center; gap: 4px; }
.main { padding: 14px; overflow: auto; }
</style>
