<template>
  <div class="login-wrap">
    <div class="mecha-panel login-box">
      <div class="brand"><span class="glow-cyan">◈ NOVA</span>WAF 智核</div>
      <div class="sub">MECHA CORE CONSOLE · 安全运维中枢</div>
      <el-form @submit.prevent="doLogin">
        <el-input v-model="f.username" placeholder="账号" size="large" prefix-icon="User" />
        <el-input v-model="f.password" type="password" placeholder="密码" size="large" prefix-icon="Lock" show-password @keyup.enter="doLogin" />
        <el-button type="primary" class="login-btn" :loading="loading" @click="doLogin">接入系统</el-button>
      </el-form>
      <div class="hint">默认 admin / Admin@2026</div>
    </div>
    <div class="grid-bg"></div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
const router = useRouter()
const f = reactive({ username: 'admin', password: '' })
const loading = ref(false)
async function doLogin() {
  if (!f.username || !f.password) return ElMessage.warning('请输入账号密码')
  loading.value = true
  try {
    const d = await api.login(f)
    localStorage.setItem('nova_token', d.token)
    localStorage.setItem('nova_perms', JSON.stringify(d.perms || []))
    localStorage.setItem('nova_admin', d.admin ? '1' : '0')
    localStorage.setItem('nova_user', d.nickname || d.username)
    ElMessage.success('认证通过,智核已上线')
    router.replace('/dashboard')
  } finally { loading.value = false }
}
</script>

<style scoped>
.login-wrap { height: 100vh; display: flex; align-items: center; justify-content: center; position: relative; }
.grid-bg { position: absolute; inset: 0; background-image: linear-gradient(rgba(0,229,255,0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,255,0.07) 1px, transparent 1px); background-size: 40px 40px; mask-image: radial-gradient(circle at center, black, transparent 75%); }
.login-box { width: 380px; padding: 38px 34px; position: relative; z-index: 1; }
.brand { font-size: 30px; font-weight: 700; letter-spacing: 2px; }
.brand span { color: var(--cyan); }
.sub { color: var(--muted); font-size: 12px; letter-spacing: 3px; margin: 6px 0 26px; }
.el-input { margin-bottom: 16px; }
.login-btn { width: 100%; margin-top: 8px; height: 44px; font-size: 16px; letter-spacing: 4px; }
.hint { margin-top: 14px; font-size: 11px; color: var(--muted); text-align: center; }
</style>
