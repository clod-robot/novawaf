<template>
  <div class="mecha-panel p">
    <!-- 区块一：运行状态 -->
    <div class="bar">
      <el-button :loading="loading" @click="load">刷新</el-button>
      <el-upload :show-file-list="false" :auto-upload="false" :on-change="onPick" style="display:inline-block;margin:0 8px">
        <el-button type="primary" :loading="uploading" :disabled="busy">上传新版本</el-button>
      </el-upload>
      <el-button type="warning" :loading="restarting" :disabled="busy || !st.running" @click="onRestart">滚动重启</el-button>
      <el-button type="danger" plain :loading="rollingBack" :disabled="busy || !st.previous" @click="onRollback">版本回退</el-button>
    </div>

    <div class="hud-title">// 引擎运行状态</div>
    <el-descriptions :column="3" border size="small" class="meta">
      <el-descriptions-item label="状态">
        <el-tag :type="st.running ? 'success' : 'danger'" size="small">{{ st.running ? '运行中' : '已停止' }}</el-tag>
        <el-tag v-if="st.supervise" type="info" size="small" style="margin-left:6px">master/worker 监管</el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="当前版本">
        <span class="ver">{{ st.current || '-' }}</span>
      </el-descriptions-item>
      <el-descriptions-item label="回退版本">{{ st.previous || '-' }}</el-descriptions-item>
      <el-descriptions-item label="Master PID">{{ st.masterPid || '-' }}</el-descriptions-item>
      <el-descriptions-item label="监听端口">{{ st.port || '-' }}</el-descriptions-item>
      <el-descriptions-item label="运行时长">{{ fmtUptime(st.uptimeSec) }}</el-descriptions-item>
      <el-descriptions-item label="Worker" :span="3">
        <template v-if="workers.length">
          <el-tag v-for="w in workers" :key="w.pid" size="small" style="margin-right:6px"
                  :type="w.version === st.current ? 'success' : 'warning'">
            pid {{ w.pid }} · v{{ w.version || '?' }}
          </el-tag>
        </template>
        <span v-else>-</span>
      </el-descriptions-item>
    </el-descriptions>

    <!-- 区块二：版本清单 -->
    <div class="hud-title" style="margin-top:20px">// 版本清单（备份仅保留最近一版，升级/回退均为零停机滚动）</div>
    <DataTable :data="versions" :columns="columns" height="320px">
      <template #cell-version="{ row }">
        <span class="ver">{{ row.version }}</span>
        <el-tag v-if="row.current" type="success" size="small" style="margin-left:6px">当前</el-tag>
        <el-tag v-if="row.previous" type="info" size="small" style="margin-left:6px">上一版</el-tag>
      </template>
      <template #cell-size="{ row }">{{ fmtSize(row.size) }}</template>
      <template #cell-sha256="{ row }"><span class="sha">{{ (row.sha256 || '').slice(0, 16) }}</span></template>
      <template #cell-mtime="{ row }">{{ fmt(row.mtime * 1000) }}</template>
      <template #cell-op="{ row }">
        <el-button v-if="!row.current" size="small" type="primary" link :disabled="busy"
                   @click="onUpgrade(row.version)">升级到此版本</el-button>
        <span v-else class="muted">运行中</span>
      </template>
    </DataTable>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import DataTable from '../components/DataTable.vue'

const columns = [
  { prop: 'version', label: '版本', minWidth: 150, slot: 'version' },
  { prop: 'size', label: '大小', width: 100, slot: 'size', noSearch: true },
  { prop: 'sha256', label: 'SHA-256', minWidth: 150, slot: 'sha256', noSearch: true },
  { prop: 'mtime', label: '安装时间', width: 165, slot: 'mtime', noSearch: true },
  { label: '操作', width: 120, fixed: 'right', slot: 'op', noSearch: true }
]

const st = ref({})
const versions = ref([])
const loading = ref(false)
const uploading = ref(false)
const upgrading = ref(false)
const rollingBack = ref(false)
const restarting = ref(false)

const workers = computed(() => (Array.isArray(st.value.workers) ? st.value.workers : []))
const busy = computed(() => uploading.value || upgrading.value || rollingBack.value || restarting.value)

function fmt(t) {
  if (!t) return '-'
  const d = new Date(t)
  if (isNaN(d.getTime())) return '-'
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
function fmtSize(n) {
  if (!n) return '-'
  if (n < 1024) return n + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1048576).toFixed(1) + ' MB'
}
function fmtUptime(s) {
  if (!s) return '-'
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60)
  return (d ? d + '天 ' : '') + (h ? h + '时 ' : '') + m + '分'
}

onMounted(load)
async function load() {
  loading.value = true
  try {
    const d = (await api.sysOpsGet()) || {}
    st.value = d
    versions.value = Array.isArray(d.versions) ? d.versions : []
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { loading.value = false }
}

async function onPick(file) {
  if (!file || !file.raw) return
  uploading.value = true
  try {
    const fd = new FormData()
    fd.append('file', file.raw, 'novawaf-engine')
    const r = await api.sysOpsUpload(fd)
    ElMessage.success(`版本 ${r.version} 安装成功`)
    await load()
    await ElMessageBox.confirm(
      `新版本 ${r.version} 已安装。升级将以零停机滚动方式切换，旧版本保留为回退目标。`,
      '立即升级？',
      { confirmButtonText: '立即升级', cancelButtonText: '稍后', type: 'warning' }
    ).then(() => doUpgrade(r.version)).catch(() => {})
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { uploading.value = false }
}

function onUpgrade(version) {
  ElMessageBox.confirm(
    `以零停机滚动方式升级引擎到 ${version}？新旧 worker 重叠监听，切换过程无丢包；失败自动回切。`,
    '一键升级',
    { confirmButtonText: '升级', cancelButtonText: '取消', type: 'warning' }
  ).then(() => doUpgrade(version)).catch(() => {})
}
async function doUpgrade(version) {
  upgrading.value = true
  try {
    const r = await api.sysOpsUpgrade(version)
    ElMessage.success(`已升级到 ${r.version}（回退目标 ${r.previous || '-'}）`)
    await load()
  } catch (e) { await load() } finally { upgrading.value = false }
}

function onRollback() {
  ElMessageBox.confirm(
    `回退引擎到上一版本 ${st.value.previous}？同样为零停机滚动切换，失败自动回切当前版本。`,
    '版本回退',
    { confirmButtonText: '回退', cancelButtonText: '取消', type: 'danger' }
  ).then(async () => {
    rollingBack.value = true
    try {
      const r = await api.sysOpsRollback()
      ElMessage.success(`已回退到 ${r.version}`)
      await load()
    } catch (e) { await load() } finally { rollingBack.value = false }
  }).catch(() => {})
}

function onRestart() {
  ElMessageBox.confirm(
    '滚动重启引擎（同版本更换全部 worker，SO_REUSEPORT 重叠监听，零丢包）？',
    '滚动重启',
    { confirmButtonText: '重启', cancelButtonText: '取消', type: 'warning' }
  ).then(async () => {
    restarting.value = true
    try {
      await api.sysOpsRestart()
      ElMessage.success('滚动重启完成')
      await load()
    } catch (e) { await load() } finally { restarting.value = false }
  }).catch(() => {})
}
</script>

<style scoped>
.p { padding: 16px; }
.bar { margin-bottom: 12px; }
.meta { margin: 10px 0; }
.ver { color: var(--cyan); font-weight: 600; }
.sha { color: var(--muted); font-family: monospace; font-size: 12px; }
.muted { color: var(--muted); font-size: 12px; }
</style>
