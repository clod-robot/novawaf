<template>
  <div class="mecha-panel p">
    <div class="bar">
      <el-button type="primary" @click="openCreate">+ 新增策略</el-button>
      <el-button @click="load">刷新</el-button>
    </div>
    <el-alert type="info" :closable="false" show-icon style="margin-bottom:12px"
      title="按应用 + URL 路径前缀设置 WAF 处置动作，保存后自动即时发布、引擎约 3 秒内热生效。"
      description="策略按所属应用隔离，仅对该应用的请求生效（不选应用=全部应用）；同一应用下路径唯一。拦截(block)=命中攻击返回 403；仅记录(log)=观察期，命中攻击只记录日志/事件并正常转发，不拦截、不联动封禁；放行(pass)=该路径跳过 WAF 检测（DDoS/限流等体积防护仍生效）。支持末尾 * 通配，最具体前缀优先。访问/拦截/放行次数由引擎按策略实时累计。" />
    <DataTable v-loading="loading" :data="list" :columns="columns" height="calc(100vh - 260px)">
      <template #cell-appName="{ row }">
        <el-tag :type="row.appId ? 'primary' : 'info'" size="small" effect="plain">
          {{ row.appName || (row.appId ? '应用-' + row.appId : '全部应用') }}
        </el-tag>
      </template>
      <template #cell-prefix="{ row }"><code>{{ row.prefix }}</code></template>
      <template #cell-action="{ row }">
        <el-tag :type="actionTag(row.action)" size="small">{{ actionText(row.action) }}</el-tag>
      </template>
      <template #cell-hitCount="{ row }"><span class="num hit">{{ fmtNum(row.hitCount) }}</span></template>
      <template #cell-blockCount="{ row }"><span class="num blk">{{ fmtNum(row.blockCount) }}</span></template>
      <template #cell-passCount="{ row }"><span class="num pass">{{ fmtNum(row.passCount) }}</span></template>
      <template #cell-remark="{ row }">{{ row.remark || '-' }}</template>
      <template #cell-enabled="{ row }">
        <el-tag :type="row.enabled === true ? 'success' : 'info'" size="small">
          {{ row.enabled === true ? '启用' : '禁用' }}
        </el-tag>
      </template>
      <template #cell-updateTime="{ row }">{{ fmt(row.updateTime || row.createTime) }}</template>
      <template #cell-op="{ row }">
        <el-button size="small" type="primary" link @click="openEdit(row)">编辑</el-button>
        <el-button size="small" :type="row.enabled === true ? 'warning' : 'success'" link @click="toggle(row)">
          {{ row.enabled === true ? '禁用' : '启用' }}
        </el-button>
        <el-button size="small" type="danger" link @click="onDelete(row)">删除</el-button>
      </template>
    </DataTable>

    <el-dialog v-model="dlg" :title="form.id ? '编辑策略' : '新增策略'" width="480px" append-to-body>
      <el-form label-width="90px">
        <el-form-item label="所属应用" required>
          <el-select v-model="form.appId" placeholder="选择应用" style="width:100%">
            <el-option label="全部应用（全局生效）" value="" />
            <el-option v-for="a in apps" :key="a.id" :label="a.name + (a.host ? ' · ' + a.host : '')" :value="String(a.id)" />
          </el-select>
        </el-form-item>
        <el-form-item label="名称" required>
          <el-input v-model="form.name" maxlength="64" placeholder="如 Portal 接口观察期" />
        </el-form-item>
        <el-form-item label="路径" required>
          <el-input v-model="form.prefix" maxlength="255" placeholder="如 /api/portal/*" />
          <div style="margin-top:6px">
            <el-button size="small" @click="form.prefix = '/api/portal/*'">/api/portal/*</el-button>
            <el-button size="small" @click="form.prefix = '/api/auth/*'">/api/auth/*</el-button>
          </div>
        </el-form-item>
        <el-form-item label="动作" required>
          <el-radio-group v-model="form.action">
            <el-radio value="block">拦截</el-radio>
            <el-radio value="log">仅记录</el-radio>
            <el-radio value="pass">放行</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="备注"><el-input v-model="form.remark" maxlength="255" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="form.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dlg = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="onSave">保存并发布</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import DataTable from '../components/DataTable.vue'

const columns = [
  { prop: 'appName', label: '所属应用', minWidth: 130, slot: 'appName' },
  { prop: 'name', label: '策略名称', minWidth: 130 },
  { prop: 'prefix', label: '路径', minWidth: 180, slot: 'prefix' },
  { label: '动作', width: 100, slot: 'action', noSearch: true },
  { prop: 'hitCount', label: '访问次数', width: 110, slot: 'hitCount', align: 'right' },
  { prop: 'blockCount', label: '拦截次数', width: 110, slot: 'blockCount', align: 'right' },
  { prop: 'passCount', label: '放行次数', width: 110, slot: 'passCount', align: 'right' },
  { prop: 'remark', label: '备注', minWidth: 140, slot: 'remark' },
  { label: '状态', width: 85, slot: 'enabled', noSearch: true },
  { prop: 'updateTime', label: '更新时间', width: 165, slot: 'updateTime', noSearch: true },
  { label: '操作', width: 190, fixed: 'right', slot: 'op', noSearch: true }
]

const loading = ref(false)
const list = ref([])
const apps = ref([])
const dlg = ref(false)
const saving = ref(false)
const form = reactive({ id: null, appId: '', name: '', prefix: '', action: 'log', remark: '', enabled: true })

const ACTION_TEXT = { block: '拦截', log: '仅记录', pass: '放行' }
const actionText = (a) => ACTION_TEXT[a] || a
const actionTag = (a) => (a === 'block' ? 'danger' : a === 'log' ? 'warning' : 'success')
const fmtNum = (n) => (n == null ? '0' : Number(n).toLocaleString())
function fmt(t) {
  if (!t) return '-'
  const d = new Date(t)
  if (isNaN(d.getTime())) return String(t)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

onMounted(() => { loadApps(); load() })
async function loadApps() {
  try { apps.value = (await api.wafApps()) || [] } catch (e) { apps.value = [] }
}
async function load() {
  loading.value = true
  try { list.value = (await api.apiPolicyList()) || [] } finally { loading.value = false }
}
function resetForm() {
  Object.assign(form, { id: null, appId: '', name: '', prefix: '', action: 'log', remark: '', enabled: true })
}
function openCreate() {
  resetForm()
  // 应用区分：默认归属第一个应用，避免新策略误建为全局
  if (apps.value.length) form.appId = String(apps.value[0].id)
  dlg.value = true
}
function openEdit(row) {
  Object.assign(form, { enabled: true, ...row, appId: row.appId == null ? '' : String(row.appId) })
  dlg.value = true
}
async function onSave() {
  if (!form.name.trim()) { ElMessage.warning('请填写名称'); return }
  if (!form.prefix.trim() || !form.prefix.trim().startsWith('/')) {
    ElMessage.warning('路径必须以 / 开头'); return
  }
  saving.value = true
  try {
    if (form.id) await api.apiPolicyUpdate({ ...form })
    else await api.apiPolicyCreate({ ...form })
    ElMessage.success('已保存并发布')
    dlg.value = false
    load()
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { saving.value = false }
}
async function toggle(row) {
  await api.apiPolicyToggle(row.id, !(row.enabled === true))
  ElMessage.success('已更新并发布'); load()
}
async function onDelete(row) {
  await ElMessageBox.confirm(`确定删除策略「${row.name} ${row.prefix}」吗？`, '提示', { type: 'warning' })
  await api.apiPolicyDelete(row.id)
  ElMessage.success('已删除并发布'); load()
}
</script>

<style scoped>
.p { padding: 16px; }
.bar { margin-bottom: 12px; }
.num { font-variant-numeric: tabular-nums; font-weight: 600; }
.num.hit { color: #7fe7ff; }
.num.blk { color: #ff6b81; }
.num.pass { color: #5fe6a8; }
</style>
