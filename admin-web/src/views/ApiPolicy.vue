<template>
  <div class="mecha-panel p">
    <div class="bar">
      <el-button type="primary" @click="openCreate">+ 新增策略</el-button>
      <el-button @click="load">刷新</el-button>
    </div>
    <el-alert type="info" :closable="false" show-icon style="margin-bottom:12px"
      title="按 URL 路径前缀设置 WAF 处置动作，保存后自动即时发布、引擎约 3 秒内热生效。"
      description="拦截(block)=命中攻击返回 403；仅记录(log)=观察期，命中攻击只记录日志/事件并正常转发，不拦截、不联动封禁；放行(pass)=该路径跳过 WAF 检测（DDoS/限流等体积防护仍生效）。支持末尾 * 通配，如 /api/portal/*，最具体前缀优先。" />
    <DataTable v-loading="loading" :data="list" :columns="columns" height="calc(100vh - 260px)">
      <template #cell-prefix="{ row }"><code>{{ row.prefix }}</code></template>
      <template #cell-action="{ row }">
        <el-tag :type="actionTag(row.action)" size="small">{{ actionText(row.action) }}</el-tag>
      </template>
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
  { prop: 'name', label: '策略名称', minWidth: 140 },
  { prop: 'prefix', label: '路径', minWidth: 200, slot: 'prefix' },
  { label: '动作', width: 110, slot: 'action', noSearch: true },
  { prop: 'remark', label: '备注', minWidth: 160, slot: 'remark' },
  { label: '状态', width: 90, slot: 'enabled', noSearch: true },
  { prop: 'updateTime', label: '更新时间', width: 170, slot: 'updateTime', noSearch: true },
  { label: '操作', width: 200, fixed: 'right', slot: 'op', noSearch: true }
]

const loading = ref(false)
const list = ref([])
const dlg = ref(false)
const saving = ref(false)
const form = reactive({ id: null, name: '', prefix: '', action: 'log', remark: '', enabled: true })

const ACTION_TEXT = { block: '拦截', log: '仅记录', pass: '放行' }
const actionText = (a) => ACTION_TEXT[a] || a
const actionTag = (a) => (a === 'block' ? 'danger' : a === 'log' ? 'warning' : 'success')
function fmt(t) {
  if (!t) return '-'
  const d = new Date(t)
  if (isNaN(d.getTime())) return String(t)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

onMounted(load)
async function load() {
  loading.value = true
  try { list.value = (await api.apiPolicyList()) || [] } finally { loading.value = false }
}
function resetForm() {
  Object.assign(form, { id: null, name: '', prefix: '', action: 'log', remark: '', enabled: true })
}
function openCreate() { resetForm(); dlg.value = true }
function openEdit(row) { Object.assign(form, { enabled: true, ...row }); dlg.value = true }
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
</style>
