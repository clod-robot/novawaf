<template>
  <div class="mecha-panel p">
    <!-- 独立筛选条：脱离表头，避免表头重排导致画面抖动 -->
    <div class="filter-bar">
      <el-select v-model="f.appId" size="small" clearable placeholder="所属应用" class="f-sel">
        <el-option label="全部应用" value="__all__" />
        <el-option v-for="a in apps" :key="a.id" :label="a.name" :value="String(a.id)" />
      </el-select>
      <el-input v-model="f.name" size="small" clearable placeholder="策略名称" class="f-inp" />
      <el-input v-model="f.prefix" size="small" clearable placeholder="路径前缀" class="f-inp" />
      <el-select v-model="f.action" size="small" clearable placeholder="动作" class="f-sel-sm">
        <el-option label="拦截" value="block" />
        <el-option label="仅记录" value="log" />
        <el-option label="放行" value="pass" />
      </el-select>
      <el-select v-model="f.enabled" size="small" clearable placeholder="状态" class="f-sel-sm">
        <el-option label="启用" value="1" />
        <el-option label="禁用" value="0" />
      </el-select>
      <el-input v-model="f.remark" size="small" clearable placeholder="备注" class="f-inp" />
      <span class="f-count">共 <b>{{ filtered.length }}</b> 条</span>
      <span style="flex:1"></span>
      <el-button size="small" @click="resetFilter">重置</el-button>
      <el-button size="small" @click="load">刷新</el-button>
      <el-button size="small" @click="openImport">批量导入</el-button>
      <el-button size="small" type="primary" @click="openCreate">+ 新增策略</el-button>
    </div>

    <el-alert type="info" :closable="false" show-icon style="margin-bottom:12px"
      title="按应用 + URL 路径前缀设置 WAF 处置动作，保存后自动即时发布、引擎约 3 秒内热生效。"
      description="策略按所属应用隔离，仅对该应用的请求生效（不选应用=全部应用）；同一应用下路径唯一。拦截(block)=命中攻击返回 403；仅记录(log)=观察期，命中攻击只记录日志/事件并正常转发，不拦截、不联动封禁；放行(pass)=该路径跳过 WAF 检测（DDoS/限流等体积防护仍生效）。支持末尾 * 通配，最具体前缀优先。访问/拦截/放行次数由引擎按策略实时累计。" />
    <DataTable :data="view" :columns="columns" :header-search="false" :loading="loading"
               height="calc(100vh - 300px)">
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

    <!-- 批量导入 -->
    <el-dialog v-model="impDlg" title="批量导入 API 防护策略" width="560px" append-to-body>
      <el-alert type="warning" :closable="false" show-icon style="margin-bottom:10px"
        title="仅支持 CSV（Excel 可用「另存为 CSV UTF-8」）。列顺序：序号, 请求格式, API接口, 动作, 所属应用, 策略名称, 备注。" />
      <div class="imp-actions">
        <el-button size="small" @click="downloadTemplate">下载表格模板</el-button>
        <el-upload ref="upRef" :auto-upload="false" :limit="1" accept=".csv" :on-change="onPick" :on-remove="onPick"
                   :file-list="fileList" style="display:inline-block;margin-left:8px">
          <el-button size="small" type="primary">选择 CSV 文件</el-button>
        </el-upload>
      </div>
      <div v-if="impResult" class="imp-result">
        <div class="ok">导入成功：<b>{{ impResult.success }}</b> 条</div>
        <div v-if="impResult.failed && impResult.failed.length" class="bad">
          失败 {{ impResult.failed.length }} 条：
          <ul>
            <li v-for="(x, i) in impResult.failed" :key="i">
              第 {{ x.line }} 行 {{ x.prefix }} — {{ x.reason }}
            </li>
          </ul>
        </div>
      </div>
      <template #footer>
        <el-button @click="impDlg = false">关闭</el-button>
        <el-button type="primary" :loading="importing" :disabled="!impFile" @click="doImport">开始导入</el-button>
      </template>
    </el-dialog>

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
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import DataTable from '../components/DataTable.vue'

const columns = [
  { prop: 'appName', label: '所属应用', minWidth: 130, slot: 'appName' },
  { prop: 'name', label: '策略名称', minWidth: 130 },
  { prop: 'prefix', label: '路径', minWidth: 180, slot: 'prefix' },
  { label: '动作', width: 100, slot: 'action' },
  { prop: 'hitCount', label: '访问次数', width: 105, slot: 'hitCount', align: 'right' },
  { prop: 'blockCount', label: '拦截次数', width: 105, slot: 'blockCount', align: 'right' },
  { prop: 'passCount', label: '放行次数', width: 105, slot: 'passCount', align: 'right' },
  { prop: 'remark', label: '备注', minWidth: 140, slot: 'remark' },
  { label: '状态', width: 85, slot: 'enabled' },
  { prop: 'updateTime', label: '更新时间', width: 165, slot: 'updateTime' },
  { label: '操作', width: 190, fixed: 'right', slot: 'op' }
]

const loading = ref(false)
const firstLoad = ref(true)
const list = ref([])
const apps = ref([])
const dlg = ref(false)
const saving = ref(false)
const form = reactive({ id: null, appId: '', name: '', prefix: '', action: 'log', remark: '', enabled: true })

// 独立筛选条件
const f = reactive({ appId: '', name: '', prefix: '', action: '', enabled: '', remark: '' })

const filtered = computed(() => {
  const kw = (s) => String(s || '').trim().toLowerCase()
  return list.value.filter((r) => {
    if (f.appId) {
      const want = f.appId === '__all__' ? '' : f.appId
      const cur = r.appId == null ? '' : String(r.appId)
      if (want !== cur) return false
    }
    if (f.action && r.action !== f.action) return false
    if (f.enabled && String(r.enabled === true ? 1 : 0) !== f.enabled) return false
    if (kw(f.name) && !kw(r.name).includes(kw(f.name))) return false
    if (kw(f.prefix) && !kw(r.prefix).includes(kw(f.prefix))) return false
    if (kw(f.remark) && !kw(r.remark).includes(kw(f.remark))) return false
    return true
  })
})
// 分页交给 DataTable，这里只传过滤结果
const view = computed(() => filtered.value)

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

onMounted(() => { loadApps(); load(); timer = setInterval(refreshCounts, 5000) })
onBeforeUnmount(() => { if (timer) clearInterval(timer) })

async function loadApps() {
  try { apps.value = (await api.wafApps()) || [] } catch (e) { apps.value = [] }
}
async function load() {
  loading.value = true
  try {
    const rows = (await api.apiPolicyList()) || []
    list.value = rows
  } finally { loading.value = false; firstLoad.value = false }
}
// 只刷新次数：原地更新字段，不替换数组、不触发整表重绘（消除抖动）
let timer = null
async function refreshCounts() {
  try {
    const rows = (await api.apiPolicyList()) || []
    const cur = list.value
    const same = cur.length === rows.length && cur.every((r, i) => r.id === rows[i].id)
    if (!same) { list.value = rows; return }
    for (let i = 0; i < rows.length; i++) {
      const a = cur[i]; const b = rows[i]
      if (a.hitCount !== b.hitCount) a.hitCount = b.hitCount
      if (a.blockCount !== b.blockCount) a.blockCount = b.blockCount
      if (a.passCount !== b.passCount) a.passCount = b.passCount
    }
  } catch (e) { /* 静默：后台刷新失败不打断操作 */ }
}
function resetFilter() { Object.assign(f, { appId: '', name: '', prefix: '', action: '', enabled: '', remark: '' }) }

function resetForm() {
  Object.assign(form, { id: null, appId: '', name: '', prefix: '', action: 'log', remark: '', enabled: true })
}
function openCreate() {
  resetForm()
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

// ---------------- 批量导入 ----------------
const impDlg = ref(false)
const impFile = ref(null)
const fileList = ref([])
const importing = ref(false)
const impResult = ref(null)
function openImport() { impResult.value = null; impFile.value = null; fileList.value = []; impDlg.value = true }
function onPick(file) { impFile.value = file && file.raw ? file.raw : null; fileList.value = file ? [file] : [] }
async function downloadTemplate() {
  try {
    const blob = await api.apiPolicyTemplate()
    const url = URL.createObjectURL(new Blob([blob], { type: 'text/csv;charset=utf-8' }))
    const a = document.createElement('a')
    a.href = url; a.download = 'API防护策略导入模板.csv'
    document.body.appendChild(a); a.click(); a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 3000)
  } catch (e) { ElMessage.error('模板下载失败') }
}
async function doImport() {
  if (!impFile.value) { ElMessage.warning('请先选择 CSV 文件'); return }
  importing.value = true
  try {
    const fd = new FormData()
    fd.append('file', impFile.value)
    const r = await api.apiPolicyImport(fd)
    impResult.value = r || { success: 0, failed: [] }
    ElMessage.success('导入完成，成功 ' + (impResult.value.success || 0) + ' 条')
    load()
  } catch (e) { /* 拦截器已提示 */ } finally { importing.value = false }
}
</script>

<style scoped>
.p { padding: 16px; }
.filter-bar {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  margin-bottom: 10px; padding: 8px 10px;
  border: 1px solid rgba(0, 229, 255, 0.18);
  border-radius: 6px; background: rgba(0, 229, 255, 0.04);
  transition: box-shadow .25s ease;
}
.filter-bar:hover { box-shadow: 0 0 12px rgba(0, 229, 255, 0.15); }
.f-inp { width: 140px; }
.f-sel { width: 140px; }
.f-sel-sm { width: 96px; }
.f-count { font-size: 12px; color: var(--muted, #889); }
.f-count b { color: #7fe7ff; }
.num { font-variant-numeric: tabular-nums; font-weight: 600; }
.num.hit { color: #7fe7ff; }
.num.blk { color: #ff6b81; }
.num.pass { color: #5fe6a8; }
.imp-actions { display: flex; align-items: center; }
.imp-result { margin-top: 10px; font-size: 13px; }
.imp-result .ok { color: #5fe6a8; }
.imp-result .bad { color: #ff6b81; margin-top: 4px; }
.imp-result ul { margin: 4px 0 0 18px; }
</style>
