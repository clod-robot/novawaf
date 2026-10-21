<template>
  <div class="mecha-panel p">
    <div class="bar">
      <el-button @click="loadAll">刷新</el-button>
      <el-button type="primary" @click="openAddGroup">+ 添加 IP 组</el-button>
    </div>

    <!-- 区块一：GeoIP 地域访问策略 -->
    <div class="hud-title">// 地域访问策略（GeoIP）</div>
    <div class="sub" style="margin-top:0">
      共 {{ stats.totalRanges || 0 }} 个国家网段 · {{ (stats.countries || []).length }} 个国家 ·
      引擎每 3 秒热加载，保存即生效
    </div>
    <el-form label-width="110px" style="max-width:760px">
      <el-form-item label="策略模式">
        <el-radio-group v-model="geo.mode">
          <el-radio value="off">关闭</el-radio>
          <el-radio value="whitelist">仅允许选中国家</el-radio>
          <el-radio value="blacklist">封禁选中国家</el-radio>
        </el-radio-group>
      </el-form-item>
      <el-form-item v-if="geo.mode !== 'off'" label="选中国家">
        <el-select v-model="geo.countries" multiple filterable style="width:100%"
                   placeholder="如：CN 中国大陆，可多选（仅允许国内+部分国外场景选 CN 及放行的国家）">
          <el-option v-for="c in (stats.countries || [])" :key="c.cc"
                     :value="c.cc" :label="`${c.name} (${c.count})`" />
        </el-select>
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="geoSaving" @click="saveGeo">保存策略</el-button>
        <span v-if="geoCurrent.mode && geoCurrent.mode !== 'off'" class="cur-policy">
          当前生效：{{ geoCurrent.mode === 'whitelist' ? '仅允许' : '封禁' }}
          {{ (geoCurrent.countries || []).length }} 个国家
        </span>
        <span v-else class="cur-policy">当前未启用地域策略</span>
      </el-form-item>
    </el-form>

    <!-- 区块二：IP 组列表 -->
    <div class="hud-title" style="margin-top:18px">// IP 组（共 {{ groups.length }} 个组）</div>
    <DataTable :data="groups" :columns="groupColumns" height="300px">
      <template #cell-name="{ row }">
        <span>{{ row.name }}</span>
        <el-tag v-if="row.type === 'threat'" size="small" type="warning" style="margin-left:6px">威胁情报</el-tag>
        <el-tag v-else size="small" :type="row.action === 'allow' ? 'success' : 'danger'" style="margin-left:6px">
          {{ row.action === 'allow' ? '放行' : '拦截' }}
        </el-tag>
        <el-tag v-if="!row.enabled" size="small" type="info" style="margin-left:6px">已禁用</el-tag>
      </template>
      <template #cell-updateTime="{ row }">{{ fmt(row.updateTime) }}</template>
      <template #cell-op="{ row }">
        <el-button size="small" type="primary" link @click="openEntries(row)">条目</el-button>
        <el-button v-if="row.type === 'threat' || row.sourceUrl" size="small" type="warning" link
                   :loading="updatingId === row.id" @click="runUpdate(row)">更新</el-button>
        <el-button size="small" type="primary" link @click="openEditGroup(row)">编辑</el-button>
        <el-button size="small" type="danger" link @click="delGroup(row)">删除</el-button>
      </template>
    </DataTable>

    <!-- 组编辑对话框 -->
    <el-dialog v-model="groupDlg" :title="groupForm.id === null ? '添加 IP 组' : '编辑 IP 组'" width="520px" append-to-body>
      <el-form label-width="100px">
        <el-form-item label="名称" required>
          <el-input v-model="groupForm.name" maxlength="64" placeholder="如：恶意 IP 情报组 / 办公网出口" />
        </el-form-item>
        <el-form-item label="类型" required>
          <el-radio-group v-model="groupForm.type" :disabled="groupForm.id !== null">
            <el-radio value="threat">威胁情报（固定拦截）</el-radio>
            <el-radio value="custom">自定义</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="groupForm.type === 'custom'" label="生效动作" required>
          <el-radio-group v-model="groupForm.action">
            <el-radio value="block">并入黑名单（拦截）</el-radio>
            <el-radio value="allow">并入白名单（放行）</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="源 URL">
          <el-input v-model="groupForm.sourceUrl" maxlength="512"
                    placeholder="可选。http/https 文本源（每行 IP/CIDR），配置后可点“更新”手动拉取" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="groupForm.enabled" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="groupForm.remark" type="textarea" :rows="2" maxlength="255" show-word-limit />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="groupDlg = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveGroup">确定</el-button>
      </template>
    </el-dialog>

    <!-- 条目管理抽屉 -->
    <el-drawer v-model="entryDrawer" :title="`条目管理 - ${currentGroup ? currentGroup.name : ''}`" size="560px" append-to-body>
      <div class="bar">
        <el-button size="small" type="primary" @click="addEntryDlg = true">+ 添加条目</el-button>
        <el-button size="small" type="success" @click="importDlg = true">导入</el-button>
        <el-button size="small" type="danger" @click="clearEntries">清空</el-button>
        <span class="sub" style="margin-left:8px">共 {{ entryTotal }} 个</span>
      </div>
      <DataTable :data="entries" :columns="entryColumns" height="360px" v-loading="entryLoading">
        <template #cell-op="{ row }">
          <el-button size="small" type="danger" link @click="delEntry(row.value)">删除</el-button>
        </template>
      </DataTable>
      <div class="sub" style="margin-top:8px">条目顺序为无序存储（Redis SET），已自动去重。</div>
    </el-drawer>

    <!-- 添加单条 -->
    <el-dialog v-model="addEntryDlg" title="添加条目" width="420px" append-to-body>
      <el-input v-model="newEntry" placeholder="如 1.2.3.4 或 10.0.0.0/24" @keyup.enter="addEntry" />
      <template #footer>
        <el-button @click="addEntryDlg = false">取消</el-button>
        <el-button type="primary" :loading="entrySaving" @click="addEntry">确定</el-button>
      </template>
    </el-dialog>

    <!-- 导入 -->
    <el-dialog v-model="importDlg" title="导入条目" width="560px" append-to-body>
      <div class="sub" style="margin-top:0">每行一个 IPv4 或 CIDR 网段，# 开头为注释；支持粘贴或选择本地 txt 文件（≤8MB）。</div>
      <input type="file" accept=".txt,.list,.log" class="file-input" @change="onFilePick" />
      <el-input v-model="importText" type="textarea" :rows="12"
                placeholder="1.2.3.4&#10;10.0.0.0/8&#10;# 注释行会被忽略" />
      <template #footer>
        <el-button @click="importDlg = false">取消</el-button>
        <el-button type="primary" :loading="entrySaving" @click="doImport">导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import DataTable from '../components/DataTable.vue'

const groupColumns = [
  { prop: 'name', label: '名称', minWidth: 160, slot: 'name' },
  { prop: 'summary', label: '内容', minWidth: 280 },
  { prop: 'updateTime', label: '更新时间', width: 170, slot: 'updateTime', noSearch: true },
  { label: '操作', width: 230, fixed: 'right', slot: 'op', noSearch: true }
]

const stats = reactive({ totalRanges: 0, countries: [] })
const geo = reactive({ mode: 'off', countries: [] })
const geoCurrent = reactive({ mode: 'off', countries: [] })
const geoSaving = ref(false)
const groups = ref([])
const saving = ref(false)
const groupDlg = ref(false)
const groupForm = reactive({ id: null, name: '', type: 'custom', action: 'block', sourceUrl: '', remark: '', enabled: true })

const entryColumns = [
  { prop: 'value', label: 'IP / CIDR', minWidth: 200 },
  { label: '操作', width: 90, fixed: 'right', slot: 'op', noSearch: true }
]

const entryDrawer = ref(false)
const currentGroup = ref(null)
const entries = ref([])
const entryTotal = ref(0)
const entryLoading = ref(false)
const entrySaving = ref(false)
const addEntryDlg = ref(false)
const newEntry = ref('')
const importDlg = ref(false)
const importText = ref('')
const updatingId = ref(null)
let pollTimer = null

function fmt(t) {
  if (!t) return '-'
  const d = new Date(t)
  if (isNaN(d.getTime())) return String(t)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

onMounted(loadAll)
onBeforeUnmount(() => { if (pollTimer) { clearInterval(pollTimer); pollTimer = null } })

async function loadAll() {
  await Promise.all([loadGeo(), loadGroups()])
}
async function loadGeo() {
  try {
    const [s, p] = await Promise.all([api.geoStats(), api.geoPolicyGet()])
    if (s) {
      stats.totalRanges = s.totalRanges || 0
      stats.countries = s.countries || []
    }
    const pol = p || {}
    geoCurrent.mode = pol.mode || 'off'
    geoCurrent.countries = pol.countries || []
    geo.mode = pol.mode || 'off'
    geo.countries = [...(pol.countries || [])]
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ }
}
async function saveGeo() {
  if (geo.mode !== 'off' && !geo.countries.length) {
    ElMessage.warning('请至少选择一个国家'); return
  }
  geoSaving.value = true
  try {
    const d = await api.geoPolicySave({ mode: geo.mode, countries: geo.mode === 'off' ? [] : geo.countries })
    if (d) {
      geoCurrent.mode = d.mode || 'off'
      geoCurrent.countries = d.countries || []
    }
    ElMessage.success('策略已保存，引擎将在 3 秒内热加载')
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { geoSaving.value = false }
}
async function loadGroups() {
  try {
    groups.value = (await api.ipGroupList()) || []
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ }
}
function openAddGroup() {
  Object.assign(groupForm, { id: null, name: '', type: 'threat', action: 'block', sourceUrl: '', remark: '', enabled: true })
  groupDlg.value = true
}
function openEditGroup(row) {
  Object.assign(groupForm, {
    id: row.id, name: row.name, type: row.type,
    action: row.action || 'block', sourceUrl: row.sourceUrl || '',
    remark: row.remark || '', enabled: !!row.enabled
  })
  groupDlg.value = true
}
async function saveGroup() {
  if (!groupForm.name.trim()) { ElMessage.warning('请填写组名'); return }
  saving.value = true
  try {
    const payload = {
      name: groupForm.name.trim(), type: groupForm.type, action: groupForm.action,
      sourceUrl: groupForm.sourceUrl.trim(), remark: groupForm.remark, enabled: groupForm.enabled
    }
    if (groupForm.id === null) await api.ipGroupCreate(payload)
    else await api.ipGroupUpdate(groupForm.id, payload)
    groupDlg.value = false
    ElMessage.success('已保存')
    await loadGroups()
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { saving.value = false }
}
async function delGroup(row) {
  try {
    await ElMessageBox.confirm(`确认删除 IP 组「${row.name}」？其条目将从黑/白名单或威胁情报通道中一并摘除。`, '删除确认', { type: 'warning' })
  } catch { return }
  try {
    await api.ipGroupDelete(row.id)
    ElMessage.success('已删除')
    await loadGroups()
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ }
}

// ---------- 条目 ----------
function openEntries(row) {
  currentGroup.value = row
  entryDrawer.value = true
  loadEntries()
}
async function loadEntries() {
  if (!currentGroup.value) return
  entryLoading.value = true
  try {
    const d = await api.ipGroupEntries(currentGroup.value.id, { page: 1, size: 10000 })
    entries.value = (d && d.items) || []
    entryTotal.value = (d && d.total) || 0
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { entryLoading.value = false }
}
async function addEntry() {
  if (!newEntry.value.trim()) { ElMessage.warning('请输入 IP/CIDR'); return }
  entrySaving.value = true
  try {
    await api.ipGroupAddEntry(currentGroup.value.id, newEntry.value.trim())
    newEntry.value = ''
    addEntryDlg.value = false
    ElMessage.success('已添加')
    await loadEntries(); await loadGroups()
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { entrySaving.value = false }
}
async function delEntry(v) {
  try {
    await api.ipGroupDelEntry(currentGroup.value.id, v)
    ElMessage.success('已删除')
    await loadEntries(); await loadGroups()
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ }
}
async function clearEntries() {
  try {
    await ElMessageBox.confirm('确认清空该组全部条目？', '清空确认', { type: 'warning' })
  } catch { return }
  try {
    await api.ipGroupClear(currentGroup.value.id)
    ElMessage.success('已清空')
    await loadEntries(); await loadGroups()
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ }
}
function onFilePick(ev) {
  const f = ev.target.files && ev.target.files[0]
  if (!f) return
  if (f.size > 8 * 1024 * 1024) { ElMessage.warning('文件超过 8MB 上限'); ev.target.value = ''; return }
  const r = new FileReader()
  r.onload = () => { importText.value = String(r.result || '') }
  r.readAsText(f)
  ev.target.value = ''
}
async function doImport() {
  if (!importText.value.trim()) { ElMessage.warning('请粘贴内容或选择文件'); return }
  entrySaving.value = true
  try {
    const d = await api.ipGroupImport(currentGroup.value.id, importText.value)
    ElMessage.success(`导入完成，新增 ${(d && d.added) || 0} 条`)
    importText.value = ''
    importDlg.value = false
    await loadEntries(); await loadGroups()
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { entrySaving.value = false }
}

// ---------- 更新（异步任务轮询） ----------
async function runUpdate(row) {
  try {
    await ElMessageBox.confirm(
      row.sourceUrl ? `从源 ${row.sourceUrl} 拉取并替换「${row.name}」条目？` : `运行威胁情报收集器并替换「${row.name}」条目？`,
      '更新确认', { type: 'info' })
  } catch { return }
  updatingId.value = row.id
  try {
    await api.ipGroupUpdateRun(row.id)
    ElMessage.success('更新任务已启动')
    if (pollTimer) clearInterval(pollTimer)
    pollTimer = setInterval(async () => {
      try {
        const t = await api.ipGroupTask(row.id)
        if (t && t.status !== 'running') {
          clearInterval(pollTimer); pollTimer = null
          updatingId.value = null
          if (t.status === 'done') {
            ElMessage.success(`更新完成，共 ${t.entryCount} 条`)
          } else {
            ElMessage.error(`更新失败：${t.error || '未知错误'}`)
          }
          await loadGroups()
        }
      } catch (e) { clearInterval(pollTimer); pollTimer = null; updatingId.value = null }
    }, 3000)
  } catch (e) { updatingId.value = null; /* 错误提示已由响应拦截器统一处理 */ }
}
</script>

<style scoped>
.p { padding: 16px; }
.bar { margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
.sub { color: var(--muted); font-size: 13px; margin: 6px 0; }
.cur-policy { color: var(--muted); font-size: 13px; margin-left: 12px; }
.file-input { margin-bottom: 10px; }
</style>
