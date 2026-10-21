<template>
  <div class="mecha-panel p">
    <div class="bar">
      <el-button @click="load">刷新</el-button>
    </div>

    <!-- 区块一：网络类型（后端探测结果，只读展示） -->
    <div class="hud-title">// 网络类型</div>
    <template v-if="nat">
      <div class="conclusion">
        <el-tag :type="natTag(nat.natType)" size="small">{{ nat.natType || '未知' }}</el-tag>
        <span :class="identifyCls">{{ identifyText }}</span>
      </div>
      <el-descriptions :column="2" border size="small" class="meta">
        <el-descriptions-item label="结论">{{ nat.title || '-' }}</el-descriptions-item>
        <el-descriptions-item label="探测时间">{{ fmt(nat.generatedAt) }}</el-descriptions-item>
        <el-descriptions-item label="建议" :span="2">{{ nat.advice || '-' }}</el-descriptions-item>
      </el-descriptions>
      <div class="sub">证据摘要</div>
      <el-descriptions :column="3" border size="small" class="meta">
        <el-descriptions-item v-for="e in evidenceList" :key="e.key" :label="e.label">{{ fmtVal(e.value) }}</el-descriptions-item>
      </el-descriptions>
      <el-button type="primary" :loading="detecting" @click="redetect" style="margin-top:12px">重新检测</el-button>
    </template>
    <el-empty v-else description="尚无探测结果，请点击重新检测">
      <el-button type="primary" :loading="detecting" @click="redetect">重新检测</el-button>
    </el-empty>

    <!-- 区块二：HA 配置（可编辑） -->
    <div class="hud-title" style="margin-top:20px">// HA 配置</div>
    <el-form label-width="90px">
      <el-form-item label="HA 模式">
        <el-radio-group v-model="ha.haMode">
          <el-radio value="single">单机</el-radio>
          <el-radio value="master-backup">主备</el-radio>
          <el-radio value="cluster">集群</el-radio>
        </el-radio-group>
      </el-form-item>
      <el-form-item label="VIP">
        <el-input v-model="ha.vip" maxlength="64" placeholder="可空，如 192.168.1.100" />
      </el-form-item>
      <el-form-item label="节点列表">
        <el-button size="small" type="primary" @click="openAddNode">+ 新增节点</el-button>
        <DataTable :data="nodeList" :columns="nodeColumns" height="240px" style="margin-top:8px">
          <template #cell-role="{ row }">{{ ROLE_TEXT[row.role] || row.role }}</template>
          <template #cell-enabled="{ row }">
            <el-switch v-model="row.enabled" @change="onToggleNode(row)" />
          </template>
          <template #cell-op="{ row, index }">
            <el-button size="small" type="primary" link @click="openEditNode(row, index)">编辑</el-button>
            <el-button size="small" type="danger" link @click="delNode(index)">删除</el-button>
          </template>
        </DataTable>
      </el-form-item>
      <el-form-item label="备注">
        <el-input v-model="ha.remark" type="textarea" :rows="3" maxlength="255" show-word-limit />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="saving" @click="onSave">保存</el-button>
      </el-form-item>
    </el-form>

    <el-dialog v-model="nodeDlg" :title="nodeForm.idx === null ? '新增节点' : '编辑节点'" width="460px" append-to-body>
      <el-form label-width="90px">
        <el-form-item label="名称" required>
          <el-input v-model="nodeForm.name" maxlength="64" placeholder="如 node-01" />
        </el-form-item>
        <el-form-item label="IP" required>
          <el-input v-model="nodeForm.ip" maxlength="64" placeholder="如 192.168.1.101" />
        </el-form-item>
        <el-form-item label="角色" required>
          <el-select v-model="nodeForm.role" style="width:100%">
            <el-option label="主(master)" value="master" />
            <el-option label="备(backup)" value="backup" />
            <el-option label="节点(node)" value="node" />
          </el-select>
        </el-form-item>
        <el-form-item label="优先级">
          <el-input-number v-model="nodeForm.priority" :min="0" :max="1000" />
        </el-form-item>
        <el-form-item label="启用"><el-switch v-model="nodeForm.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="nodeDlg = false">取消</el-button>
        <el-button type="primary" @click="saveNode">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import DataTable from '../components/DataTable.vue'

const nodeColumns = [
  { prop: 'name', label: '名称', minWidth: 120 },
  { prop: 'role', label: '角色', width: 90, slot: 'role' },
  { prop: 'priority', label: '优先级', width: 90 },
  { prop: 'ip', label: 'IP', minWidth: 140 },
  { label: '启用', width: 90, slot: 'enabled', noSearch: true },
  { label: '操作', width: 120, fixed: 'right', slot: 'op', noSearch: true }
]

const nat = ref(null)
const detecting = ref(false)
const saving = ref(false)
const nodeList = ref([])
const nodeDlg = ref(false)
const ha = reactive({ haMode: 'single', vip: '', remark: '' })
const nodeForm = reactive({ idx: null, name: '', ip: '', role: 'node', priority: 100, enabled: true })

const ROLE_TEXT = { master: '主', backup: '备', node: '节点' }
// evidence 关键项中文标签；未知键回退为原始键名
const EVIDENCE_LABELS = {
  gateway: '网关',
  localIp: '本机地址',
  localAddr: '本机地址',
  nginxSampleCount: 'nginx 日志采样数',
  nginxSamples: 'nginx 日志采样数',
  nginxUniqueSourceCount: '去重来源数',
  nginxUniqueSources: '去重来源数',
  nginxRecordXff: '是否记录 XFF',
  engineClientIp: '引擎记录到的 clientIp',
  trustedProxy: '可信代理',
  trustedProxies: '可信代理'
}

const evidenceList = computed(() => {
  const ev = nat.value && nat.value.evidence
  if (!ev || typeof ev !== 'object') return []
  return Object.entries(ev).map(([key, value]) => ({ key, label: EVIDENCE_LABELS[key] || key, value }))
})

const natTag = (t) => (t === 'DNAT' || t === 'L7_XFF' ? 'success' : t === 'SNAT' ? 'danger' : 'info')
// UNKNOWN 是证据不足而非明确“不能识别”，用橙色中性提示，避免红字误导
const identifyCls = computed(() => {
  if (!nat.value) return 'warn'
  if (nat.value.natType === 'UNKNOWN') return 'warn'
  return nat.value.canIdentifyExternalIp ? 'ok' : 'bad'
})
const identifyText = computed(() => {
  if (!nat.value || nat.value.natType === 'UNKNOWN') return '暂无法确认能否识别外网真实源 IP'
  return nat.value.canIdentifyExternalIp ? '可识别外网真实源 IP' : '无法识别外网真实源 IP'
})
function fmtVal(v) {
  if (v === null || v === undefined || v === '') return '-'
  if (typeof v === 'boolean') return v ? '是' : '否'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}
function fmt(t) {
  if (!t) return '-'
  const d = new Date(t)
  if (isNaN(d.getTime())) return String(t)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

onMounted(load)
async function load() {
  try {
    const d = (await api.deployGet()) || {}
    nat.value = d.nat || null
    const h = d.ha || {}
    ha.haMode = h.haMode || 'single'
    ha.vip = h.vip || ''
    ha.remark = h.remark || ''
    nodeList.value = parseNodes(h.nodes)
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ }
}
function parseNodes(nodes) {
  if (Array.isArray(nodes)) return nodes
  if (typeof nodes === 'string' && nodes.trim()) {
    try { const a = JSON.parse(nodes); return Array.isArray(a) ? a : [] } catch { return [] }
  }
  return []
}
async function redetect() {
  detecting.value = true
  try {
    const d = await api.deployDetectNat()
    if (d) nat.value = d.nat || d
    ElMessage.success('检测完成')
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { detecting.value = false }
}
function openAddNode() {
  Object.assign(nodeForm, { idx: null, name: '', ip: '', role: 'node', priority: 100, enabled: true })
  nodeDlg.value = true
}
function openEditNode(row, index) {
  Object.assign(nodeForm, { enabled: true, ...row, idx: index })
  nodeDlg.value = true
}
function saveNode() {
  if (!nodeForm.name.trim()) { ElMessage.warning('请填写名称'); return }
  if (!nodeForm.ip.trim()) { ElMessage.warning('请填写 IP'); return }
  const node = { name: nodeForm.name.trim(), ip: nodeForm.ip.trim(), role: nodeForm.role, priority: nodeForm.priority, enabled: nodeForm.enabled }
  if (nodeForm.idx === null) nodeList.value.push(node)
  else nodeList.value.splice(nodeForm.idx, 1, node)
  nodeDlg.value = false
}
function delNode(index) { nodeList.value.splice(index, 1) }
function onToggleNode(row) { ElMessage.success(row.enabled ? '已启用' : '已禁用') }
async function onSave() {
  saving.value = true
  try {
    await api.deploySave({ haMode: ha.haMode, vip: ha.vip, nodes: JSON.stringify(nodeList.value), remark: ha.remark })
    ElMessage.success('已保存')
  } catch (e) { /* 错误提示已由响应拦截器统一处理 */ } finally { saving.value = false }
}
</script>

<style scoped>
.p { padding: 16px; }
.bar { margin-bottom: 12px; }
.conclusion { display: flex; align-items: center; gap: 10px; margin: 10px 0; }
.ok { color: var(--green); font-weight: 600; }
.bad { color: var(--red); font-weight: 600; }
.warn { color: var(--el-color-warning, #e6a23c); font-weight: 600; }
.meta { margin: 10px 0; }
.sub { color: var(--muted); font-size: 13px; margin: 12px 0 4px; }
</style>
