<template>
  <div class="mecha-panel p">
    <div class="bar">
      <el-tag :type="live.reachable ? 'success' : 'danger'" size="small" effect="dark">
        {{ live.reachable ? '引擎在线' : '引擎状态不可达' }}
      </el-tag>
      <el-tag :type="enabledTag" size="small" effect="dark" style="margin-left:8px">
        总开关：{{ form.enabled ? '开启' : '关闭（默认）' }}
      </el-tag>
      <el-tag type="info" size="small" effect="dark" style="margin-left:8px">
        当前生效后端：{{ live.activeBackend || 'Scalar' }}
      </el-tag>
      <span style="flex:1"></span>
      <el-switch v-model="autoRefresh" active-text="自动刷新" style="margin-right:14px" />
      <el-button :loading="testing" @click="selfTest">引擎自检</el-button>
      <el-button @click="load">刷新</el-button>
    </div>

    <el-alert v-if="testResult" :title="testResult" :type="testOk ? 'success' : 'error'"
              :closable="true" show-icon style="margin:10px 0" @close="testResult=''" />

    <!-- CPU / SIMD 能力 -->
    <div class="hud-title">// CPU / SIMD 能力</div>
    <el-descriptions :column="2" border size="small" class="meta">
      <el-descriptions-item label="处理器型号">{{ cpu.model || '-' }}</el-descriptions-item>
      <el-descriptions-item label="厂商 / 核心数">{{ cpu.vendor || '-' }} / {{ cpu.cores ?? '-' }}</el-descriptions-item>
      <el-descriptions-item label="最高 SIMD 级别">
        <el-tag size="small" type="success" effect="dark">{{ cpu.simd || 'Scalar' }}</el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="指令集标志"><span class="flags">{{ cpu.flags || '-' }}</span></el-descriptions-item>
    </el-descriptions>

    <!-- 后端健康 -->
    <div class="hud-title" style="margin-top:18px">// 计算后端健康状态</div>
    <DataTable :data="backendRows" :columns="backendColumns" height="180px" class="tbl">
      <template #cell-state="{ row }">
        <el-tag :type="stateType(row.state)" size="small" effect="dark">{{ stateText(row.state) }}</el-tag>
      </template>
      <template #cell-detail="{ row }">{{ row.detail || '—' }}</template>
    </DataTable>

    <!-- 设备清单 -->
    <div class="hud-title" style="margin-top:18px">// 已识别设备</div>
    <DataTable :data="live.devices || []" :columns="deviceColumns" height="220px" class="tbl">
      <template #cell-vendor="{ row }">{{ row.vendor || '—' }}</template>
      <template #cell-healthy="{ row }">
        <el-tag :type="row.healthy ? 'success' : 'danger'" size="small" effect="dark">
          {{ row.healthy ? '正常' : '异常' }}
        </el-tag>
      </template>
    </DataTable>

    <!-- 配置下发 -->
    <div class="hud-title" style="margin-top:18px">// 加速配置</div>
    <div class="formbox">
      <el-form label-width="170px" class="cfg">
        <el-form-item label="硬件加速总开关">
          <el-switch v-model="form.enabled" :disabled="!canEdit" @change="markDirty" />
          <span class="hint">默认关闭；关闭时数据面逐字节等价于标量 AC，检测结果零变化</span>
        </el-form-item>
        <el-form-item label="首选计算后端">
          <el-select v-model="form.preferredBackend" :disabled="!canEdit" style="width:240px" @change="markDirty">
            <el-option v-for="o in backendOptions" :key="o.value"
                       :label="o.label" :value="o.value" :disabled="!optHealthy(o)" />
          </el-select>
          <span v-if="backendWarn" class="warn">{{ backendWarn }}</span>
        </el-form-item>
        <el-form-item label="批量闸门阈值 batchGateMinN">
          <el-input-number v-model="form.batchGateMinN" :min="1" :max="1024" :disabled="!canEdit" @change="markDirty" />
          <span class="hint">积累多少条候选才触发一次批量预筛（预留参数）</span>
        </el-form-item>
        <el-form-item label="批量等待上限 batchMaxWaitUs">
          <el-input-number v-model="form.batchMaxWaitUs" :min="0" :max="100000" :step="100" :disabled="!canEdit" @change="markDirty" />
          <span class="hint">微秒，保护 P99，超时即按逐请求处理（预留参数）</span>
        </el-form-item>
        <el-form-item label="IOC 重建旁路卸载">
          <el-switch v-model="form.offloadIocRebuild" :disabled="!canEdit" @change="markDirty" />
          <span class="hint">规则/IOC 重建等离线任务优先放到加速侧</span>
        </el-form-item>
        <el-form-item v-if="canEdit">
          <el-button type="primary" :loading="saving" @click="onSave">保存并热生效</el-button>
          <el-button @click="resetForm">重置</el-button>
          <span v-if="formDirty" class="warn" style="margin-left:8px">有未保存修改</span>
        </el-form-item>
        <el-form-item v-else>
          <span class="hint">当前角色仅可查看，修改需 system:accel:edit 权限</span>
        </el-form-item>
      </el-form>
    </div>

    <!-- 聚合统计 -->
    <div class="hud-title" style="margin-top:18px">// 加速路径聚合统计</div>
    <div class="tiles">
      <div class="tile"><div class="t-num">{{ nfmt(stats.scans) }}</div><div class="t-lab">扫描块数</div></div>
      <div class="tile"><div class="t-num">{{ nfmt(stats.confirmed) }}</div><div class="t-lab">锚点命中确认</div></div>
      <div class="tile"><div class="t-num">{{ nfmt(stats.rejected) }}</div><div class="t-lab">锚点预筛命中</div></div>
      <div class="tile ok"><div class="t-num">{{ nfmt(stats.fallback) }}</div><div class="t-lab">回退标量次数</div></div>
      <div class="tile"><div class="t-num">{{ nfmt(stats.batchFlush) }}</div><div class="t-lab">批量冲刷</div></div>
      <div class="tile"><div class="t-num">{{ nfmt(stats.gpuBatch) }}</div><div class="t-lab">GPU 批量</div></div>
    </div>
    <p class="footnote">
      安全说明：加速仅作为“必要条件预筛”，锚点精确匹配后再对完整串二次确认，命中判定仍回到原始 AC/语义层，
      因此 <b>零漏报、零误报</b>；无可用 GPU/NPU 或后端异常时自动熔断回退标量基线，不影响防护。当前版本 GPU/NPU 仅做设备探测与兼容，扫描加速在 CPU AVX2 路径生效。
    </p>
  </div>
</template>

<script setup>
import { computed, onMounted, onBeforeUnmount, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { fmtBig } from '../utils/format'
import DataTable from '../components/DataTable.vue'

const backendColumns = [
  { prop: 'name', label: '后端', width: 140 },
  { label: '状态', width: 120, slot: 'state' },
  { prop: 'detail', label: '说明', minWidth: 200, slot: 'detail' }
]
const deviceColumns = [
  { prop: 'type', label: '类型', width: 90 },
  { label: '厂商', width: 130, slot: 'vendor' },
  { prop: 'name', label: '型号', minWidth: 240 },
  { prop: 'backend', label: '对应后端', width: 110 },
  { prop: 'computeUnits', label: '计算单元', width: 90 },
  { label: '健康', width: 80, slot: 'healthy', noSearch: true }
]

const live = ref({ reachable: false, activeBackend: 'Scalar', cpu: {}, devices: [], backends: [], stats: {} })
const stats = computed(() => live.value.stats || {})
const cpu = computed(() => live.value.cpu || {})

const isAdmin = localStorage.getItem('nova_admin') === '1'
const permList = (() => { try { return JSON.parse(localStorage.getItem('nova_perms') || '[]') } catch { return [] } })()
const canEdit = isAdmin || permList.includes('system:accel:edit')

const form = reactive({ enabled: false, preferredBackend: 'auto', batchGateMinN: 8, batchMaxWaitUs: 2000, offloadIocRebuild: true })
const formDirty = ref(false)
const saving = ref(false)
const testing = ref(false)
const autoRefresh = ref(true)
const testResult = ref('')
const testOk = ref(false)
let timer = null

const BACKEND_ORDER = ['Scalar', 'AVX2', 'AVX-512', 'OpenCL', 'CUDA', 'HIP', 'CANN']
const backendRows = computed(() => {
  const map = {}
  for (const b of (live.value.backends || [])) map[b.name] = b
  return BACKEND_ORDER.map((n) => map[n] || { name: n, state: 'unavailable', detail: '' })
})

const backendOptions = [
  { value: 'auto', label: '自动（推荐）' },
  { value: 'scalar', label: '标量 Scalar（关闭 SIMD）' },
  { value: 'avx2', label: 'AVX2 (CPU SIMD)' },
  { value: 'avx512', label: 'AVX-512 (CPU SIMD)' },
  { value: 'opencl', label: 'OpenCL (GPU 通用)' },
  { value: 'cuda', label: 'CUDA (NVIDIA)' },
  { value: 'hip', label: 'HIP (AMD / 海光 DCU)' },
  { value: 'cann', label: 'CANN (华为昇腾)' }
]
const backendKeyToName = { scalar: 'Scalar', avx2: 'AVX2', avx512: 'AVX-512', opencl: 'OpenCL', cuda: 'CUDA', hip: 'HIP', cann: 'CANN' }
const optionHealth = computed(() => {
  const h = {}
  for (const b of backendRows.value) h[b.name] = b.state === 'healthy'
  return h
})
function optHealthy(o) {
  if (o.value === 'auto' || o.value === 'scalar') return true
  return !!optionHealth.value[backendKeyToName[o.value]]
}
const backendWarn = computed(() => {
  if (!form.enabled) return ''
  const bn = backendKeyToName[form.preferredBackend]
  if (!bn) return ''
  return optionHealth.value[bn] ? '' : `后端 ${bn} 当前不可用，保存后引擎将自动回退到标量基线`
})
const enabledTag = computed(() => (form.enabled ? 'warning' : 'info'))

function stateType(s) {
  if (s === 'healthy') return 'success'
  if (s === 'open') return 'danger'
  if (s === 'half_open') return 'warning'
  return 'info'
}
function stateText(s) {
  return ({ healthy: '健康可用', unavailable: '不可用', open: '熔断打开', half_open: '半开探测', closed: '已关闭' })[s] || s || '未知'
}
function nfmt(v) { return (v === null || v === undefined) ? '0' : fmtBig(v) }
function markDirty() { formDirty.value = true }

function syncForm(d) {
  form.enabled = !!d.enabled
  form.preferredBackend = d.preferredBackend || 'auto'
  form.batchGateMinN = Number(d.batchGateMinN ?? 8)
  form.batchMaxWaitUs = Number(d.batchMaxWaitUs ?? 2000)
  form.offloadIocRebuild = d.offloadIocRebuild !== false
  formDirty.value = false
}

async function load(syncCfg = true) {
  try {
    const d = await api.accelGet()
    live.value = d || live.value
    if (syncCfg && !formDirty.value) syncForm(d || {})
  } catch (e) { /* 拦截器已提示 */ }
}
function resetForm() { syncForm(live.value) }

async function onSave() {
  try {
    await ElMessageBox.confirm(
      form.enabled
        ? '开启硬件加速后，引擎将在 CPU SIMD(AVX2) 快路径执行预筛（异常会自动熔断回退）。确认下发？'
        : '将关闭硬件加速并回到标量基线，检测结果不受影响。确认下发？',
      '硬件加速配置', { confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning' })
  } catch { return }
  saving.value = true
  try {
    const msg = await api.accelSave({
      enabled: form.enabled,
      preferredBackend: form.preferredBackend,
      batchGateMinN: form.batchGateMinN,
      batchMaxWaitUs: form.batchMaxWaitUs,
      offloadIocRebuild: form.offloadIocRebuild
    })
    ElMessage.success(msg || '已下发')
    formDirty.value = false
    setTimeout(() => load(true), 2500)   // 引擎 ~2s 热加载、~6s 上报，稍后回读
  } catch (e) { /* 拦截器已提示 */ } finally { saving.value = false }
}

async function selfTest() {
  testing.value = true
  try {
    const r = await api.accelSelftest()
    testOk.value = !!(r && r.ok)
    testResult.value = r && r.ok
      ? `自检通过：当前生效后端 ${r.activeBackend || 'Scalar'}，加速开关 ${r.enabled ? '开启' : '关闭'}`
      : (`自检未通过：${(r && r.reason) || '引擎状态不可达'}`)
  } catch (e) { /* 拦截器已提示 */ } finally { testing.value = false }
}

onMounted(() => {
  load(true)
  timer = setInterval(() => { if (autoRefresh.value) load(false) }, 4000)
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.p { padding: 16px; }
.bar { display: flex; align-items: center; margin-bottom: 12px; }
.meta { margin-top: 8px; }
.flags { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: var(--cyan, #00e5ff); }
.tbl { margin-top: 8px; }
.formbox { margin-top: 8px; padding: 14px 14px 0; border: 1px solid var(--line, #1f3a52); border-radius: 6px; }
.hint { margin-left: 10px; color: var(--muted, #8aa6c4); font-size: 12px; }
.warn { margin-left: 10px; color: var(--el-color-warning, #e6a23c); font-size: 12px; }
.tiles { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin-top: 10px; }
.tile { border: 1px solid var(--line, #1f3a52); border-radius: 6px; padding: 12px; text-align: center; background: rgba(0, 229, 255, 0.04); }
.t-num { font-size: 20px; font-weight: 700; color: var(--cyan, #00e5ff); font-variant-numeric: tabular-nums; }
.t-lab { margin-top: 4px; font-size: 12px; color: var(--muted, #8aa6c4); }
.tile.ok .t-num { color: var(--green, #2ecc71); }
.footnote { margin-top: 14px; color: var(--muted, #8aa6c4); font-size: 12px; line-height: 1.7; }
</style>
