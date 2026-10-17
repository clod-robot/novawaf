<template>
  <div class="mecha-panel p">
    <!-- 状态栏 -->
    <div class="bar">
      <el-tag :type="cfg.enabled ? 'success' : 'info'" size="small" effect="dark">
        防篡改总开关：{{ cfg.enabled ? '已开启' : '关闭' }}
      </el-tag>
      <el-tag type="info" size="small" effect="dark" style="margin-left:8px">
        配置版本 v{{ cfg.cfgver ?? 0 }}
      </el-tag>
      <span style="flex:1"></span>
      <el-button size="small" @click="loadAll">刷新</el-button>
    </div>

    <!-- 引擎统计 -->
    <div class="tiles">
      <div class="tile"><div class="t-num">{{ pages.length }}</div><div class="t-lab">基线页面</div></div>
      <div class="tile"><div class="t-num">{{ nfmt(stats.learned) }}</div><div class="t-lab">累计学习</div></div>
      <div class="tile danger"><div class="t-num">{{ nfmt(stats.restored) }}</div><div class="t-lab">篡改恢复</div></div>
      <div class="tile ok"><div class="t-num">{{ nfmt(stats.passed) }}</div><div class="t-lab">一致放行</div></div>
    </div>

    <!-- 配置下发 -->
    <div class="hud-title" style="margin-top:18px">// 防护配置（保存后引擎 5 秒内热生效）</div>
    <div class="formbox">
      <el-form label-width="170px" class="cfgform">
        <el-form-item label="防篡改总开关">
          <el-switch v-model="form.enabled" />
          <span class="hint">开启后引擎自动学习受保护页面的正常基线，源站被篡改时对外返回正常缓存内容</span>
        </el-form-item>
        <el-form-item label="基线 TTL（秒）">
          <el-input-number v-model="form.ttl" :min="0" :max="86400" :step="60" />
          <span class="hint">到期以当前响应重学基线（覆盖页面正常更新）；0 = 每次请求都重学</span>
        </el-form-item>
        <el-form-item label="单页最大缓存">
          <el-input-number v-model="form.maxBody" :min="1024" :max="4194304" :step="65536" />
          <span class="hint">字节，默认 256KB；超过该大小的页面不参与防篡改</span>
        </el-form-item>
        <el-form-item label="基线页面容量">
          <el-input-number v-model="form.maxPages" :min="1" :max="4096" />
          <span class="hint">LRU 容量，超出自动淘汰最久未访问页面</span>
        </el-form-item>
        <el-form-item label="保护路径前缀">
          <el-select v-model="form.prefixes" multiple filterable allow-create default-first-option
                     placeholder="留空 = 保护全部静态 HTML；输入 / 开头前缀后回车" style="width:420px" />
          <span class="hint">仅保护匹配的 GET HTML 页面；动态接口务必排除，避免误报</span>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="saving" @click="onSave">保存并热生效</el-button>
          <el-button @click="resetForm">重置</el-button>
        </el-form-item>
      </el-form>
    </div>

    <!-- 基线页面 -->
    <div class="hud-title" style="margin-top:18px">// 基线页面（{{ pages.length }}）
      <el-button type="danger" size="small" plain style="margin-left:12px"
                 :disabled="!pages.length" @click="onPurgeAll">清除全部基线</el-button>
    </div>
    <el-table :data="pages" border size="small" height="380" class="tbl">
      <el-table-column type="index" width="50" />
      <el-table-column prop="host" label="站点" min-width="140" show-overflow-tooltip />
      <el-table-column prop="path" label="页面路径" min-width="220" show-overflow-tooltip />
      <el-table-column label="基线建立时间" width="170">
        <template #default="{ row }">{{ fmtTs(row.ts) }}</template>
      </el-table-column>
      <el-table-column label="大小" width="100" align="right">
        <template #default="{ row }">{{ fmtSize(row.size) }}</template>
      </el-table-column>
      <el-table-column prop="id" label="页面 ID" width="150">
        <template #default="{ row }"><span class="mono">{{ row.id }}</span></template>
      </el-table-column>
      <el-table-column label="操作" width="130" fixed="right">
        <template #default="{ row }">
          <el-button type="danger" size="small" plain @click="onPurge(row)">清除重学</el-button>
        </template>
      </el-table-column>
      <template #empty>
        <span>暂无基线页面 —— 开启总开关并访问受保护页面后自动学习</span>
      </template>
    </el-table>
    <p class="footnote">
      原理：引擎对 GET + 200 + text/html 的响应建立字节级基线；之后源站页面一旦被篡改，
      引擎立即返回正常缓存内容保障对外展示合规，同时上报告警事件（可在溯源分析中追踪攻击源）。
      「清除重学」用于页面正常改版后重建基线。chunked/gzip 压缩响应不参与（建议源站对保护页面输出 identity）。
    </p>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'

const pages = ref([]), stats = ref({}), cfg = ref({})
const form = ref({ enabled: false, ttl: 3600, maxBody: 262144, maxPages: 256, prefixes: [] })
const saving = ref(false)

function nfmt(n) { return (n ?? 0).toLocaleString() }
function fmtTs(ts) { return ts ? new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) : '-' }
function fmtSize(n) {
  if (!n) return '0'
  return n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B'
}

async function loadAll() {
  const [p, s, c] = await Promise.all([
    api.tamperPages().catch(() => []),
    api.tamperStats().catch(() => ({})),
    api.tamperConfig().catch(() => ({}))
  ])
  pages.value = Array.isArray(p) ? p : []
  stats.value = s || {}
  cfg.value = c || {}
  resetForm()
}
function resetForm() {
  form.value = {
    enabled: !!cfg.value.enabled,
    ttl: cfg.value.ttl ?? 3600,
    maxBody: cfg.value.maxBody ?? 262144,
    maxPages: cfg.value.maxPages ?? 256,
    prefixes: Array.isArray(cfg.value.prefixes) ? [...cfg.value.prefixes] : []
  }
}
async function onSave() {
  saving.value = true
  try {
    const out = await api.tamperSaveConfig(form.value)
    cfg.value = out
    ElMessage.success('已保存，引擎 5 秒内热生效（配置版本 v' + out.cfgver + '）')
  } finally { saving.value = false }
}
async function onPurge(row) {
  await ElMessageBox.confirm(
    `清除页面「${row.host}${row.path}」的基线？下次访问将以当前源站内容重新学习。`,
    '清除重学确认', { type: 'warning', confirmButtonText: '清除重学', cancelButtonText: '取消' })
  await api.tamperPurge(row.id)
  ElMessage.success('已下发清除指令，引擎重学后索引自动更新')
  loadAll()
}
async function onPurgeAll() {
  await ElMessageBox.confirm(
    `清除全部 ${pages.value.length} 个页面基线？所有受保护页面将重新学习。`,
    '清除全部基线确认', { type: 'warning', confirmButtonText: '全部清除', cancelButtonText: '取消' })
  await api.tamperPurge('all')
  ElMessage.success('已下发全量清除指令')
  loadAll()
}
onMounted(loadAll)
</script>

<style scoped>
.p { padding: 16px; }
.bar { display: flex; align-items: center; }
.tiles { display: flex; gap: 12px; margin-top: 14px; flex-wrap: wrap; }
.tile { flex: 1; min-width: 140px; background: rgba(0, 229, 255, .05); border: 1px solid var(--line); border-radius: 6px; padding: 12px 16px; }
.tile.danger { background: rgba(245, 108, 108, .08); border-color: rgba(245, 108, 108, .35); }
.tile.ok { background: rgba(103, 194, 58, .07); border-color: rgba(103, 194, 58, .3); }
.t-num { font-size: 22px; font-weight: 700; color: var(--cyan); font-family: 'Consolas', monospace; }
.tile.danger .t-num { color: #f56c6c; }
.tile.ok .t-num { color: #67c23a; }
.t-lab { font-size: 12px; color: var(--muted); margin-top: 4px; }
.formbox { background: rgba(0, 229, 255, .03); border: 1px solid var(--line); border-radius: 6px; padding: 14px 10px 0; margin-top: 10px; }
.cfgform :deep(.el-form-item__label) { color: #9fc4e8; }
.hint { margin-left: 12px; font-size: 12px; color: var(--muted); }
.tbl { margin-top: 10px; }
.mono { font-family: 'Consolas', monospace; font-size: 12px; color: #9fc4e8; }
.footnote { margin-top: 12px; font-size: 12px; color: var(--muted); line-height: 1.8; }
</style>
