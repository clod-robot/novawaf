<template>
  <div class="mecha-panel p">
    <el-tabs v-model="tab" class="log-tabs">
      <!-- 攻击告警 -->
      <el-tab-pane label="攻击告警日志" name="alert">
        <div class="bar">
          <el-button type="primary" @click="loadEvents">刷新</el-button>
          <span class="tip">经 SSE 实时增量，此处为最近 {{ events.length }} 条历史</span>
        </div>
        <DataTable :data="events" :columns="eventColumns" height="calc(100vh - 240px)">
          <template #cell-ts="{ row }">{{ fmt(row.ts) }}</template>
          <template #cell-action="{ row }">
            <el-tag size="small" :type="row.action==='block'?'danger':'success'" effect="dark">{{ row.action || 'block' }}</el-tag>
          </template>
          <template #cell-matched="{ row }"><span class="mono">{{ row.matched }}</span></template>
        </DataTable>
      </el-tab-pane>

      <!-- 运行日志 -->
      <el-tab-pane label="运行日志" name="run">
        <div class="bar">
          <el-input v-model="kw" placeholder="搜索日志..." style="width:260px" clearable @keyup.enter="loadLogs" />
          <el-button type="primary" @click="loadLogs">检索</el-button>
        </div>
        <DataTable :data="rows" :columns="logColumns" height="calc(100vh - 240px)">
          <template #cell-content="{ row }"><span class="mono">{{ pretty(row) }}</span></template>
        </DataTable>
      </el-tab-pane>

      <!-- Syslog 外发 -->
      <el-tab-pane label="Syslog 外发审计" name="syslog">
        <div class="sys">
          <el-form :model="cfg" label-width="130px" class="form">
            <el-form-item label="启用外发">
              <el-switch v-model="cfg.enabled" />
              <span class="tip">开启后将攻击告警与运行日志发送到外部 Syslog 服务器（SIEM/日志审计）</span>
            </el-form-item>
            <el-form-item label="服务器地址"><el-input v-model="cfg.host" style="width:240px" placeholder="如 192.168.100.10" /></el-form-item>
            <el-form-item label="端口"><el-input-number v-model="cfg.port" :min="1" :max="65535" style="width:160px" /></el-form-item>
            <el-form-item label="协议">
              <el-radio-group v-model="cfg.protocol"><el-radio value="udp">UDP</el-radio><el-radio value="tcp">TCP</el-radio></el-radio-group>
            </el-form-item>
            <el-form-item label="Facility">
              <el-select v-model="cfg.facility" style="width:160px">
                <el-option v-for="f in facs" :key="f" :label="f" :value="f" />
              </el-select>
            </el-form-item>
            <el-form-item label="Tag(标识)"><el-input v-model="cfg.tag" style="width:200px" /></el-form-item>
            <el-form-item label="最低级别">
              <el-select v-model="cfg.minLevel" style="width:140px">
                <el-option v-for="s in sevs" :key="s" :label="s" :value="s" />
              </el-select>
            </el-form-item>
            <el-form-item label="转发内容">
              <el-checkbox v-model="cfg.forwardAlerts">攻击告警</el-checkbox>
              <el-checkbox v-model="cfg.forwardRuntime">运行心跳</el-checkbox>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="save">保存配置</el-button>
              <el-button @click="test">发送测试</el-button>
            </el-form-item>
          </el-form>
          <div class="status-box mecha-panel">
            <div class="hud-title">外发状态</div>
            <div class="kv"><span>目标</span><b>{{ cfg.host }}:{{ cfg.port }}/{{ cfg.protocol }}</b></div>
            <div class="kv"><span>状态</span><b :class="cfg.enabled?'on':'off'">{{ cfg.enabled ? '已启用' : '已停用' }}</b></div>
            <div class="kv"><span>已发送</span><b>{{ st.forwarded }}</b></div>
            <div class="kv"><span>失败</span><b>{{ st.failed }}</b></div>
            <div class="kv err"><span>最近错误</span><b>{{ st.lastError || '-' }}</b></div>
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { onMounted, ref, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import DataTable from '../components/DataTable.vue'

const eventColumns = [
  { type: 'index', label: '#', width: 50 },
  { label: '时间', width: 160, slot: 'ts', noSearch: true },
  { label: '动作', width: 80, slot: 'action' },
  { prop: 'category', label: '类型', width: 110 },
  { prop: 'ruleId', label: '规则', width: 120 },
  { prop: 'ip', label: '源 IP', width: 150 },
  { prop: 'matched', label: '匹配内容', slot: 'matched' }
]
const logColumns = [
  { type: 'index', label: '#', width: 50 },
  { prop: 'content', label: '日志内容', slot: 'content' }
]

const tab = ref('alert')
const facs = ['local0','local1','local2','local3','local4','local5','local6','local7','user','daemon','auth','authpriv']
const sevs = ['emerg','alert','crit','err','warning','notice','info','debug']

// 攻击告警
const events = ref([])
async function loadEvents() { try { events.value = (await api.wafEvents({ limit: 200 })) || [] } catch {} }

// 运行日志
const rows = ref([]), kw = ref('')
function pretty(r) { try { return JSON.stringify(r) } catch { return String(r) } }
async function loadLogs() {
  const d = await api.wafLogs({ page: 1, size: 5000, keyword: kw.value || undefined })
  rows.value = d.rows || []
}

// Syslog
const cfg = reactive({ enabled:false, host:'127.0.0.1', port:514, protocol:'udp', facility:'local0', tag:'novawaf', minLevel:'info', forwardAlerts:true, forwardRuntime:true })
const st = reactive({ forwarded:0, failed:0, lastError:'' })
async function loadStatus() {
  try {
    const r = await api.syslogStatus()
    if (r.config) Object.assign(cfg, r.config)
    st.forwarded = r.forwarded || 0; st.failed = r.failed || 0; st.lastError = r.lastError || ''
  } catch {}
}
async function save() {
  await api.saveSyslog({ ...cfg })
  ElMessage.success('已保存')
  loadStatus()
}
async function test() {
  const r = await api.testSyslog({ ...cfg })
  if (r.ok) ElMessage.success('测试消息已发送 → ' + r.target)
  else ElMessage.error('发送失败: ' + (r.error || '未知'))
  loadStatus()
}
function fmt(ts) { if (!ts) return ''; return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) }

onMounted(() => { loadEvents(); loadLogs(); loadStatus() })
</script>

<style scoped>
.p { padding: 16px; }
.bar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; }
.pg { margin-top: 12px; }
.mono { font-family: monospace; font-size: 12px; color: #9fc4e8; }
.tip { color: var(--muted); font-size: 12px; }
.sys { display: flex; gap: 24px; }
.form { flex: 1; }
.status-box { width: 320px; padding: 16px; }
.kv { display: flex; justify-content: space-between; padding: 6px 0; font-size: 13px; border-bottom: 1px dashed rgba(0,229,255,.12); }
.kv span { color: var(--muted); }
.kv b { color: #cfe9ff; font-weight: 600; }
.kv b.on { color: #00ff9d; } .kv b.off { color: var(--muted); }
.kv.err b { color: #ff7a45; max-width: 200px; text-align: right; word-break: break-all; }
:deep(.log-tabs .el-tabs__item) { color: #9fc4e8; }
</style>
