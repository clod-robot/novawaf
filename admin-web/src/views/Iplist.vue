<template>
  <div class="mecha-panel iplist">
    <!-- 顶部 Tab + 操作区 -->
    <div class="topbar">
      <div class="tabs">
        <div :class="['tab', type === 'black' && 'on']" @click="switchTo('black')">黑名单</div>
        <div :class="['tab', type === 'white' && 'on']" @click="switchTo('white')">白名单</div>
      </div>
      <div class="ops">
        <el-switch v-model="autoRefresh" active-text="自动刷新" @change="toggleStream" />
        <el-button size="small" @click="load">刷新</el-button>
        <el-button size="small" type="warning" @click="clearAll">清空</el-button>
        <el-button size="small" type="primary" @click="openAdd">+ 新增</el-button>
      </div>
    </div>

    <!-- 筛选条 -->
    <div class="filterbar">
      <el-input v-model="q" size="small" placeholder="源 IP / 备注 / 地区" clearable
        style="width:240px" @keyup.enter="load" @clear="load" />
      <el-select v-model="sourceFilter" size="small" placeholder="来源" clearable style="width:130px" @change="load">
        <el-option label="手动" value="manual" /><el-option label="自动" value="auto" />
      </el-select>
      <span class="live" :class="{ on: autoRefresh }">● {{ autoRefresh ? 'SSE 实时' : '已暂停' }}</span>
      <span class="count">共 {{ filtered.length }} 条 · 命中 {{ totalHits }} 次</span>
    </div>

    <!-- 表格 -->
    <el-table :data="paged" size="small" stripe height="460" border style="margin-top:8px">
      <el-table-column label="源 IP" min-width="150">
        <template #default="{ row }">
          <span class="ip mono">{{ row.ip }}</span>
          <el-tag size="small" effect="dark" class="geo-tag" :type="geoType(row.geo)">{{ row.geo }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="动作" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="type === 'black' ? 'danger' : 'success'">
            {{ type === 'black' ? '拦截' : '放行' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="来源" width="90">
        <template #default="{ row }">{{ row.source === 'auto' ? '自动' : '手动' }}</template>
      </el-table-column>
      <el-table-column label="命中次数" width="100" sortable :sort-method="(a,b)=>a.hits-b.hits">
        <template #default="{ row }"><b :class="{ hot: row.hits > 0 }">{{ row.hits || 0 }}</b></template>
      </el-table-column>
      <el-table-column label="最近命中" width="170">
        <template #default="{ row }">{{ row.lastHit ? fmt(row.lastHit) : '—' }}</template>
      </el-table-column>
      <el-table-column label="加入时间" width="170">
        <template #default="{ row }">{{ fmt(row.createdAt) }} · {{ row.createdBy || 'system' }}</template>
      </el-table-column>
      <el-table-column label="备注" min-width="140" show-overflow-tooltip>
        <template #default="{ row }">{{ row.note || '—' }}</template>
      </el-table-column>
      <el-table-column label="状态" width="80">
        <template #default="{ row }">
          <el-switch :model-value="row.enabled !== false" size="small" @change="toggle(row)" />
        </template>
      </el-table-column>
      <el-table-column label="操作" width="80" fixed="right">
        <template #default="{ row }">
          <el-button size="small" type="danger" link @click="del(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>
    <div class="pager">
      <el-pagination layout="prev, pager, next" :total="filtered.length" :page-size="pageSize"
        v-model:current-page="page" small />
    </div>

    <!-- 新增弹窗 -->
    <el-dialog v-model="showAdd" :title="type==='black'?'新增黑名单 IP':'新增白名单 IP'" width="460px">
      <el-form label-width="80px">
        <el-form-item label="IP/CIDR"><el-input v-model="form.ip" placeholder="如 1.2.3.4 或 10.0.0.0/8" /></el-form-item>
        <el-form-item label="备注"><el-input v-model="form.note" placeholder="可选" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAdd = false">取消</el-button>
        <el-button type="primary" @click="doAdd">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'

const type = ref('black')
const rows = ref([])
const q = ref('')
const sourceFilter = ref('')
const autoRefresh = ref(true)
const page = ref(1); const pageSize = 10
const showAdd = ref(false)
const form = ref({ ip: '', note: '' })
let es = null

const filtered = computed(() => rows.value.filter(r =>
  (!sourceFilter.value || r.source === sourceFilter.value)))
const paged = computed(() => filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize))
const totalHits = computed(() => rows.value.reduce((s, r) => s + (r.hits || 0), 0))

async function load() { rows.value = await api.ipList(type.value, q.value) || [] }
function switchTo(t) { type.value = t; q.value = ''; sourceFilter.value = ''; page.value = 1; load() }

function geoType(g) {
  if (g === '内网') return 'info'; if (g === '未知') return 'info'
  if (['中国', '中国香港', '中国台湾'].includes(g)) return 'success'
  return 'warning'
}
function fmt(t) { if (!t) return '—'; const d = new Date(t); return d.toLocaleString('zh-CN', { hour12: false }) }

async function openAdd() { form.value = { ip: '', note: '' }; showAdd.value = true }
async function doAdd() {
  if (!form.value.ip.trim()) return ElMessage.error('IP 不能为空')
  try { await api.addIp({ ip: form.value.ip, type: type.value, note: form.value.note, source: 'manual' }) }
  catch { return }
  ElMessage.success('已新增并下发引擎'); showAdd.value = false; load()
}
async function del(row) {
  try { await ElMessageBox.confirm(`删除 ${row.ip} ?`, '确认', { type: 'warning' }) } catch { return }
  await api.delIp(type.value, row.ip); ElMessage.success('已删除'); load()
}
async function toggle(row) { await api.toggleIp(type.value, row.ip); load() }
async function clearAll() {
  try { await ElMessageBox.confirm('清空当前名单？', '确认', { type: 'warning' }) } catch { return }
  await api.clearIp(type.value); ElMessage.success('已清空'); load()
}

// SSE 实时：名单变更推送 iplist → 自动刷新；事件推送也刷新命中数
function toggleStream() { autoRefresh.value ? openStream() : closeStream() }
function openStream() {
  closeStream()
  try {
    es = new EventSource(api.streamUrl())
    es.addEventListener('iplist', load)
    es.addEventListener('event', load)   // 命中计数变化也刷新
    es.onerror = () => { /* EventSource 自带重连 */ }
  } catch (e) { /* ignore */ }
}
function closeStream() { if (es) { es.close(); es = null } }

onMounted(() => { load(); if (autoRefresh.value) openStream() })
onBeforeUnmount(closeStream)
</script>

<style scoped>
.iplist { padding: 16px; }
.topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.tabs { display: flex; gap: 2px; }
.tab { padding: 8px 22px; cursor: pointer; font-size: 14px; color: #8aa; border: 1px solid #1e3a3a;
  background: rgba(10,22,26,.6); clip-path: polygon(8px 0, 100% 0, calc(100% - 8px) 100%, 0 100%); }
.tab.on { color: #4af3ff; background: rgba(0,229,255,.12); border-color: #2bd4e0; font-weight: 600;
  text-shadow: 0 0 8px rgba(0,229,255,.6); }
.ops { display: flex; align-items: center; gap: 10px; }
.filterbar { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.live { font-size: 12px; color: #566; } .live.on { color: #4af3ff; text-shadow: 0 0 6px #4af3ff; }
.count { margin-left: auto; font-size: 12px; color: #9ad; }
.ip { font-weight: 600; }
.geo-tag { margin-left: 8px; font-size: 11px; }
.mono { font-family: monospace; }
.hot { color: #ff6b6b; text-shadow: 0 0 6px rgba(255,107,107,.6); }
.pager { display: flex; justify-content: flex-end; margin-top: 10px; }
</style>
