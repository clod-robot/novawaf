<template>
  <div class="mecha-panel p">
    <!-- 状态栏 -->
    <div class="bar">
      <span class="hud-inline">// 攻击源 IP 排行（{{ scope }}）</span>
      <span style="flex:1"></span>
      <el-select v-model="limit" size="small" style="width:130px;margin-right:10px" @change="load">
        <el-option :value="20" label="Top 20" />
        <el-option :value="50" label="Top 50" />
        <el-option :value="100" label="Top 100" />
        <el-option :value="200" label="Top 200" />
      </el-select>
      <el-button size="small" type="success" plain @click="exportSummary">导出 CSV</el-button>
      <el-button size="small" @click="load">刷新</el-button>
    </div>

    <!-- 攻击源 IP 排行 -->
    <DataTable :data="rows" :columns="summaryColumns" height="calc(100vh - 220px)" class="tbl" v-loading="loading">
      <template #cell-ip="{ row }">
        <el-link type="primary" class="mono" @click="openDetail(row.ip)">{{ row.ip }}</el-link>
      </template>
      <template #cell-riskScore="{ row }">
        <div class="risk">
          <el-progress :percentage="row.riskScore" :stroke-width="10" :color="riskColor(row.riskScore)" :show-text="false" style="flex:1" />
          <span class="score mono" :style="{ color: riskColor(row.riskScore) }">{{ row.riskScore }}</span>
        </div>
      </template>
      <template #cell-level="{ row }">
        <el-tag :type="levelType(row.level)" size="small" effect="dark">{{ row.level }}</el-tag>
      </template>
      <template #cell-count="{ row }">{{ fmtBig(row.count) }}</template>
      <template #cell-tags="{ row }">
        <el-tag v-for="t in row.tags" :key="t" size="small" effect="plain" class="tag">{{ t }}</el-tag>
      </template>
      <template #cell-chain="{ row }">
        <span v-for="(s, i) in row.chain" :key="s" class="chain">
          <span class="stage" :class="'st-' + s">{{ stageText(s) }}</span>
          <span v-if="i < row.chain.length - 1" class="arrow">→</span>
        </span>
      </template>
      <template #cell-seen="{ row }">
        <div class="ts">{{ fmtTs(row.firstSeen) }}</div>
        <div class="ts">{{ fmtTs(row.lastSeen) }}</div>
      </template>
      <template #cell-op="{ row }">
        <el-button size="small" type="primary" plain @click="openDetail(row.ip)">攻击链</el-button>
      </template>
    </DataTable>
    <p class="footnote">
      攻击次数 = 当日真实累计（引擎按天分桶持久计数，不封顶、不被洪水挤占、封禁解除后不清零，跨天自动重置）。
      攻击类型画像来自最近 1000 条明细样本。
      风险分 = 严重度加权（critical 10 / high 5 / medium 2 / low 1）+ 攻击类别多样性 + 频率加成，上限 100。
      攻击链：侦察(recon) → 渗透(exploit) → 入侵(intrusion) → 破坏(impact)，阶段越靠后威胁越大。
      「导出 CSV」可作为公安电子证据留存。
    </p>

    <!-- 单 IP 攻击链详情抽屉 -->
    <el-drawer v-model="drawer" :title="'攻击链溯源 // ' + (detail.ip || '')" size="62%" destroy-on-close>
      <div v-if="detail.ip" class="drawer-body">
        <!-- 概要 -->
        <div class="headline">
          <el-tag :type="levelType(detail.level)" effect="dark">{{ detail.level }} · {{ detail.riskScore }} 分</el-tag>
          <el-tag v-for="t in detail.tags" :key="t" size="small" effect="plain" class="tag">{{ t }}</el-tag>
          <span style="flex:1"></span>
          <el-button size="small" type="success" plain @click="exportIpDetail">导出本 IP 明细</el-button>
        </div>
        <el-descriptions :column="4" border size="small" class="meta">
          <el-descriptions-item label="攻击次数">{{ fmtBig(detail.count) }}</el-descriptions-item>
          <el-descriptions-item label="首次攻击">{{ fmtTs(detail.firstSeen) }}</el-descriptions-item>
          <el-descriptions-item label="最近攻击">{{ fmtTs(detail.lastSeen) }}</el-descriptions-item>
          <el-descriptions-item label="拦截动作">
            <span v-for="(v, k) in detail.actions" :key="k" class="tag">{{ actText(k) }}×{{ v }}</span>
          </el-descriptions-item>
        </el-descriptions>

        <!-- 攻击链阶段（时间序） -->
        <div class="hud-title" style="margin-top:16px">// 攻击链推进路径（按时间顺序）</div>
        <el-steps :active="(detail.stageFlow || []).length" align-center class="steps">
          <el-step v-for="s in detail.stageFlow" :key="s" :title="stageText(s)"
                   :description="stageDesc(s)" :status="stepStatus(s)" />
        </el-steps>

        <!-- 命中规则 Top -->
        <div class="hud-title" style="margin-top:16px">// 高频命中规则</div>
        <DataTable :data="detail.topRules || []" :columns="ruleColumns" height="220px" class="tbl">
          <template #cell-ruleId="{ row }"><span class="mono">{{ row.ruleId }}</span></template>
          <template #cell-count="{ row }">{{ fmtBig(row.count) }}</template>
          <template #cell-ratio="{ row }">
            <el-progress :percentage="Math.round(row.count * 100 / detail.count)" :stroke-width="8" color="#00e5ff" />
          </template>
        </DataTable>

        <!-- 攻击时间线 -->
        <div class="hud-title" style="margin-top:16px">// 攻击时间线（最近 {{ fmtBig((detail.timeline || []).length) }} / {{ fmtBig(detail.timelineTotal) }} 条）</div>
        <DataTable :data="detail.timeline || []" :columns="tlColumns" height="calc(100vh - 520px)" class="tbl">
          <template #cell-ts="{ row }"><span class="mono">{{ fmtTs(row.ts) }}</span></template>
          <template #cell-stage="{ row }"><span class="stage" :class="'st-' + row.stage">{{ stageText(row.stage) }}</span></template>
          <template #cell-ruleId="{ row }"><span class="mono">{{ row.ruleId || '-' }}</span></template>
          <template #cell-action="{ row }">
            <el-tag :type="row.action === 'block' ? 'danger' : 'info'" size="small" effect="dark">{{ actText(row.action) }}</el-tag>
          </template>
        </DataTable>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { fmtBig } from '../utils/format'
import DataTable from '../components/DataTable.vue'

const summaryColumns = [
  { type: 'index', label: '#', width: 50 },
  { label: '攻击源 IP', width: 150, slot: 'ip' },
  { label: '风险分', width: 170, slot: 'riskScore', noSearch: true },
  { label: '等级', width: 80, align: 'center', slot: 'level' },
  { label: '攻击次数', width: 100, align: 'right', sortable: true, slot: 'count', noSearch: true },
  { label: '攻击类型画像', minWidth: 220, slot: 'tags' },
  { label: '攻击链', width: 200, slot: 'chain' },
  { label: '首次 / 最近攻击', width: 180, slot: 'seen', noSearch: true },
  { label: '操作', width: 110, fixed: 'right', slot: 'op', noSearch: true }
]
const ruleColumns = [
  { prop: 'ruleId', label: '规则 ID', width: 180, slot: 'ruleId' },
  { prop: 'count', label: '命中次数', width: 100, align: 'right', slot: 'count', noSearch: true },
  { label: '占比', slot: 'ratio', noSearch: true }
]
const tlColumns = [
  { label: '时间', width: 165, slot: 'ts', noSearch: true },
  { label: '阶段', width: 80, align: 'center', slot: 'stage' },
  { prop: 'category', label: '攻击类型', width: 120 },
  { prop: 'ruleId', label: '规则', width: 130, slot: 'ruleId' },
  { label: '动作', width: 80, align: 'center', slot: 'action', noSearch: true },
  { prop: 'matched', label: '命中内容', minWidth: 200 }
]

const rows = ref([]), limit = ref(50), loading = ref(false)
const scope = ref('加载中…')
const drawer = ref(false), detail = ref({})

function fmtTs(ts) { return ts ? new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) : '-' }
function riskColor(s) { return s >= 70 ? '#f56c6c' : s >= 40 ? '#e6a23c' : s >= 20 ? '#c8b73c' : '#67c23a' }
function levelType(l) { return l === '严重' ? 'danger' : l === '高危' ? 'danger' : l === '中危' ? 'warning' : 'info' }
function stageText(s) {
  return { recon: '侦察', exploit: '渗透', intrusion: '入侵', impact: '破坏', other: '其他' }[s] || s
}
function stageDesc(s) {
  return {
    recon: '扫描探测 / 信息收集', exploit: '注入 / XSS / 越权尝试',
    intrusion: '代码执行 / 反序列化', impact: '篡改 / 资源破坏', other: '未分类行为'
  }[s] || ''
}
function stepStatus(s) { return s === 'impact' || s === 'intrusion' ? 'error' : 'finish' }
function actText(a) { return a === 'block' ? '拦截' : a === 'challenge' ? '挑战' : a === 'restore' ? '恢复' : '记录' }

// ---------- CSV 导出（电子证据留存） ----------
function csvEscape(v) {
  if (v === null || v === undefined) return ''
  const s = Array.isArray(v) ? v.join(' | ') : String(v)
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s
}
function downloadCsv(filename, header, dataRows) {
  const bom = '\uFEFF'
  const csv = [header.join(','), ...dataRows.map(r => r.map(csvEscape).join(','))].join('\r\n')
  const blob = new Blob([bom + csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
function nowStamp() {
  const d = new Date(), p = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
}
function exportSummary() {
  if (!rows.value.length) return
  const header = ['攻击源IP', '风险分', '等级', '攻击次数', '攻击类型画像', '攻击链', '首次攻击', '最近攻击', '导出时间']
  const ts = nowStamp()
  const data = rows.value.map(r => [
    r.ip, r.riskScore, r.level, r.count, (r.tags || []).join('|'), (r.chain || []).map(stageText).join('→'),
    fmtTs(r.firstSeen), fmtTs(r.lastSeen), ts
  ])
  downloadCsv(`溯源_攻击源Top${limit.value}_${ts}.csv`, header, data)
}
function exportIpDetail() {
  const d = detail.value
  if (!d || !d.ip) return
  const ts = nowStamp()
  const header = ['攻击源IP', '时间', '阶段', '攻击类型', '规则', '动作', '命中内容', '导出时间']
  const data = (d.timeline || []).map(r => [
    d.ip, fmtTs(r.ts), stageText(r.stage), r.category || '', r.ruleId || '', actText(r.action), r.matched || '', ts
  ])
  downloadCsv(`溯源_IP_${d.ip}_${ts}.csv`, header, data)
}

async function load() {
  loading.value = true
  try {
    const resp = await api.traceSummary(limit.value) || {}
    rows.value = resp.rows || []
    if (resp.date) scope.value = resp.date + ' ' + (resp.scope || '今日真实累计')
  }
  finally { loading.value = false }
}
async function openDetail(ip) {
  detail.value = await api.traceIp(ip)
  drawer.value = true
}
onMounted(load)
</script>

<style scoped>
.p { padding: 16px; }
.bar { display: flex; align-items: center; margin-bottom: 12px; }
.hud-inline { font-size: 13px; color: var(--cyan); letter-spacing: 1px; }
.tbl { margin-top: 6px; }
.mono { font-family: 'Consolas', monospace; font-size: 12px; }
.risk { display: flex; align-items: center; gap: 8px; }
.score { font-weight: 700; font-size: 13px; min-width: 28px; text-align: right; }
.tag { margin: 2px 4px 2px 0; }
.ts { font-size: 12px; color: #9fc4e8; line-height: 1.6; }
.chain .arrow { color: var(--muted); margin: 0 3px; }
.stage { font-size: 12px; padding: 1px 8px; border-radius: 3px; border: 1px solid; white-space: nowrap; }
.st-recon { color: #9fc4e8; border-color: #4a6b8a; background: rgba(74, 107, 138, .15); }
.st-exploit { color: #e6a23c; border-color: rgba(230, 162, 60, .5); background: rgba(230, 162, 60, .12); }
.st-intrusion { color: #f56c6c; border-color: rgba(245, 108, 108, .5); background: rgba(245, 108, 108, .12); }
.st-impact { color: #ff4d4f; border-color: #ff4d4f; background: rgba(255, 77, 79, .18); font-weight: 700; }
.st-other { color: var(--muted); border-color: var(--line); }
.footnote { margin-top: 12px; font-size: 12px; color: var(--muted); line-height: 1.8; }
.drawer-body { padding: 0 4px 20px; }
.headline { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
.meta { margin-bottom: 4px; }
.steps { margin-top: 12px; }
.steps :deep(.el-step__title) { font-size: 13px; color: #cfe8ff; }
.steps :deep(.el-step__description) { font-size: 11px; color: var(--muted); }
</style>
