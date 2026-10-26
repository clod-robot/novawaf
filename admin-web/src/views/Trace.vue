<template>
  <div class="mecha-panel p">
    <el-tabs v-model="tab" class="trace-tabs">
      <!-- ============ 页签 1：攻击源 IP 排行 ============ -->
      <el-tab-pane label="攻击源 IP 排行" name="ip">
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
      <el-button size="small" type="success" plain :loading="exporting" @click="exportSummary">导出证据包</el-button>
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
      「导出证据包」会同时生成明文 CSV 与 AES-256-GCM 加密包（32 位随机密码仅显示一次、不做任何保存），可用于公安电子证据留存与防篡改校验。
    </p>
      </el-tab-pane>

      <!-- ============ 页签 2：API 维度统计 ============ -->
      <el-tab-pane label="API 维度统计" name="api">
    <div class="bar">
      <span class="hud-inline">// 按 API(Host + URI) 统计攻击/拦截量（评估防护策略效果）</span>
      <span style="flex:1"></span>
      <el-select v-model="apiApp" size="small" clearable placeholder="所属应用" style="width:150px;margin-right:8px">
        <el-option label="全部应用" value="__all__" />
        <el-option v-for="a in apps" :key="a.id" :label="a.name" :value="String(a.id)" />
      </el-select>
      <el-date-picker v-model="apiRange" type="datetimerange" size="small" range-separator="至"
                      start-placeholder="开始时间" end-placeholder="结束时间" value-format="X"
                      style="width:330px;margin-right:8px" @change="loadApiStats" />
      <el-button size="small" @click="resetApiRange">今天</el-button>
      <el-button size="small" @click="loadApiStats">刷新</el-button>
    </div>
    <div v-if="apiSummary.length" class="api-summary">
      <span v-for="s in apiSummary" :key="s.name" class="sum-chip" :class="{ active: apiApp === s.id }"
            @click="apiApp = apiApp === s.id ? '' : s.id">
        {{ s.name }} <b>{{ fmtBig(s.total) }}</b>
      </span>
    </div>
    <DataTable :data="apiRowsView" :columns="apiColumns" height="calc(100vh - 300px)" class="tbl" v-loading="apiLoading">
      <template #cell-appName="{ row }">
        <el-tag size="small" effect="plain" :type="row.host ? 'primary' : 'info'">{{ row.appName }}</el-tag>
      </template>
      <template #cell-host="{ row }"><span class="mono">{{ row.host || '-' }}</span></template>
      <template #cell-uri="{ row }"><span class="mono">{{ row.uri }}</span></template>
      <template #cell-total="{ row }"><span class="num hit">{{ fmtBig(row.total) }}</span></template>
      <template #cell-blocked="{ row }"><span class="num blk">{{ fmtBig(row.blocked) }}</span></template>
      <template #cell-challenged="{ row }"><span class="num chal">{{ fmtBig(row.challenged) }}</span></template>
      <template #cell-attackers="{ row }">{{ fmtBig(row.attackers) }}</template>
      <template #cell-blockRate="{ row }">
        <el-progress :percentage="blockRate(row)" :stroke-width="8" color="#ff6b81" />
      </template>
      <template #cell-lastTs="{ row }"><span class="mono">{{ fmtTs(row.lastTs) }}</span></template>
    </DataTable>
    <p class="footnote">
      数据来源：分钟聚合表 waf_api_stat（由 MySQL 归档 waf_attack_event 每分钟预聚合，页面查询不再扫明细表，延迟约 1 分钟）。
      攻击次数 = 该时段命中该 API 的攻击事件总数；拦截 = action=block；挑战 = action=challenge（人机验证）；攻击源 = 该时段内单分钟峰值独立 IP 数。
      所属应用按事件 Host 头匹配防护应用域名，未匹配归入「未绑定应用」。
      默认统计范围为今天 0 点至当前，可自行选择任意时段（超出预聚合覆盖范围时自动回退明细表查询，速度较慢但结果完整）。
    </p>
      </el-tab-pane>
    </el-tabs>

    <!-- 单 IP 攻击链详情抽屉 -->
    <el-drawer v-model="drawer" :title="'攻击链溯源 // ' + (detail.ip || '')" size="62%" destroy-on-close>
      <div v-if="detail.ip" class="drawer-body">
        <!-- 概要 -->
        <div class="headline">
          <el-tag :type="levelType(detail.level)" effect="dark">{{ detail.level }} · {{ detail.riskScore }} 分</el-tag>
          <el-tag v-for="t in detail.tags" :key="t" size="small" effect="plain" class="tag">{{ t }}</el-tag>
          <span style="flex:1"></span>
          <el-date-picker v-model="range" type="datetimerange" size="small" range-separator="至"
                          start-placeholder="开始时间" end-placeholder="结束时间" value-format="X"
                          style="width:330px;margin-right:8px" @change="reloadDetail" />
          <el-button size="small" type="success" plain :loading="exporting" @click="exportIpDetail">导出本 IP 证据包</el-button>
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
          <template #cell-uri="{ row }"><span class="mono">{{ row.uri ? (row.host || '') + row.uri : '-' }}</span></template>
          <template #cell-action="{ row }">
            <el-tag :type="row.action === 'block' ? 'danger' : 'info'" size="small" effect="dark">{{ actText(row.action) }}</el-tag>
          </template>
        </DataTable>
      </div>
    </el-drawer>

    <!-- 一次性密码弹窗：密码不保存，关闭即销毁 -->
    <el-dialog v-model="pwdOpen" title="加密证据包已生成 · 密码仅显示一次" width="660px" :close-on-click-modal="false"
               @closed="closePwd">
      <el-alert type="error" :closable="false" show-icon
                title="密码不保存在任何位置（不写本地存储、不上传后端），关闭本窗口后无法找回。请立即抄录或复制，并与证据文件分开保管。" />
      <div class="pwd-block">
        <div class="pwd-label">文件</div>
        <div class="pwd-files">
          <div><span class="mono">{{ pwdInfo.csvFile }}</span> <span class="muted">— 明文 CSV（可阅卷，改动会与下方摘要不一致）</span></div>
          <div><span class="mono">{{ pwdInfo.encFile }}</span> <span class="muted">— AES-256 加密包（无密码不可查看/修改，{{ pwdInfo.bytes }} 字节明文）</span></div>
        </div>
        <div class="pwd-label">加密密码（32 位强密码）</div>
        <div class="pwd-row">
          <el-input :model-value="pwdInfo.password" readonly class="mono pwd-input" />
          <el-button type="primary" @click="copyPwd">复制密码</el-button>
        </div>
        <div class="pwd-label">明文 SHA-256 摘要</div>
        <div class="pwd-row">
          <el-input :model-value="pwdInfo.digest" readonly class="mono pwd-input" />
          <el-button @click="copyDigest">复制摘要</el-button>
        </div>
        <p class="pwd-note">
          校验方法：对明文 CSV 计算 SHA-256，结果须与上方摘要完全一致；不一致说明文件已被篡改。
          加密包采用 PBKDF2-HMAC-SHA256 派生密钥 + AES-256-CBC 加密，并对密文做 HMAC-SHA256 认证，
          密文被改动 1 字节即校验失败、无法解密。
        </p>
      </div>
      <template #footer>
        <el-button type="primary" @click="closePwd">我已记录密码，关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { fmtBig } from '../utils/format'
import DataTable from '../components/DataTable.vue'
import { genPassword, encryptEvidence, download, copyText, operatorName, nowStamp, buildCsv } from '../utils/evidence'

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
  { prop: 'uri', label: '目标 URI', minWidth: 220, slot: 'uri' },
  { prop: 'matched', label: '命中内容', minWidth: 200 }
]
const apiColumns = [
  { prop: 'appName', label: '所属应用', width: 140, slot: 'appName', noSearch: true },
  { prop: 'host', label: 'Host', width: 150, slot: 'host' },
  { prop: 'uri', label: 'URI', minWidth: 240, slot: 'uri' },
  { label: '攻击次数', width: 100, align: 'right', slot: 'total', noSearch: true },
  { label: '拦截', width: 90, align: 'right', slot: 'blocked', noSearch: true },
  { label: '挑战', width: 90, align: 'right', slot: 'challenged', noSearch: true },
  { label: '攻击源数', width: 90, align: 'right', slot: 'attackers', noSearch: true },
  { label: '拦截率', minWidth: 120, slot: 'blockRate', noSearch: true },
  { label: '最近攻击', width: 165, slot: 'lastTs', noSearch: true }
]

const rows = ref([]), limit = ref(50), loading = ref(false)
const scope = ref('加载中…')
const tab = ref('ip')
const apiRows = ref([]), apiLoading = ref(false), apiRange = ref(null)
const apiApp = ref('')
const apps = ref([])
const drawer = ref(false), detail = ref({})
const range = ref(null)   // [from_epoch_sec, to_epoch_sec]
const currentIp = ref('')

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

// ---------- 证据导出（明文 CSV + AES-256 加密证据包，密码一次性显示不保存） ----------
const exporting = ref(false)
const pwdOpen = ref(false)
const pwdInfo = ref({ password: '', digest: '', encFile: '', csvFile: '', bytes: 0 })

async function doExport(filenameBase, header, dataRows) {
  if (!dataRows.length) { ElMessage.warning('当前没有可导出的数据'); return }
  exporting.value = true
  try {
    const ts = nowStamp()
    const csvFile = `${filenameBase}_${ts}.csv`
    const csv = buildCsv(header, dataRows)
    // 1) 明文 CSV（UTF-8 BOM，Excel 可直接打开；内容任何改动都会与 SHA-256 摘要不一致）
    download(csvFile, '\uFEFF' + csv, 'text/csv;charset=utf-8')
    // 2) AES-256 加密证据包：无密码无法查看/修改，密文改动 1 字节即 MAC 校验失败
    const password = genPassword(32)
    const enc = await encryptEvidence(csv, password, { filename: csvFile, operator: operatorName() })
    download(csvFile + '.enc', enc.text)
    // 3) 密码仅在此处一次性展示，不写 localStorage / 不上送后端
    pwdInfo.value = { password, digest: enc.digest, encFile: csvFile + '.enc', csvFile, bytes: enc.bytes }
    pwdOpen.value = true
  } catch (e) {
    ElMessage.error('加密证据包生成失败：' + (e && e.message ? e.message : e))
  } finally { exporting.value = false }
}

async function exportSummary() {
  const header = ['攻击源IP', '风险分', '等级', '攻击次数', '攻击类型画像', '攻击链', '首次攻击', '最近攻击', '导出操作人', '导出时间']
  const ts = new Date().toLocaleString('zh-CN', { hour12: false })
  const op = operatorName()
  const data = rows.value.map(r => [
    r.ip, r.riskScore, r.level, r.count, (r.tags || []).join('|'), (r.chain || []).map(stageText).join('→'),
    fmtTs(r.firstSeen), fmtTs(r.lastSeen), op, ts
  ])
  await doExport(`溯源_攻击源Top${limit.value}`, header, data)
}

async function exportIpDetail() {
  const d = detail.value
  if (!d || !d.ip) return
  const header = ['攻击源IP', '时间', '阶段', '攻击类型', '规则', '动作', '目标URI', '命中内容', '风险分', '等级', '导出操作人', '导出时间']
  const ts = new Date().toLocaleString('zh-CN', { hour12: false })
  const op = operatorName()
  const data = (d.timeline || []).map(r => [
    d.ip, fmtTs(r.ts), stageText(r.stage), r.category || '', r.ruleId || '', actText(r.action),
    r.uri ? (r.host || '') + r.uri : '', r.matched || '', d.riskScore, d.level, op, ts
  ])
  await doExport(`溯源_IP_${d.ip}`, header, data)
}

async function copyPwd() {
  const ok = await copyText(pwdInfo.value.password)
  ElMessage[ok ? 'success' : 'error'](ok ? '密码已复制' : '复制失败，请手动选中复制')
}
async function copyDigest() {
  const ok = await copyText(pwdInfo.value.digest)
  ElMessage[ok ? 'success' : 'error'](ok ? 'SHA-256 已复制' : '复制失败，请手动选中复制')
}
function closePwd() { pwdOpen.value = false; pwdInfo.value = { password: '', digest: '', encFile: '', csvFile: '', bytes: 0 } }

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
  currentIp.value = ip
  range.value = null
  detail.value = await api.traceIp(ip)
  drawer.value = true
}
async function reloadDetail() {
  if (!currentIp.value) return
  const from = range.value && range.value[0] ? Number(range.value[0]) : undefined
  const to = range.value && range.value[1] ? Number(range.value[1]) : undefined
  detail.value = await api.traceIp(currentIp.value, from, to)
}

// ---------- API 维度统计 ----------
function todayRange() {
  const now = Math.floor(Date.now() / 1000)
  const d = new Date(); d.setHours(0, 0, 0, 0)
  return [Math.floor(d.getTime() / 1000), now]
}
function resetApiRange() { apiRange.value = todayRange(); loadApiStats() }

// 应用归属：按事件 Host 头匹配应用域名，未匹配的归入「未绑定应用」
function appOf(host) {
  const h = String(host || '').toLowerCase()
  if (!h) return { id: '', name: '未知应用' }
  const a = apps.value.find((x) => String(x.host || '').toLowerCase() === h)
  return a ? { id: String(a.id), name: a.name } : { id: '', name: '未绑定应用' }
}
const apiRowsView = computed(() => {
  let list = apiRows.value.map((r) => {
    const a = appOf(r.host)
    return { ...r, appId: a.id, appName: a.name }
  })
  if (apiApp.value && apiApp.value !== '__all__') list = list.filter((r) => r.appId === apiApp.value)
  return list.sort((a, b) => (Number(b.total) || 0) - (Number(a.total) || 0))
})
// 每个应用的攻击量汇总，作为顶部快捷筛选
const apiSummary = computed(() => {
  const m = new Map()
  for (const r of apiRows.value) {
    const a = appOf(r.host)
    const key = a.id || 'none'
    const cur = m.get(key) || { id: a.id || 'none', name: a.name, total: 0 }
    cur.total += Number(r.total) || 0
    m.set(key, cur)
  }
  return [...m.values()].sort((x, y) => y.total - x.total).slice(0, 8)
})

function blockRate(row) {
  const t = Number(row.total) || 0
  return t > 0 ? Math.round((Number(row.blocked) || 0) * 100 / t) : 0
}
async function loadApiStats() {
  apiLoading.value = true
  try {
    const from = apiRange.value && apiRange.value[0] ? Number(apiRange.value[0]) : undefined
    const to = apiRange.value && apiRange.value[1] ? Number(apiRange.value[1]) : undefined
    const resp = await api.traceUriStats(from, to, 200) || {}
    apiRows.value = resp.rows || []
  } finally { apiLoading.value = false }
}

onMounted(() => {
  load()
  apiRange.value = todayRange()
  loadApiStats()
  api.wafApps().then((x) => { apps.value = x || [] }).catch(() => { apps.value = [] })
})
</script>

<style scoped>
.p { padding: 16px; }
.api-summary { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
.sum-chip {
  font-size: 12px; padding: 3px 10px; border-radius: 12px; cursor: pointer;
  border: 1px solid rgba(0, 229, 255, .25); background: rgba(0, 229, 255, .06);
  color: #bfe9ff; transition: all .2s ease;
}
.sum-chip:hover { transform: translateY(-1px); box-shadow: 0 2px 10px rgba(0, 229, 255, .25); }
.sum-chip.active { border-color: #00e5ff; background: rgba(0, 229, 255, .18); color: #eaffff; }
.sum-chip b { margin-left: 4px; color: #7fe7ff; font-variant-numeric: tabular-nums; }
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
.pwd-block { margin-top: 14px; }
.pwd-label { font-size: 12px; color: var(--muted); margin: 14px 0 6px; letter-spacing: 1px; }
.pwd-files { font-size: 12px; line-height: 1.9; color: #cfe9ff; }
.pwd-row { display: flex; gap: 10px; align-items: center; }
.pwd-input { flex: 1; }
.pwd-input :deep(.el-input__inner) { font-family: monospace; letter-spacing: 1px; }
.pwd-note { margin-top: 14px; font-size: 12px; color: var(--muted); line-height: 1.8; }
.muted { color: var(--muted); }
.num { font-variant-numeric: tabular-nums; font-weight: 600; }
.num.hit { color: #7fe7ff; }
.num.blk { color: #ff6b81; }
.num.chal { color: #e6a23c; }
.headline { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
.meta { margin-bottom: 4px; }
.steps { margin-top: 12px; }
.steps :deep(.el-step__title) { font-size: 13px; color: #cfe8ff; }
.steps :deep(.el-step__description) { font-size: 11px; color: var(--muted); }
</style>
