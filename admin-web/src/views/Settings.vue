<template>
  <div class="settings">
    <!-- 全局防护模式（WAF 指纹三态） -->
    <el-card class="panel mecha-panel" shadow="never">
      <template #header>
        <div class="card-head">
          <span class="t">全局防护模式</span>
          <el-tag :type="tagType" effect="dark">{{ modeLabel }}</el-tag>
        </div>
      </template>

      <el-radio-group v-model="mode" class="modes">
        <div class="mode-item">
          <el-radio value="hidden" size="large">
            <span class="m-name">开启 · 隐藏指纹</span>
            <el-tag size="small" type="success" effect="plain" class="rec">推荐 · 默认</el-tag>
          </el-radio>
          <div class="m-desc">防护全开，但拦截页、响应头、Cookie 均不暴露 WAF 品牌（对外表现为普通 nginx），攻击者无法识别防护产品。</div>
        </div>
        <div class="mode-item">
          <el-radio value="public" size="large"><span class="m-name">开启 · 公开指纹</span></el-radio>
          <div class="m-desc">防护全开，拦截页与响应头（Server / X-WAF）公开 NovaWAF 品牌，可被 wafw00f 等工具识别，起威慑作用。</div>
        </div>
        <div class="mode-item">
          <el-radio value="off" size="large"><span class="m-name">关闭防护</span></el-radio>
          <div class="m-desc">全站降级为旁路观察：攻击仅记录，不拦截、不封禁。仅用于应急排障，慎用。</div>
        </div>
      </el-radio-group>

      <div class="ops">
        <el-button type="primary" :loading="saving" :disabled="mode === cur" @click="save">保存并生效</el-button>
        <span class="hint">引擎热路径读取，保存后 2 秒内全站生效，无需重启</span>
      </div>

      <el-alert class="why" type="info" :closable="false" show-icon>
        <template #title>为什么推荐「隐藏指纹」？</template>
        <ul class="why-list">
          <li><b>增加侦察成本</b>：攻击者无法用 wafw00f 等工具识别防护产品，无法针对性选择绕过手法</li>
          <li><b>混淆攻击面</b>：响应特征与原生 nginx 完全一致，攻击者难以判断目标是否有 WAF、拦截来自 WAF 还是应用本身</li>
          <li><b>防指纹绕过</b>：公开品牌等于告知规则库类型，隐藏后攻击者只能盲测，已知绕过手法全部失效</li>
          <li><b>防护不打折</b>：隐藏只是"隐身"——检测、拦截页、追踪 ID、CC 限流、自动封禁全部照常工作</li>
        </ul>
      </el-alert>
    </el-card>

    <!-- 拟态防御（动态指纹 / 移动目标防御） -->
    <el-card class="panel mecha-panel" shadow="never">
      <template #header>
        <div class="card-head">
          <span class="t">拟态防御</span>
          <div>
            <el-tag v-if="mc.enabled && mc.status.persona" type="success" effect="dark" class="persona-tag">
              当前人格：{{ mc.status.persona }}
            </el-tag>
            <el-tag :type="mc.enabled ? 'success' : 'info'" effect="dark">
              {{ mc.enabled ? '运行中' : '已关闭' }}
            </el-tag>
          </div>
        </div>
      </template>

      <div class="mimic-form">
        <div class="row">
          <span class="label">启用拟态防御</span>
          <el-switch v-model="mc.enabled" />
          <span class="hint">仅作用于「开启 · 隐藏指纹」模式；公开指纹模式以品牌威慑为先</span>
        </div>
        <div class="row">
          <span class="label">轮换窗口</span>
          <el-input-number v-model="mc.windowMin" :min="5" :max="1440" :step="5" />
          <span class="hint">分钟（5-1440）。窗口内人格稳定（正常用户体验一致），跨窗自动轮换</span>
        </div>
        <div class="row">
          <span class="label">人格盐</span>
          <el-tag size="small" :type="mc.saltSet ? 'success' : 'info'" effect="plain">
            {{ mc.saltSet ? '已设置' : '未设置（使用默认序列）' }}
          </el-tag>
          <el-button size="small" :loading="rotating" @click="rotateSalt">一键换盐</el-button>
          <span class="hint">换盐后全部人格序列立即更换，正在进行的探测结论即刻作废</span>
        </div>
      </div>

      <template v-if="mc.enabled && mc.status.persona">
        <el-descriptions :column="4" border size="small" class="persona-view">
          <el-descriptions-item label="伪装 Server">{{ mc.status.banner }}</el-descriptions-item>
          <el-descriptions-item label="拦截状态码">{{ mc.status.blockStatus }}</el-descriptions-item>
          <el-descriptions-item label="会话 Cookie 名">{{ mc.status.cookieName }}</el-descriptions-item>
          <el-descriptions-item label="窗口剩余">{{ remainText }}</el-descriptions-item>
        </el-descriptions>
      </template>

      <div class="ops">
        <el-button type="primary" :loading="mimicSaving" @click="saveMimic">保存并生效</el-button>
        <el-button size="default" @click="load">刷新</el-button>
        <span class="hint">引擎热路径读取，保存后 2 秒内生效，无需重启</span>
      </div>

      <el-alert class="why" type="info" :closable="false" show-icon>
        <template #title>拟态防御如何让探测失效？</template>
        <ul class="why-list">
          <li><b>指纹矛盾化</b>：拦截响应的 Server banner / 状态码 / 页面风格 / Cookie 名按人格池整体轮换（nginx、Apache、IIS、openresty、Tengine…），wafw00f 等工具跨窗采集到自相矛盾的指纹，无法归因产品</li>
          <li><b>扫描结果投毒</b>：人格池含 404（被拦路径在扫描报告中"不存在"）与 503（伪装过载诱导降速）幽灵人格，直接污染扫描器结论</li>
          <li><b>探测干扰</b>：识别扫描器 UA 后，其拦截响应每次随机人格——同窗内连续探测也无法获得稳定指纹</li>
          <li><b>零检测损耗</b>：内部解析与检测始终全维度最严，拟态只改变对外表现，不引入任何绕过面</li>
        </ul>
      </el-alert>
    </el-card>

    <!-- 阈值管理（端点分级限流：monitor 采集 → 分阶段 enforce） -->
    <el-card class="panel mecha-panel" shadow="never">
      <template #header>
        <div class="card-head">
          <span class="t">阈值管理 · 端点分级限流</span>
          <div>
            <el-tag :type="stageTag" effect="dark">{{ stageLabel }}</el-tag>
            <el-button size="small" style="margin-left:10px" @click="openRl">配置弹窗</el-button>
          </div>
        </div>
      </template>

      <el-table :data="rlRows" size="small" class="rl-table">
        <el-table-column label="端点类别" width="110">
          <template #default="{ row }"><b class="rl-cls">{{ row.label }}</b></template>
        </el-table-column>
        <el-table-column label="QPS 配额" width="90">
          <template #default="{ row }">{{ row.cfg.qps || '不限' }}</template>
        </el-table-column>
        <el-table-column label="Burst" width="70">
          <template #default="{ row }">{{ row.cfg.burst || '—' }}</template>
        </el-table-column>
        <el-table-column label="实测 P99" width="90">
          <template #default="{ row }">{{ fmtNum(row.dist?.p99) }}</template>
        </el-table-column>
        <el-table-column label="建议阈值" width="100">
          <template #default="{ row }">
            <span class="rl-suggest">{{ row.dist ? fmtNum(row.dist.suggestQps) : '采集中' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="建议 Burst" width="90">
          <template #default="{ row }">{{ row.dist?.suggestBurst ?? '—' }}</template>
        </el-table-column>
        <el-table-column label="桶利用率 P95" width="110">
          <template #default="{ row }">
            <span :class="{ 'rl-warn': (row.dist?.utilP95 ?? 0) > 0.6 }">{{ fmtNum(row.dist?.utilP95) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="本应拦截/分" width="100">
          <template #default="{ row }">{{ row.dist?.wouldBlock1m ?? 0 }}</template>
        </el-table-column>
        <el-table-column label="状态">
          <template #default="{ row }">
            <el-tag size="small" :type="row.cfg.enabled ? 'success' : 'info'" effect="plain">
              {{ row.cls === 'static' ? '只记账' : row.cfg.enabled ? '启用' : '停用' }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>

      <div class="ops">
        <span class="hint">
          上线顺序：monitor（只记账不处置，采集每 IP 每端点 QPS 分布）→ 仅 auth enforce → 加 read/write/upload → 最后开封禁阶梯（仅到 L2 URL+方法，不开全端口）。
          阈值 = max(P99 × 3, 业务最小值)；burst = P99.9 的 3 秒峰值。盯两个指标：桶利用率 P95 &gt; 0.6（偏紧）、封禁速率/分 &gt; 5（误伤突增）。
        </span>
      </div>
      <div class="ops" v-if="rl.metrics">
        <span class="hint">引擎指标：L1 限流 {{ rl.metrics.l1LastMin ?? 0 }}/分 · L2 封禁 {{ rl.metrics.bansLastMin ?? 0 }}/分 · 策略版本 v{{ rl.version }}</span>
      </div>

      <el-dialog v-model="rlDlg" title="阈值策略配置" width="680px" append-to-body>
        <div class="rl-stage">
          <span class="label">上线阶段</span>
          <el-radio-group v-model="rlForm.stage">
            <el-radio :value="0">0 · monitor-only</el-radio>
            <el-radio :value="1">1 · 仅 auth</el-radio>
            <el-radio :value="2">2 · +read/write/upload</el-radio>
            <el-radio :value="3">3 · +封禁阶梯(L2)</el-radio>
          </el-radio-group>
        </div>
        <div class="rl-presets">
          <span class="label">三档预设</span>
          <el-button size="small" @click="applyPreset('light')">轻（宽松/低误伤）</el-button>
          <el-button size="small" @click="applyPreset('mid')">中（推荐默认）</el-button>
          <el-button size="small" @click="applyPreset('strict')">高（严格）</el-button>
        </div>
        <el-table :data="rlFormRows" size="small" class="rl-table">
          <el-table-column label="类别" width="90">
            <template #default="{ row }">{{ row.label }}</template>
          </el-table-column>
          <el-table-column label="QPS" width="150">
            <template #default="{ row }">
              <el-input-number v-model="row.cfg.qps" :min="0" :max="100000" :step="row.cls === 'auth' ? 0.05 : 1"
                               :disabled="row.cls === 'static'" controls-position="right" size="small" />
            </template>
          </el-table-column>
          <el-table-column label="Burst" width="120">
            <template #default="{ row }">
              <el-input-number v-model="row.cfg.burst" :min="0" :max="1000000"
                               :disabled="row.cls === 'static'" controls-position="right" size="small" />
            </template>
          </el-table-column>
          <el-table-column label="业务最小值" width="120">
            <template #default="{ row }">
              <el-input-number v-model="row.cfg.minQps" :min="0" :max="100000"
                               :disabled="row.cls === 'static'" controls-position="right" size="small" />
            </template>
          </el-table-column>
          <el-table-column label="启用" width="70">
            <template #default="{ row }">
              <el-switch v-model="row.cfg.enabled" :disabled="row.cls === 'static'" />
            </template>
          </el-table-column>
        </el-table>
        <div class="rl-stage" style="margin-top:12px">
          <span class="label">封禁阶梯</span>
          <span class="hint">60s 内超限</span>
          <el-input-number v-model="rlForm.banStrikes" :min="1" :max="100" size="small" controls-position="right" />
          <span class="hint">次 → L2 封禁（该 URL+方法）</span>
          <el-input-number v-model="rlForm.banSec" :min="10" :max="86400" :step="30" size="small" controls-position="right" />
          <span class="hint">秒</span>
        </div>
        <template #footer>
          <el-button @click="rlDlg = false">取消</el-button>
          <el-button type="primary" :loading="rlSaving" @click="saveRl">保存并热生效</el-button>
        </template>
      </el-dialog>
    </el-card>

    <!-- 检测规则版本管理 -->
    <el-card class="panel mecha-panel" shadow="never">
      <template #header>
        <div class="card-head">
          <span class="t">检测规则版本</span>
          <el-button size="small" @click="load">刷新</el-button>
        </div>
      </template>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="当前版本">v{{ rv.version }}</el-descriptions-item>
        <el-descriptions-item label="规则条数">{{ rv.count }}</el-descriptions-item>
        <el-descriptions-item label="最近更新">{{ rv.updatedAt || '—' }}</el-descriptions-item>
        <el-descriptions-item label="规则集">{{ rv.source }}</el-descriptions-item>
      </el-descriptions>
      <div class="rv-tip">
        规则在「规则管理」保存后自动递增版本号；引擎按版本号热加载（60s 轮询），无需重启。
        规则集等效覆盖 OWASP CRS 核心类别：SQLi / XSS / RCE / 路径穿越 / 反序列化 / XXE / SSRF / 扫描器指纹 / 敏感文件探测，另含国产组件与国际通用 CVE 定向规则。
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'

const mode = ref('hidden')   // 编辑中的选择
const cur = ref('hidden')    // 服务端当前生效值
const saving = ref(false)
const rv = ref({ version: 0, count: 0, updatedAt: '', source: '' })
const mc = ref({ enabled: false, windowMin: 60, saltSet: false, status: {} })
const mimicSaving = ref(false)
const rotating = ref(false)

const LABELS = { hidden: '开启 · 隐藏指纹', public: '开启 · 公开指纹', off: '关闭防护' }
const modeLabel = computed(() => LABELS[cur.value] || cur.value)
const tagType = computed(() => ({ hidden: 'success', public: 'warning', off: 'danger' }[cur.value] || 'info'))
const remainText = computed(() => {
  const end = Number(mc.value.status?.slotEnd || 0)
  if (!end) return '—'
  const sec = Math.max(0, end - Math.floor(Date.now() / 1000))
  return `${Math.floor(sec / 60)}分${sec % 60}秒`
})

async function load() {
  const m = await api.settingsWafModeGet()
  mode.value = m.mode || 'hidden'
  cur.value = mode.value
  rv.value = await api.settingsRulesVersion()
  const c = await api.settingsMimicGet()
  mc.value = { enabled: !!c.enabled, windowMin: c.windowMin || 60, saltSet: !!c.saltSet, status: c.status || {} }
  await loadRl()
}

// ---- 阈值管理（端点分级限流） ----
const CLS_LABEL = { read: '动态读 GET /api', write: '动态写 POST 等', upload: '上传', auth: '认证端点', static: '静态资源' }
const CLS_ORDER = ['read', 'write', 'upload', 'auth', 'static']
const PRESETS = {
  light:  { read: { qps: 50, burst: 100, minQps: 20 }, write: { qps: 10, burst: 20, minQps: 5 }, upload: { qps: 4, burst: 8, minQps: 2 }, auth: { qps: 0.25, burst: 5, minQps: 0.1 } },
  mid:    { read: { qps: 20, burst: 40, minQps: 20 },  write: { qps: 5, burst: 10, minQps: 5 },   upload: { qps: 2, burst: 4, minQps: 2 }, auth: { qps: 0.1, burst: 3, minQps: 0.1 } },
  strict: { read: { qps: 8, burst: 15, minQps: 8 },    write: { qps: 2, burst: 4, minQps: 2 },    upload: { qps: 1, burst: 2, minQps: 1 }, auth: { qps: 0.05, burst: 2, minQps: 0.05 } }
}
const STAGE_LABEL = ['monitor-only 采集中', '阶段1 · 仅 auth 限流', '阶段2 · +读/写/上传限流', '阶段3 · +封禁阶梯(L2)']
const rl = ref({ policy: null, version: '0', metrics: null, dist: {} })
const rlDlg = ref(false)
const rlSaving = ref(false)
const rlForm = ref({ stage: 0, banStrikes: 3, banSec: 300, classes: {} })

const stageLabel = computed(() => STAGE_LABEL[rl.value.policy?.stage ?? 0])
const stageTag = computed(() => ['info', 'warning', 'warning', 'danger'][rl.value.policy?.stage ?? 0])
const rlRows = computed(() => CLS_ORDER.map(cls => ({
  cls, label: CLS_LABEL[cls],
  cfg: rl.value.policy?.classes?.[cls] || {},
  dist: rl.value.dist?.[cls]
})))
const rlFormRows = computed(() => CLS_ORDER.map(cls => ({
  cls, label: CLS_LABEL[cls],
  cfg: rlForm.value.classes[cls] || (rlForm.value.classes[cls] = { qps: 0, burst: 0, minQps: 0, enabled: true })
})))

function fmtNum(v) {
  if (v === null || v === undefined) return '—'
  const n = Number(v)
  return Number.isInteger(n) ? String(n) : n.toFixed(2)
}

async function loadRl() {
  try { rl.value = await api.rateLimitGet() } catch { /* 引擎未上报时静默 */ }
}

function openRl() {
  const p = rl.value.policy || {}
  rlForm.value = {
    stage: p.stage ?? 0,
    banStrikes: p.banStrikes ?? 3,
    banSec: p.banSec ?? 300,
    classes: JSON.parse(JSON.stringify(p.classes || {}))
  }
  rlDlg.value = true
}

function applyPreset(tier) {
  for (const [cls, v] of Object.entries(PRESETS[t])) {
    rlForm.value.classes[cls] = { ...(rlForm.value.classes[cls] || {}), ...v, enabled: true }
  }
}

async function saveRl() {
  const s = rlForm.value.stage
  try {
    await ElMessageBox.confirm(
      s === 0 ? 'monitor-only：只记账不处置，继续采集分布。确认保存？'
        : `确认进入阶段 ${s}（${STAGE_LABEL[s]}）？引擎 3 秒内热生效，请同步盯桶利用率与封禁速率。`,
      '下发限流策略', { type: 'warning', confirmButtonText: '确认生效', cancelButtonText: '取消' })
  } catch { return }
  rlSaving.value = true
  try {
    const msg = await api.rateLimitSave(rlForm.value)
    ElMessage.success(msg)
    rlDlg.value = false
    setTimeout(loadRl, 4000)  // 引擎 3s 热生效后刷新状态
  } finally {
    rlSaving.value = false
  }
}


async function saveMimic() {
  mimicSaving.value = true
  try {
    const msg = await api.settingsMimicSave({ enabled: mc.value.enabled, windowMin: mc.value.windowMin })
    ElMessage.success(msg)
    setTimeout(load, 2500)  // 引擎 2s 热生效后刷新人格预览
  } finally {
    mimicSaving.value = false
  }
}

async function rotateSalt() {
  try {
    await ElMessageBox.confirm(
      '换盐后全部人格序列立即更换，正在进行的攻击探测结论即刻作废。确认换盐？',
      '轮换人格盐', { type: 'warning', confirmButtonText: '确认换盐', cancelButtonText: '取消' })
  } catch { return }
  rotating.value = true
  try {
    const msg = await api.settingsMimicRotateSalt()
    ElMessage.success(msg)
    setTimeout(load, 2500)
  } finally {
    rotating.value = false
  }
}

async function save() {
  const v = mode.value
  try {
    await ElMessageBox.confirm(
      v === 'off'
        ? '关闭后全站仅观察记录、不拦截不封禁，确认关闭防护？'
        : `确认切换到「${LABELS[v]}」模式？保存后 2 秒内全站生效。`,
      '变更全局防护模式',
      { type: 'warning', confirmButtonText: '确认生效', cancelButtonText: '取消' })
  } catch { return }
  saving.value = true
  try {
    const msg = await api.settingsWafModeSave(v)
    ElMessage.success(msg)
    cur.value = v
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.settings { display: flex; flex-direction: column; gap: 14px; }
.panel { background: var(--panel); border: 1px solid var(--line); }
.card-head { display: flex; align-items: center; justify-content: space-between; }
.t { font-size: 15px; font-weight: 600; color: var(--cyan); letter-spacing: 1px; }
.modes { display: flex; flex-direction: column; gap: 12px; width: 100%; }
.mode-item { padding: 10px 14px; border: 1px solid var(--line); border-radius: 6px; }
.m-name { font-weight: 600; color: #d6ecff; }
.rec { margin-left: 8px; }
.m-desc { margin: 4px 0 0 26px; font-size: 12px; color: var(--muted); line-height: 1.6; }
.ops { margin-top: 14px; display: flex; align-items: center; gap: 12px; }
.hint { font-size: 12px; color: var(--muted); }
.why { margin-top: 16px; background: rgba(0, 229, 255, .04); border: 1px solid var(--line); }
.why-list { margin: 6px 0 0; padding-left: 18px; line-height: 1.9; font-size: 13px; }
.why-list b { color: var(--cyan); }
.rv-tip { margin-top: 12px; font-size: 12px; color: var(--muted); line-height: 1.8; }
.mimic-form { display: flex; flex-direction: column; gap: 12px; }
.mimic-form .row { display: flex; align-items: center; gap: 12px; }
.mimic-form .label { width: 84px; font-size: 13px; color: #d6ecff; font-weight: 600; }
.persona-tag { margin-right: 8px; }
.persona-view { margin-top: 14px; }
.rl-table { width: 100%; }
.rl-cls { color: #d6ecff; }
.rl-suggest { color: var(--cyan); font-weight: 600; }
.rl-warn { color: #ffb020; font-weight: 600; }
.rl-stage { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.rl-stage .label, .rl-presets .label { font-size: 13px; color: #d6ecff; font-weight: 600; }
.rl-presets { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
</style>
