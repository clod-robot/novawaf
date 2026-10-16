<template>
  <div class="mecha-panel p">
    <div class="bar">
      <span class="hud-title">// 规则管理 · CVE 漏洞规则库 (引擎热加载, Redis: novawaf:rules)</span>
      <div>
        <el-button size="small" @click="showJson = !showJson">{{ showJson ? '表格视图' : 'JSON 编辑' }}</el-button>
        <el-button type="success" size="small" @click="save">下发保存</el-button>
        <el-button size="small" @click="reload">热加载</el-button>
      </div>
    </div>

    <!-- 统计 chips -->
    <div v-if="!showJson" class="stats">
      <el-tag size="small" effect="dark" type="info">规则 {{ rows.length }}</el-tag>
      <el-tag size="small" effect="dark" type="danger">CVE/CNVD {{ cveCount }}</el-tag>
      <el-tag size="small" effect="dark" class="g-cn">国产组件 {{ groupCount['国产组件'] || 0 }}</el-tag>
      <el-tag size="small" effect="dark" class="g-intl">国际通用 {{ groupCount['国际通用'] || 0 }}</el-tag>
      <el-tag size="small" effect="dark" class="g-gen">通用特征 {{ groupCount['通用攻击特征'] || 0 }}</el-tag>
      <el-tag size="small" effect="dark" type="warning">近5年高危TOP {{ top5yCount }}</el-tag>
      <el-tag size="small" effect="dark" type="danger">block {{ actionCount.block || 0 }}</el-tag>
      <el-tag size="small" effect="dark" type="info">log {{ actionCount.log || 0 }}</el-tag>
    </div>

    <!-- 检索与筛选 -->
    <div v-if="!showJson" class="filters">
      <el-input v-model="kw" size="small" clearable placeholder="检索 CVE 编号 / 漏洞名 / 组件 / 特征串"
        class="kw" prefix-icon="Search" />
      <el-select v-model="fgroup" size="small" clearable placeholder="分组" class="sel">
        <el-option label="国产组件" value="国产组件" />
        <el-option label="国际通用" value="国际通用" />
        <el-option label="通用攻击特征" value="通用攻击特征" />
      </el-select>
      <el-select v-model="fsev" size="small" clearable placeholder="严重度" class="sel">
        <el-option label="critical" value="critical" />
        <el-option label="high" value="high" />
        <el-option label="medium" value="medium" />
      </el-select>
      <el-checkbox v-model="ftop" size="small" class="topck">近5年高危TOP</el-checkbox>
      <span class="fcount">命中 {{ filtered.length }} / {{ rows.length }}</span>
    </div>

    <!-- 表格视图 -->
    <el-table v-if="!showJson" :data="filtered" size="small" stripe height="480" border>
      <el-table-column type="expand" width="28">
        <template #default="{ row }">
          <div class="detail">
            <div v-if="row.vulnName"><b>漏洞：</b>{{ row.vulnName }}</div>
            <div v-if="row.desc"><b>说明：</b>{{ row.desc }}</div>
            <div v-if="row.cvss"><b>CVSS：</b>{{ row.cvss }} <span v-if="row.year">· {{ row.year }}</span></div>
            <div v-if="row.ref"><b>参考：</b><a :href="row.ref" target="_blank" class="reflink">{{ row.ref }}</a></div>
          </div>
        </template>
      </el-table-column>
      <el-table-column prop="id" label="ID" width="60" sortable />
      <el-table-column label="CVE/CNVD" width="140">
        <template #default="{ row }">
          <span v-if="row.cve" class="cve mono">{{ row.cve }}</span>
          <span v-else class="nocve">-</span>
        </template>
      </el-table-column>
      <el-table-column prop="name" label="规则名称" min-width="200" show-overflow-tooltip />
      <el-table-column label="影响组件" width="150">
        <template #default="{ row }"><span v-if="row.component">{{ row.component }}</span><span v-else class="nocve">-</span></template>
      </el-table-column>
      <el-table-column label="分组" width="110">
        <template #default="{ row }">
          <el-tag size="small" :class="groupCls(row.group)">{{ row.group || '通用攻击特征' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="严重度" width="90">
        <template #default="{ row }">
          <el-tag v-if="row.severity" size="small" :type="sevType(row.severity)" effect="dark">{{ row.severity }}</el-tag>
          <span v-else class="nocve">-</span>
        </template>
      </el-table-column>
      <el-table-column prop="category" label="类型" width="118">
        <template #default="{ row }">
          <el-tag size="small" :type="tagType(row.category)">{{ row.category }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="pattern" label="匹配特征" min-width="210">
        <template #default="{ row }"><code class="mono">{{ row.pattern }}</code></template>
      </el-table-column>
      <el-table-column prop="action" label="动作" width="80">
        <template #default="{ row }">
          <el-tag size="small" :type="row.action === 'block' ? 'danger' : row.action === 'pass' ? 'success' : 'info'">
            {{ row.action }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="启用" width="60">
        <template #default="{ row }">
          <el-tag size="small" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '是' : '否' }}</el-tag>
        </template>
      </el-table-column>
    </el-table>
    <div v-if="!showJson" class="hint">
      共 {{ rows.length }} 条规则（{{ cveCount }} 个 CVE/CNVD）。点行首箭头查看漏洞详情与参考链接；
      「近5年高危TOP」= 年份≥2021 且 CVSS≥9.0。点「JSON 编辑」可新增/修改后下发，引擎将在 60s 内热加载生效。
    </div>

    <!-- JSON 编辑视图 -->
    <el-input v-else v-model="json" type="textarea" :rows="24" class="mono"
      placeholder='[{"id":1,"name":"...","pattern":"...","category":"SQLi","action":"block","enabled":true,"group":"国产组件","cve":"CVE-XXXX-XXXX","severity":"critical","component":"...","cvss":9.8,"year":2024,"desc":"..."}]' />
  </div>
</template>
<script setup>
import { onMounted, ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
const json = ref('')
const showJson = ref(false)
const kw = ref('')
const fgroup = ref('')
const fsev = ref('')
const ftop = ref(false)
const rows = computed(() => {
  try { const v = JSON.parse(json.value); return Array.isArray(v) ? v : [] } catch { return [] }
})
const filtered = computed(() => {
  const k = kw.value.trim().toLowerCase()
  return rows.value.filter(r => {
    if (fgroup.value && (r.group || '通用攻击特征') !== fgroup.value) return false
    if (fsev.value && r.severity !== fsev.value) return false
    if (ftop.value && !isTop5y(r)) return false
    if (!k) return true
    return [r.cve, r.name, r.vulnName, r.component, r.pattern, r.category]
      .some(v => v && String(v).toLowerCase().includes(k))
  })
})
const groupCount = computed(() => rows.value.reduce((m, r) => { const g = r.group || '通用攻击特征'; m[g] = (m[g] || 0) + 1; return m }, {}))
const actionCount = computed(() => rows.value.reduce((m, r) => { m[r.action] = (m[r.action] || 0) + 1; return m }, {}))
const cveCount = computed(() => new Set(rows.value.map(r => r.cve).filter(Boolean)).size)
const top5yCount = computed(() => rows.value.filter(isTop5y).length)
function isTop5y(r) { return (r.year || 0) >= 2021 && (r.cvss || 0) >= 9.0 }
function tagType(cat) {
  return { SQLi: 'danger', XSS: 'warning', RCE: 'danger', Traversal: 'warning', XXE: 'danger',
           Scanner: 'info', InfoLeak: '', Deserialization: 'danger', AuthBypass: 'warning', SSRF: 'warning' }[cat] || ''
}
function sevType(s) { return { critical: 'danger', high: 'warning', medium: 'info' }[s] || 'info' }
function groupCls(g) { return { '国产组件': 'g-cn', '国际通用': 'g-intl', '通用攻击特征': 'g-gen' }[g] || 'g-gen' }
onMounted(async () => { const r = await api.wafRules(); json.value = JSON.stringify(r, null, 2) })
async function save() {
  try { JSON.parse(json.value) } catch { return ElMessage.error('JSON 格式错误') }
  await api.saveRules(json.value); ElMessage.success('已下发并触发热加载')
}
async function reload() { await api.reloadRules(); ElMessage.success('已 bump 版本号,引擎将热加载') }
</script>
<style scoped>
.p { padding: 16px; }
.bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.stats { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
.filters { display: flex; gap: 10px; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }
.kw { width: 300px; }
.sel { width: 140px; }
.topck { margin: 0; }
.fcount { font-size: 12px; opacity: .75; }
.mono { font-family: monospace; font-size: 12px; }
.cve { color: #ff6b6b; font-weight: 600; }
.nocve { opacity: .4; }
.hint { margin-top: 10px; font-size: 12px; opacity: .7; }
.detail { padding: 6px 12px; font-size: 12px; line-height: 1.9; }
.reflink { color: #4da3ff; word-break: break-all; }
.g-cn { --el-tag-bg-color: rgba(255, 77, 79, .15); }
:deep(.g-cn) { color: #ff8589 !important; border-color: rgba(255,77,79,.4) !important; background: rgba(255,77,79,.12) !important; }
:deep(.g-intl) { color: #6fb7ff !important; border-color: rgba(111,183,255,.4) !important; background: rgba(111,183,255,.12) !important; }
:deep(.g-gen) { color: #9aa4b5 !important; border-color: rgba(154,164,181,.35) !important; background: rgba(154,164,181,.1) !important; }
</style>
