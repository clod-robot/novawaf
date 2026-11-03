<template>
  <div class="mecha-panel p">
    <div class="bar">
      <span class="hud-title">// CVE 虚拟补丁 · 应急漏洞热防护 (引擎热加载)</span>
      <div class="ops">
        <el-button size="small" @click="fmtVisible = true">补丁格式</el-button>
        <el-button type="primary" size="small" @click="openEdit(null)">新增补丁</el-button>
        <el-button size="small" @click="openImport">导入 JSON</el-button>
        <el-button size="small" @click="exportJson">导出</el-button>
        <el-button type="success" size="small" :disabled="!dirty" @click="save">下发保存</el-button>
        <el-button size="small" @click="reload">热加载</el-button>
      </div>
    </div>

    <el-tabs v-model="mode" class="mtabs" @tab-change="load">
      <el-tab-pane label="字面量补丁 (AC 多模, 推荐)" name="literal" />
      <el-tab-pane label="正则补丁 (复杂指纹)" name="regex" />
    </el-tabs>
    <div v-if="mode === 'regex'" class="regex-tip">
      正则模式：match 为 ECMAScript 正则（icase，作用于归一化文本），单条 ≤256 字符、总数 ≤100，
      禁止嵌套量词 (x+)+ 形态防 ReDoS，body 仅扫前 16KB。能用工整字面量表达的特征请优先用「字面量补丁」（更快）。
    </div>

    <div class="stats">
      <el-tag size="small" effect="dark" type="info">补丁 {{ list.length }}</el-tag>
      <el-tag size="small" effect="dark" type="danger">block {{ actionCount.block || 0 }}</el-tag>
      <el-tag size="small" effect="dark" type="info">log {{ actionCount.log || 0 }}</el-tag>
      <el-tag size="small" effect="dark" type="success">pass {{ actionCount.pass || 0 }}</el-tag>
      <el-tag size="small" effect="dark" type="warning">已禁用 {{ disabledCount }}</el-tag>
      <el-tag size="small" effect="dark" type="info">版本 v{{ version }}</el-tag>
      <el-input v-model="kw" size="small" clearable placeholder="检索 CVE / 名称 / 匹配串"
        class="kw" prefix-icon="Search" />
      <span class="fcount">命中 {{ filtered.length }} / {{ list.length }}</span>
    </div>

    <el-table :data="filtered" size="small" max-height="calc(100vh - 240px)" class="tbl">
      <el-table-column prop="cve" label="CVE 编号" width="150">
        <template #default="{ row }"><span class="cve mono">{{ row.cve }}</span></template>
      </el-table-column>
      <el-table-column prop="name" label="名称" min-width="160" show-overflow-tooltip />
      <el-table-column label="严重度" width="90">
        <template #default="{ row }">
          <el-tag size="small" effect="dark" :type="sevType(row.severity)">{{ row.severity || 'high' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="动作" width="80">
        <template #default="{ row }">
          <el-tag size="small" :type="row.action === 'log' ? 'info' : row.action === 'pass' ? 'success' : 'danger'">
            {{ row.action || 'block' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="方法" width="110">
        <template #default="{ row }"><span class="mono">{{ (row.methods && row.methods.length) ? row.methods.join(',') : 'ALL' }}</span></template>
      </el-table-column>
      <el-table-column prop="uri" label="URI 收敛" min-width="120" show-overflow-tooltip>
        <template #default="{ row }"><span class="mono">{{ row.uri || '-' }}</span></template>
      </el-table-column>
      <el-table-column label="作用域" width="130">
        <template #default="{ row }"><span class="mono">{{ (row.scope && row.scope.length) ? row.scope.join(',') : '全域' }}</span></template>
      </el-table-column>
      <el-table-column prop="match" label="匹配串" min-width="200" show-overflow-tooltip>
        <template #default="{ row }"><code class="mono">{{ row.match }}</code></template>
      </el-table-column>
      <el-table-column label="启用" width="70">
        <template #default="{ row }">
          <el-switch :model-value="row.enabled !== false" size="small" @change="v => { row.enabled = v; dirty = true }" />
        </template>
      </el-table-column>
      <el-table-column label="操作" width="110" fixed="right">
        <template #default="{ row, $index }">
          <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
          <el-popconfirm title="删除该补丁?" @confirm="del($index)">
            <template #reference><el-button link type="danger" size="small">删除</el-button></template>
          </el-popconfirm>
        </template>
      </el-table-column>
    </el-table>
    <div class="hint">
      界面编辑/导入后点「下发保存」写入 Redis 并 bump 版本号，引擎 60s 轮询自动热加载（无需重启）；「热加载」仅手动 bump 版本号。
      命中事件的 ruleId = CVE 编号，类别固定为 VirtualPatch。
    </div>

    <!-- 新增/编辑对话框 -->
    <el-dialog v-model="editVisible" :title="editIdx < 0 ? '新增虚拟补丁' : '编辑虚拟补丁'" width="640px" destroy-on-close>
      <el-form :model="form" label-width="96px" size="small">
        <el-form-item label="CVE 编号" required>
          <el-input v-model="form.cve" placeholder="CVE-2024-12345 或 CNVD-2024-12345" :disabled="editIdx >= 0" class="mono" />
        </el-form-item>
        <el-form-item label="名称"><el-input v-model="form.name" placeholder="如 Log4Shell JNDI 注入" /></el-form-item>
        <el-form-item label="严重度">
          <el-select v-model="form.severity" class="w180">
            <el-option v-for="s in ['critical', 'high', 'medium', 'low']" :key="s" :label="s" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item label="动作">
          <el-radio-group v-model="form.action">
            <el-radio-button value="block">block 拦截</el-radio-button>
            <el-radio-button value="log">log 仅记录</el-radio-button>
            <el-radio-button value="pass">pass 放行</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="isRegex ? '正则表达式' : '匹配串'" required>
          <el-input v-model="form.match" class="mono"
            :placeholder="isRegex ? '如 \\$\\{jndi:(ldap|rmi)://[^/]+/  （作用于归一化文本，icase）' : '如 ${jndi:  （引擎按归一化后子串匹配）'" />
        </el-form-item>
        <el-form-item label="HTTP 方法">
          <el-select v-model="form.methods" multiple clearable placeholder="缺省匹配所有方法" class="wfull">
            <el-option v-for="m in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']" :key="m" :label="m" :value="m" />
          </el-select>
        </el-form-item>
        <el-form-item label="URI 收敛">
          <el-input v-model="form.uri" placeholder="可选，path 子串，如 /api/login" class="mono" />
        </el-form-item>
        <el-form-item label="作用域">
          <el-checkbox-group v-model="form.scope">
            <el-checkbox value="uri">uri</el-checkbox>
            <el-checkbox value="args">args</el-checkbox>
            <el-checkbox value="headers">headers</el-checkbox>
            <el-checkbox value="body">body</el-checkbox>
          </el-checkbox-group>
          <span class="dim">（不选 = 全域）</span>
        </el-form-item>
        <el-form-item label="请求头条件">
          <el-input v-model="form.headersText" type="textarea" :rows="2"
            placeholder='可选，每行一个 "头名: 包含子串"，如：&#10;x-api-version: v1' class="mono" />
        </el-form-item>
        <el-form-item label="启用"><el-switch v-model="form.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" @click="applyEdit">确定</el-button>
      </template>
    </el-dialog>

    <!-- 导入 JSON 对话框 -->
    <el-dialog v-model="impVisible" title="导入补丁 JSON" width="640px" destroy-on-close>
      <div class="impbar">
        <el-radio-group v-model="impMode" size="small">
          <el-radio-button value="append">合并(按 CVE 去重)</el-radio-button>
          <el-radio-button value="replace">整体替换</el-radio-button>
        </el-radio-group>
        <el-upload :auto-upload="false" :show-file-list="false" accept=".json,application/json" :on-change="onFile">
          <el-button size="small">选择 .json 文件</el-button>
        </el-upload>
      </div>
      <el-input v-model="impText" type="textarea" :rows="14" class="mono"
        placeholder='[{"cve":"CVE-2021-44228","name":"Log4Shell JNDI","action":"block","severity":"critical","match":"${jndi:"}]' />
      <template #footer>
        <el-button @click="impVisible = false">取消</el-button>
        <el-button type="primary" @click="applyImport">导入</el-button>
      </template>
    </el-dialog>

    <!-- 补丁格式说明 -->
    <el-dialog v-model="fmtVisible" title="CVE 虚拟补丁格式说明" width="720px" destroy-on-close>
      <div class="fmt">
        <p>顶层为 <b>JSON 数组</b>，每个元素是一个补丁对象。存储于 Redis <code>novawaf:cve_patch</code>，
          引擎按 <code>novawaf:cve_patch:version</code> 版本号 60s 轮询热加载。</p>
        <table class="fdoc">
          <tr><th>字段</th><th>必填</th><th>说明</th></tr>
          <tr><td class="mono">cve</td><td>是</td><td>漏洞编号，如 CVE-2024-12345 / CNVD-2024-12345；全局唯一，作为事件 ruleId</td></tr>
          <tr><td class="mono">match</td><td>必填</td><td>匹配串（≤512 字符）。引擎对请求文本做 URL 解码/小写等归一化后做子串匹配</td></tr>
          <tr><td class="mono">name</td><td>否</td><td>名称描述，事件展示用，缺省为 cve</td></tr>
          <tr><td class="mono">enabled</td><td>否</td><td>true/false，缺省 true；禁用项不下发检测</td></tr>
          <tr><td class="mono">action</td><td>否</td><td>block(默认，拦截) / log(仅记录) / pass(放行)</td></tr>
          <tr><td class="mono">severity</td><td>否</td><td>critical / high(缺省) / medium / low</td></tr>
          <tr><td class="mono">methods</td><td>否</td><td>HTTP 方法数组，如 ["GET","POST"]；缺省匹配所有方法</td></tr>
          <tr><td class="mono">uri</td><td>否</td><td>path 子串，收敛作用范围，如 "/api/login"</td></tr>
          <tr><td class="mono">scope</td><td>否</td><td>检测范围数组，子集 ["uri","args","headers","body"]；缺省全域</td></tr>
          <tr><td class="mono">headers</td><td>否</td><td>对象 {"头名":"包含子串"}，全部满足才命中，如 {"x-api-version":"v1"}</td></tr>
        </table>
        <p class="dim">匹配逻辑（字面量补丁）：所有补丁的 match 构建单棵 AC 自动机，各 scope 文本每请求仅扫描一次；
          命中后回验 methods/uri/headers/scope 条件，首条全满足的补丁胜出。</p>
        <p class="dim"><b>正则补丁（本页「正则补丁」标签页）</b>：同 JSON 结构，唯 match 为 ECMAScript 正则
          （icase，作用于归一化文本，引擎逐条 regex_search，首条全条件命中胜出）。
          护栏：总数 ≤100、单条 ≤256 字符、禁嵌套量词 (x+)+、body 仅扫前 16KB。
          存于 Redis <code>novawaf:regex_patch</code>，版本键 <code>novawaf:regex_patch:version</code>。</p>
        <pre class="ex">[{
  "cve": "CVE-2021-44228",
  "name": "Log4Shell JNDI",
  "enabled": true,
  "action": "block",
  "severity": "critical",
  "methods": ["GET", "POST"],
  "uri": "/api/login",
  "scope": ["uri", "args", "headers", "body"],
  "headers": {"x-api-version": "v1"},
  "match": "${jndi:"
}]</pre>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, ref, computed, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const list = ref([])
const version = ref(0)
const dirty = ref(false)
const kw = ref('')
const mode = ref('literal')
const isRegex = computed(() => mode.value === 'regex')

const editVisible = ref(false)
const editIdx = ref(-1)
const form = reactive({ cve: '', name: '', severity: 'high', action: 'block', match: '', methods: [], uri: '', scope: [], headersText: '', enabled: true })

const impVisible = ref(false)
const impText = ref('')
const impMode = ref('append')
const fmtVisible = ref(false)

const filtered = computed(() => {
  const k = kw.value.trim().toLowerCase()
  if (!k) return list.value
  return list.value.filter(p => [p.cve, p.name, p.match, p.uri]
    .some(v => v && String(v).toLowerCase().includes(k)))
})
const actionCount = computed(() => list.value.reduce((m, p) => { const a = p.action || 'block'; m[a] = (m[a] || 0) + 1; return m }, {}))
const disabledCount = computed(() => list.value.filter(p => p.enabled === false).length)
function sevType(s) { return { critical: 'danger', high: 'warning', medium: '', low: 'info' }[s || 'high'] ?? '' }

onMounted(load)
async function load() {
  const r = await (isRegex.value ? api.regexPatchGet() : api.cvePatchGet())
  list.value = Array.isArray(r.patches) ? r.patches : []
  version.value = r.version || 0
  dirty.value = false
}

function openEdit(row) {
  if (row) {
    editIdx.value = list.value.indexOf(row)
    Object.assign(form, {
      cve: row.cve || '', name: row.name || '', severity: row.severity || 'high',
      action: row.action || 'block', match: row.match || '',
      methods: Array.isArray(row.methods) ? [...row.methods] : [],
      uri: row.uri || '', scope: Array.isArray(row.scope) ? [...row.scope] : [],
      headersText: headersToText(row.headers), enabled: row.enabled !== false
    })
  } else {
    editIdx.value = -1
    Object.assign(form, { cve: '', name: '', severity: 'high', action: 'block', match: '', methods: [], uri: '', scope: [], headersText: '', enabled: true })
  }
  editVisible.value = true
}

function headersToText(h) {
  if (!h || typeof h !== 'object') return ''
  return Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\n')
}
function textToHeaders(t) {
  const out = {}
  for (const line of String(t || '').split('\n')) {
    const i = line.indexOf(':')
    if (i <= 0) continue
    const k = line.slice(0, i).trim().toLowerCase()
    const v = line.slice(i + 1).trim()
    if (k && v) out[k] = v
  }
  return Object.keys(out).length ? out : undefined
}

function validatePatch(p, existingIdx = -1) {
  if (!/^[A-Za-z]{2,6}-[0-9A-Za-z-]{2,30}$/.test(p.cve))
    return 'CVE 编号格式非法（应为 CVE-2024-12345 / CNVD-2024-12345 形式）'
  if (!p.match) return isRegex.value ? '正则表达式 match 不能为空' : '匹配串 match 不能为空'
  if (isRegex.value) {
    if (p.match.length > 256) return '正则超长(>256)'
    if (/\([^()]*[+*{][^()]*\)[+*{]/.test(p.match)) return '正则含嵌套量词 (x+)+ 形态，有 ReDoS 风险'
    try { new RegExp(p.match) } catch (e) { return '正则无法编译: ' + e.message }
  } else if (p.match.length > 512) return '匹配串超长(>512)'
  if (list.value.some((x, i) => i !== existingIdx && String(x.cve).toUpperCase() === p.cve.toUpperCase()))
    return 'CVE 编号重复: ' + p.cve
  return null
}

function applyEdit() {
  const p = {
    cve: form.cve.trim(), enabled: form.enabled, action: form.action,
    severity: form.severity, match: form.match
  }
  if (form.name.trim()) p.name = form.name.trim()
  if (form.methods.length) p.methods = [...form.methods]
  if (form.uri.trim()) p.uri = form.uri.trim()
  if (form.scope.length) p.scope = [...form.scope]
  const hc = textToHeaders(form.headersText)
  if (hc) p.headers = hc
  const err = validatePatch(p, editIdx.value)
  if (err) return ElMessage.error(err)
  if (editIdx.value >= 0) list.value.splice(editIdx.value, 1, p)
  else list.value.push(p)
  dirty.value = true
  editVisible.value = false
}

function del(i) { list.value.splice(i, 1); dirty.value = true }

function openImport() { impText.value = ''; impMode.value = 'append'; impVisible.value = true }
function onFile(f) {
  const r = new FileReader()
  r.onload = () => { impText.value = String(r.result || '') }
  r.readAsText(f.raw)
}
function applyImport() {
  let arr
  try { arr = JSON.parse(impText.value) } catch { return ElMessage.error('JSON 解析失败') }
  if (!Array.isArray(arr)) return ElMessage.error('顶层必须是 JSON 数组')
  if (impMode.value === 'replace') {
    list.value = arr
  } else {
    const seen = new Map(list.value.map((p, i) => [String(p.cve || '').toUpperCase(), i]))
    for (const p of arr) {
      const k = String(p.cve || '').toUpperCase()
      if (seen.has(k)) list.value.splice(seen.get(k), 1, p)
      else { seen.set(k, list.value.length); list.value.push(p) }
    }
  }
  dirty.value = true
  impVisible.value = false
  ElMessage.success(`已导入 ${arr.length} 条，点「下发保存」生效`)
}

function exportJson() {
  const blob = new Blob([JSON.stringify(list.value, null, 2)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = isRegex.value ? 'regex_patch.json' : 'cve_patch.json'
  a.click()
  URL.revokeObjectURL(a.href)
}

async function save() {
  const r = await (isRegex.value
    ? api.regexPatchSave(JSON.stringify(list.value))
    : api.cvePatchSave(JSON.stringify(list.value)))
  list.value = Array.isArray(r.patches) ? r.patches : list.value
  version.value = r.version || version.value
  dirty.value = false
  ElMessage.success('已下发并触发热加载，引擎 60s 内生效')
}
async function reload() {
  await (isRegex.value ? api.regexPatchReload() : api.cvePatchReload())
  ElMessage.success('已 bump 版本号，引擎将热加载')
}
</script>

<style scoped>
.p { padding: 16px; }
.mtabs { margin-bottom: 4px; }
.regex-tip { font-size: 12px; color: #e6a23c; background: rgba(230, 162, 60, .08); border: 1px solid rgba(230, 162, 60, .3); border-radius: 4px; padding: 6px 10px; margin-bottom: 10px; }
.bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px; }
.ops { display: flex; gap: 8px; flex-wrap: wrap; }
.stats { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 10px; }
.kw { width: 280px; margin-left: auto; }
.fcount { font-size: 12px; opacity: .75; }
.mono { font-family: monospace; font-size: 12px; }
.cve { color: #ff6b6b; font-weight: 600; }
.hint { margin-top: 10px; font-size: 12px; opacity: .7; }
.dim { font-size: 12px; opacity: .6; }
.w180 { width: 180px; }
.wfull { width: 100%; }
.impbar { display: flex; gap: 12px; align-items: center; margin-bottom: 10px; }
.fmt p { font-size: 13px; line-height: 1.8; }
.fdoc { width: 100%; border-collapse: collapse; font-size: 12px; margin: 8px 0; }
.fdoc th, .fdoc td { border: 1px solid var(--line, #2a3a4a); padding: 5px 8px; text-align: left; }
.ex { background: rgba(0, 0, 0, .3); padding: 10px; border-radius: 4px; font-size: 12px; overflow: auto; }
.tbl { width: 100%; }
</style>
