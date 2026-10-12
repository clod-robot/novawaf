<template>
  <div class="mecha-panel p">
    <div class="bar">
      <span class="hud-title">// 规则管理 · 自定义规则集 (引擎热加载, Redis: novawaf:rules)</span>
      <div>
        <el-button size="small" @click="showJson = !showJson">{{ showJson ? '表格视图' : 'JSON 编辑' }}</el-button>
        <el-button type="success" size="small" @click="save">下发保存</el-button>
        <el-button size="small" @click="reload">热加载</el-button>
      </div>
    </div>

    <!-- 表格视图 -->
    <el-table v-if="!showJson" :data="rows" size="small" stripe height="520" border>
      <el-table-column prop="id" label="ID" width="60" />
      <el-table-column prop="name" label="规则名称" min-width="170" />
      <el-table-column prop="category" label="类型" width="100">
        <template #default="{ row }">
          <el-tag size="small" :type="tagType(row.category)">{{ row.category }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="pattern" label="匹配特征" min-width="200">
        <template #default="{ row }"><code class="mono">{{ row.pattern }}</code></template>
      </el-table-column>
      <el-table-column prop="action" label="动作" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="row.action === 'block' ? 'danger' : row.action === 'pass' ? 'success' : 'info'">
            {{ row.action }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="启用" width="70">
        <template #default="{ row }">
          <el-tag size="small" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '是' : '否' }}</el-tag>
        </template>
      </el-table-column>
    </el-table>
    <div v-if="!showJson" class="hint">共 {{ rows.length }} 条自定义规则。点「JSON 编辑」可新增/修改后下发，引擎将在 60s 内热加载生效。</div>

    <!-- JSON 编辑视图 -->
    <el-input v-else v-model="json" type="textarea" :rows="24" class="mono"
      placeholder='[{"id":1,"name":"...","pattern":"...","category":"SQLi","action":"block","enabled":true}]' />
  </div>
</template>
<script setup>
import { onMounted, ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
const json = ref('')
const showJson = ref(false)
const rows = computed(() => {
  try { const v = JSON.parse(json.value); return Array.isArray(v) ? v : [] } catch { return [] }
})
function tagType(cat) {
  return { SQLi: 'danger', XSS: 'warning', RCE: 'danger', Traversal: 'warning', XXE: 'danger',
           Scanner: 'info', InfoLeak: '' }[cat] || ''
}
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
.mono { font-family: monospace; font-size: 12px; }
.hint { margin-top: 10px; font-size: 12px; opacity: .7; }
</style>
