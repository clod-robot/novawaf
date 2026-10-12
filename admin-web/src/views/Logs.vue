<template>
  <div class="mecha-panel p">
    <div class="bar">
      <el-input v-model="kw" placeholder="搜索日志..." style="width:260px" clearable @keyup.enter="load" />
      <el-button type="primary" @click="load">检索</el-button>
    </div>
    <el-table :data="rows" border size="small" height="520">
      <el-table-column type="index" label="#" width="50" />
      <el-table-column label="日志内容">
        <template #default="{ row }"><span class="mono">{{ pretty(row) }}</span></template>
      </el-table-column>
    </el-table>
    <el-pagination class="pg" background layout="total, prev, pager, next" :total="total" :page-size="size" :current-page="page" @current-change="(p)=>{page=p;load()}" />
  </div>
</template>
<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
const rows = ref([]), total = ref(0), page = ref(1), size = 20, kw = ref('')
function pretty(r) { try { return JSON.stringify(r) } catch { return String(r) } }
async function load() {
  const d = await api.wafLogs({ page: page.value, size, keyword: kw.value || undefined })
  rows.value = d.rows || []; total.value = d.total || 0
}
onMounted(load)
</script>
<style scoped>
.p { padding: 16px; }
.bar { display: flex; gap: 10px; margin-bottom: 12px; }
.pg { margin-top: 12px; }
.mono { font-family: monospace; font-size: 12px; color: #9fc4e8; }
</style>
