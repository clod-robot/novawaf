<template>
  <div class="mecha-panel p">
    <div class="hud-title">// 威胁情报 IOC (引擎 Redis: novawaf:ioc)</div>
    <el-descriptions :column="3" border size="small" class="meta">
      <el-descriptions-item v-for="(v,k) in meta" :key="k" :label="k">{{ typeof v==='object'?JSON.stringify(v):v }}</el-descriptions-item>
    </el-descriptions>
    <el-table :data="rows" border size="small" height="460">
      <el-table-column type="index" width="50" />
      <el-table-column label="IOC 条目"><template #default="{row}">{{ pretty(row) }}</template></el-table-column>
    </el-table>
  </div>
</template>
<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
const rows = ref([]), meta = ref({})
function pretty(r){ try{return JSON.stringify(r)}catch{return String(r)} }
onMounted(async () => { const d = await api.wafIoc(); const ioc = d.ioc; rows.value = Array.isArray(ioc)?ioc.slice(0,500):[]; meta.value = d.meta||{} })
</script>
<style scoped>
.p { padding: 16px; }
.meta { margin: 12px 0; }
</style>
