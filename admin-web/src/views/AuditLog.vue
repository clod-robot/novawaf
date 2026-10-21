<template>
  <div class="mecha-panel p">
    <DataTable :data="rows" :columns="columns" :loading="loading">
      <template #cell-status="{ row }">
        <el-tag :type="row.status === 1 ? 'success' : 'danger'" size="small">
          {{ row.status === 1 ? '成功' : '失败' }}
        </el-tag>
      </template>
    </DataTable>
  </div>
</template>
<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import DataTable from '../components/DataTable.vue'
const rows = ref([]), loading = ref(false)
const columns = [
  { prop: 'id', label: '#', width: 70 },
  { prop: 'username', label: '用户', width: 120 },
  { prop: 'module', label: '模块', width: 120 },
  { prop: 'operation', label: '操作', minWidth: 200 },
  { prop: 'ip', label: 'IP', width: 140 },
  { prop: 'status', label: '结果', width: 80, slot: 'status' },
  { prop: 'createTime', label: '时间', width: 170 }
]
async function load() {
  loading.value = true
  try { const d = await api.operLogs({ page: 1, size: 5000 }); rows.value = d.rows || [] }
  finally { loading.value = false }
}
onMounted(load)
</script>
<style scoped>.p{padding:14px;height:100%;box-sizing:border-box;display:flex;flex-direction:column}</style>
