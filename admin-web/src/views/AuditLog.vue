<template>
  <div class="mecha-panel p">
    <el-table :data="rows" border size="small" height="560">
      <el-table-column prop="id" label="#" width="60" />
      <el-table-column prop="username" label="用户" width="120" />
      <el-table-column prop="module" label="模块" width="100" />
      <el-table-column prop="operation" label="操作" />
      <el-table-column prop="ip" label="IP" width="140" />
      <el-table-column label="结果" width="80"><template #default="{row}"><el-tag :type="row.status===1?'success':'danger'">{{ row.status===1?'成功':'失败' }}</el-tag></template></el-table-column>
      <el-table-column prop="createTime" label="时间" width="170" />
    </el-table>
    <el-pagination class="pg" background layout="total,prev,pager,next" :total="total" :page-size="size" :current-page="page" @current-change="(p)=>{page=p;load()}" />
  </div>
</template>
<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
const rows=ref([]),total=ref(0),page=ref(1),size=20
async function load(){const d=await api.operLogs({page:page.value,size});rows.value=d.rows||[];total.value=d.total||0}
onMounted(load)
</script>
<style scoped>.p{padding:16px}.pg{margin-top:12px}</style>
