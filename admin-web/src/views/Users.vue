<template>
  <div class="mecha-panel p">
    <div class="bar"><el-button type="primary" @click="openAdd">+ 新增用户</el-button></div>
    <DataTable :data="rows" :columns="columns" :loading="loading" height="calc(100vh - 230px)">
      <template #cell-status="{ row }">
        <el-tag :type="row.status === 1 ? 'success' : 'danger'" size="small">
          {{ row.status === 1 ? '启用' : '禁用' }}
        </el-tag>
      </template>
      <template #cell-action="{ row }">
        <el-button size="small" @click="resetPwd(row)">重置密码</el-button>
        <el-button size="small" type="danger" @click="del(row)">删除</el-button>
      </template>
    </DataTable>
    <el-dialog v-model="dlg" title="新增用户" width="420" append-to-body>
      <el-form :model="f" label-width="80">
        <el-form-item label="账号"><el-input v-model="f.username" /></el-form-item>
        <el-form-item label="密码"><el-input v-model="f.password" show-password /></el-form-item>
        <el-form-item label="昵称"><el-input v-model="f.nickname" /></el-form-item>
      </el-form>
      <template #footer><el-button type="primary" @click="add">确定</el-button></template>
    </el-dialog>
  </div>
</template>
<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import DataTable from '../components/DataTable.vue'
const rows = ref([]), loading = ref(false), dlg = ref(false)
const f = reactive({ username: '', password: '', nickname: '' })
const columns = [
  { prop: 'id', label: 'ID', width: 70 },
  { prop: 'username', label: '账号', minWidth: 140 },
  { prop: 'nickname', label: '昵称', minWidth: 140 },
  { prop: 'status', label: '状态', width: 80, slot: 'status' },
  { label: '操作', width: 200, fixed: 'right', slot: 'action', noSearch: true }
]
async function load() {
  loading.value = true
  try { const d = await api.users({ page: 1, size: 2000 }); rows.value = d.rows || [] }
  finally { loading.value = false }
}
function openAdd() { Object.assign(f, { username: '', password: '', nickname: '' }); dlg.value = true }
async function add() { await api.addUser(f); ElMessage.success('已创建'); dlg.value = false; load() }
async function del(r) { await ElMessageBox.confirm('确认删除 ' + r.username + '?'); await api.delUser(r.id); load() }
async function resetPwd(r) { const { value } = await ElMessageBox.prompt('输入新密码(≥6位)', '重置 ' + r.username); await api.resetPwd(r.id, value); ElMessage.success('已重置') }
onMounted(load)
</script>
<style scoped>.p{padding:14px;height:100%;box-sizing:border-box;display:flex;flex-direction:column}.bar{margin-bottom:12px}</style>
