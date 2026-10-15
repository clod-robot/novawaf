<template>
  <div class="mecha-panel p">
    <div class="bar"><el-button type="primary" @click="openAdd">+ 新增用户</el-button></div>
    <el-table :data="rows" border size="small">
      <el-table-column prop="id" label="ID" width="60" />
      <el-table-column prop="username" label="账号" />
      <el-table-column prop="nickname" label="昵称" />
      <el-table-column label="状态" width="90"><template #default="{row}"><el-tag :type="row.status===1?'success':'danger'">{{ row.status===1?'启用':'禁用' }}</el-tag></template></el-table-column>
      <el-table-column label="操作" width="200">
        <template #default="{row}">
          <el-button size="small" @click="resetPwd(row)">重置密码</el-button>
          <el-button size="small" type="danger" @click="del(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-pagination class="pg" background layout="total,prev,pager,next" :total="total" :page-size="size" :current-page="page" @current-change="(p)=>{page=p;load()}" />
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
const rows=ref([]),total=ref(0),page=ref(1),size=10,dlg=ref(false)
const f=reactive({username:'',password:'',nickname:''})
async function load(){const d=await api.users({page:page.value,size});rows.value=d.rows||[];total.value=d.total||0}
function openAdd(){Object.assign(f,{username:'',password:'',nickname:''});dlg.value=true}
async function add(){await api.addUser(f);ElMessage.success('已创建');dlg.value=false;load()}
async function del(r){await ElMessageBox.confirm('确认删除 '+r.username+'?');await api.delUser(r.id);load()}
async function resetPwd(r){const {value}=await ElMessageBox.prompt('输入新密码(≥6位)','重置 '+r.username);await api.resetPwd(r.id,value);ElMessage.success('已重置')}
onMounted(load)
</script>
<style scoped>.p{padding:16px}.bar{margin-bottom:12px}.pg{margin-top:12px}</style>
