<template>
  <div class="mecha-panel p">
    <div class="bar">
      <span class="hud-title">// 当前规则集 (引擎 Redis: novawaf:rules)</span>
      <div>
        <el-button type="success" @click="save">下发保存</el-button>
        <el-button @click="reload">热加载</el-button>
      </div>
    </div>
    <el-input v-model="json" type="textarea" :rows="22" class="mono" placeholder='[{"id":1,"pattern":...}]' />
  </div>
</template>
<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
const json = ref('')
onMounted(async () => { const r = await api.wafRules(); json.value = JSON.stringify(r, null, 2) })
async function save() { try { JSON.parse(json.value) } catch { return ElMessage.error('JSON 格式错误') }; await api.saveRules(json.value); ElMessage.success('已下发并触发热加载') }
async function reload() { await api.reloadRules(); ElMessage.success('已 bump 版本号,引擎将热加载') }
</script>
<style scoped>
.p { padding: 16px; }
.bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.mono { font-family: monospace; font-size: 12px; }
</style>
