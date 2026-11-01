<template>
  <div class="settings">
    <!-- 全局防护模式（WAF 指纹三态） -->
    <el-card class="panel mecha-panel" shadow="never">
      <template #header>
        <div class="card-head">
          <span class="t">全局防护模式</span>
          <el-tag :type="tagType" effect="dark">{{ modeLabel }}</el-tag>
        </div>
      </template>

      <el-radio-group v-model="mode" class="modes">
        <div class="mode-item">
          <el-radio value="hidden" size="large">
            <span class="m-name">开启 · 隐藏指纹</span>
            <el-tag size="small" type="success" effect="plain" class="rec">推荐 · 默认</el-tag>
          </el-radio>
          <div class="m-desc">防护全开，但拦截页、响应头、Cookie 均不暴露 WAF 品牌（对外表现为普通 nginx），攻击者无法识别防护产品。</div>
        </div>
        <div class="mode-item">
          <el-radio value="public" size="large"><span class="m-name">开启 · 公开指纹</span></el-radio>
          <div class="m-desc">防护全开，拦截页与响应头（Server / X-WAF）公开 NovaWAF 品牌，可被 wafw00f 等工具识别，起威慑作用。</div>
        </div>
        <div class="mode-item">
          <el-radio value="off" size="large"><span class="m-name">关闭防护</span></el-radio>
          <div class="m-desc">全站降级为旁路观察：攻击仅记录，不拦截、不封禁。仅用于应急排障，慎用。</div>
        </div>
      </el-radio-group>

      <div class="ops">
        <el-button type="primary" :loading="saving" :disabled="mode === cur" @click="save">保存并生效</el-button>
        <span class="hint">引擎热路径读取，保存后 2 秒内全站生效，无需重启</span>
      </div>

      <el-alert class="why" type="info" :closable="false" show-icon>
        <template #title>为什么推荐「隐藏指纹」？</template>
        <ul class="why-list">
          <li><b>增加侦察成本</b>：攻击者无法用 wafw00f 等工具识别防护产品，无法针对性选择绕过手法</li>
          <li><b>混淆攻击面</b>：响应特征与原生 nginx 完全一致，攻击者难以判断目标是否有 WAF、拦截来自 WAF 还是应用本身</li>
          <li><b>防指纹绕过</b>：公开品牌等于告知规则库类型，隐藏后攻击者只能盲测，已知绕过手法全部失效</li>
          <li><b>防护不打折</b>：隐藏只是"隐身"——检测、拦截页、追踪 ID、CC 限流、自动封禁全部照常工作</li>
        </ul>
      </el-alert>
    </el-card>

    <!-- 检测规则版本管理 -->
    <el-card class="panel mecha-panel" shadow="never">
      <template #header>
        <div class="card-head">
          <span class="t">检测规则版本</span>
          <el-button size="small" @click="load">刷新</el-button>
        </div>
      </template>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="当前版本">v{{ rv.version }}</el-descriptions-item>
        <el-descriptions-item label="规则条数">{{ rv.count }}</el-descriptions-item>
        <el-descriptions-item label="最近更新">{{ rv.updatedAt || '—' }}</el-descriptions-item>
        <el-descriptions-item label="规则集">{{ rv.source }}</el-descriptions-item>
      </el-descriptions>
      <div class="rv-tip">
        规则在「规则管理」保存后自动递增版本号；引擎按版本号热加载（60s 轮询），无需重启。
        规则集等效覆盖 OWASP CRS 核心类别：SQLi / XSS / RCE / 路径穿越 / 反序列化 / XXE / SSRF / 扫描器指纹 / 敏感文件探测，另含国产组件与国际通用 CVE 定向规则。
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'

const mode = ref('hidden')   // 编辑中的选择
const cur = ref('hidden')    // 服务端当前生效值
const saving = ref(false)
const rv = ref({ version: 0, count: 0, updatedAt: '', source: '' })

const LABELS = { hidden: '开启 · 隐藏指纹', public: '开启 · 公开指纹', off: '关闭防护' }
const modeLabel = computed(() => LABELS[cur.value] || cur.value)
const tagType = computed(() => ({ hidden: 'success', public: 'warning', off: 'danger' }[cur.value] || 'info'))

async function load() {
  const m = await api.settingsWafModeGet()
  mode.value = m.mode || 'hidden'
  cur.value = mode.value
  rv.value = await api.settingsRulesVersion()
}

async function save() {
  const v = mode.value
  try {
    await ElMessageBox.confirm(
      v === 'off'
        ? '关闭后全站仅观察记录、不拦截不封禁，确认关闭防护？'
        : `确认切换到「${LABELS[v]}」模式？保存后 2 秒内全站生效。`,
      '变更全局防护模式',
      { type: 'warning', confirmButtonText: '确认生效', cancelButtonText: '取消' })
  } catch { return }
  saving.value = true
  try {
    const msg = await api.settingsWafModeSave(v)
    ElMessage.success(msg)
    cur.value = v
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.settings { display: flex; flex-direction: column; gap: 14px; }
.panel { background: var(--panel); border: 1px solid var(--line); }
.card-head { display: flex; align-items: center; justify-content: space-between; }
.t { font-size: 15px; font-weight: 600; color: var(--cyan); letter-spacing: 1px; }
.modes { display: flex; flex-direction: column; gap: 12px; width: 100%; }
.mode-item { padding: 10px 14px; border: 1px solid var(--line); border-radius: 6px; }
.m-name { font-weight: 600; color: #d6ecff; }
.rec { margin-left: 8px; }
.m-desc { margin: 4px 0 0 26px; font-size: 12px; color: var(--muted); line-height: 1.6; }
.ops { margin-top: 14px; display: flex; align-items: center; gap: 12px; }
.hint { font-size: 12px; color: var(--muted); }
.why { margin-top: 16px; background: rgba(0, 229, 255, .04); border: 1px solid var(--line); }
.why-list { margin: 6px 0 0; padding-left: 18px; line-height: 1.9; font-size: 13px; }
.why-list b { color: var(--cyan); }
.rv-tip { margin-top: 12px; font-size: 12px; color: var(--muted); line-height: 1.8; }
</style>
