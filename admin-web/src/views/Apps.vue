<template>
  <div class="apps">
    <!-- 顶栏 -->
    <div class="toolbar mecha-panel">
      <div class="left">
        <span class="hud-title">共 {{ list.length }} 个应用</span>
        <el-input v-model="kw" placeholder="应用 / 域名" clearable class="search" :prefix-icon="Search" />
      </div>
      <div class="right">
        <el-button type="primary" plain @click="showAdd = true"><el-icon><Plus /></el-icon>添加应用</el-button>
      </div>
    </div>

    <!-- 卡片网格 -->
    <div class="grid">
      <div v-for="a in filtered" :key="a.id" class="mecha-panel app-card">
        <div class="card-head">
          <div class="app-id">
            <el-icon class="a-ic"><Cpu /></el-icon>
            <span class="a-name">{{ a.name || ('应用-' + a.id) }}</span>
          </div>
          <div class="card-ops">
            <span class="detail" @click="openDetail(a)">详情</span>
            <el-icon class="edit" title="修改" @click="openEdit(a)"><Edit /></el-icon>
            <el-icon class="del" title="删除" @click="remove(a)"><Delete /></el-icon>
          </div>
        </div>

        <div class="badge-row">
          <el-tag size="small" :type="modeType(a.mode)" effect="dark" round class="mode-tag" @click="openMode(a)">{{ a.mode || '防护' }}模式</el-tag>
        </div>

        <div class="meta">
          <div class="meta-line"><span class="k">域名</span><span class="v">{{ a.host || '-' }}</span></div>
          <div class="meta-line"><span class="k">端口</span><span class="v">🔒 {{ a.upstreamPort }} / HTTP/HTTPS</span></div>
        </div>

        <div class="today">
          <div class="t-item"><span class="t-num cyan">{{ a.todayReq }}</span><span class="t-lbl">今日请求</span></div>
          <div class="t-item"><span class="t-num red">{{ a.todayBlock }}</span><span class="t-lbl">今日拦截</span></div>
          <div class="t-item"><span class="t-num green">{{ a.qps }}</span><span class="t-lbl">QPS</span></div>
        </div>

        <div class="feats">
          <el-tag v-for="f in a.features" :key="f" size="small" effect="plain" class="ft">{{ f }}</el-tag>
          <span v-if="!a.statsEnabled" class="off-tag">统计未开启</span>
        </div>
      </div>
      <div v-if="!filtered.length" class="empty mecha-panel">暂无匹配的防护应用</div>
    </div>

    <!-- 详情弹窗 -->
    <el-dialog v-model="detailShow" :title="'应用详情 · ' + (cur.name || cur.id)" width="460px" class="mecha-dialog" append-to-body>
      <el-descriptions :column="1" border>
        <el-descriptions-item label="应用ID">{{ cur.id }}</el-descriptions-item>
        <el-descriptions-item label="应用名称">{{ cur.name }}</el-descriptions-item>
        <el-descriptions-item label="防护域名">{{ cur.host }}</el-descriptions-item>
        <el-descriptions-item label="上游地址">{{ cur.upstreamHost }}:{{ cur.upstreamPort }}</el-descriptions-item>
        <el-descriptions-item label="运行模式">{{ cur.mode }}模式</el-descriptions-item>
        <el-descriptions-item label="统计采集">{{ cur.statsEnabled ? '已开启' : '未开启' }}</el-descriptions-item>
        <el-descriptions-item label="今日请求">{{ cur.todayReq }}</el-descriptions-item>
        <el-descriptions-item label="今日拦截">{{ cur.todayBlock }}</el-descriptions-item>
        <el-descriptions-item label="实时 QPS">{{ cur.qps }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <!-- 添加/修改应用 -->
    <el-dialog v-model="showAdd" :title="editingId ? '修改防护应用' : '添加防护应用'" width="460px" append-to-body>
      <el-form :model="form" label-width="90px" size="default">
        <el-form-item label="应用名称">
          <el-input v-model="form.name" placeholder="如：NAC 认证网关" />
        </el-form-item>
        <el-form-item label="防护域名" required>
          <el-input v-model="form.host" placeholder="如：nac 或 nac.example.com（匹配 Host 头）" />
        </el-form-item>
        <el-form-item label="上游地址" required>
          <el-input v-model="form.upstreamHost" placeholder="如：127.0.0.1" />
        </el-form-item>
        <el-form-item label="上游端口" required>
          <el-input-number v-model="form.upstreamPort" :min="1" :max="65535" controls-position="right" />
        </el-form-item>
        <el-form-item label="流量统计">
          <el-switch v-model="form.statsEnabled" active-text="开启" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAdd = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="submit">{{ editingId ? '保存修改' : '确定添加' }}</el-button>
      </template>
      <div class="tip">保存后写入引擎配置并触发热加载（约 60s 内生效），无需重启引擎。</div>
    </el-dialog>

    <!-- 运行模式切换 -->
    <el-dialog v-model="modeShow" :title="'运行模式 · ' + (modeApp.name || modeApp.id)" width="560px" class="mecha-dialog" append-to-body>
      <div class="mode-cards">
        <div v-for="m in modes" :key="m.val" class="mode-card" :class="{ active: selMode === m.val, [m.val]: true }" @click="selMode = m.val">
          <div class="mc-title">{{ m.label }}</div>
          <div class="mc-desc">{{ m.desc }}</div>
        </div>
      </div>
      <template #footer>
        <el-button @click="modeShow = false">取消</el-button>
        <el-button type="primary" :loading="modeSaving" @click="saveMode">保存</el-button>
      </template>
      <div class="tip">切换后约 60s 内热加载生效；维护模式会向所有访客展示维护页。</div>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, onBeforeUnmount, reactive, ref } from 'vue'
import { Search, Plus, Cpu, Delete, Edit } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'

const list = ref([])
const kw = ref('')
const detailShow = ref(false)
const showAdd = ref(false)
const saving = ref(false)
const cur = ref({})
const editingId = ref(null)
const form = reactive({ name: '', host: '', upstreamHost: '', upstreamPort: 80, statsEnabled: true })

const modeShow = ref(false)
const modeSaving = ref(false)
const modeApp = ref({})
const selMode = ref('protect')
const modes = [
  { val: 'protect', label: '防护模式', desc: '发现攻击后将自动拦截，并记录攻击事件' },
  { val: 'observe', label: '观察模式', desc: '发现攻击后仅记录攻击事件，不拦截' },
  { val: 'maintenance', label: '维护模式', desc: '展示维护页面，任何人都将无法访问您的应用' }
]
const LABEL2VAL = { '防护': 'protect', '观察': 'observe', '维护': 'maintenance' }
function modeType(m) { return m === '观察' ? 'warning' : m === '维护' ? 'danger' : 'success' }
function openMode(a) { modeApp.value = a; selMode.value = LABEL2VAL[a.mode] || 'protect'; modeShow.value = true }
async function saveMode() {
  modeSaving.value = true
  try {
    await api.setAppMode(modeApp.value.id, selMode.value)
    ElMessage.success('模式已切换，引擎热加载中（约 60s 生效）')
    modeShow.value = false
    await load()
  } catch (e) { /* 拦截器已提示 */ } finally { modeSaving.value = false }
}

const filtered = computed(() => {
  const k = kw.value.trim().toLowerCase()
  if (!k) return list.value
  return list.value.filter(a => String(a.name || '').toLowerCase().includes(k) || String(a.host || '').toLowerCase().includes(k))
})
function openDetail(a) { cur.value = a; detailShow.value = true }
function openEdit(a) {
  editingId.value = a.id
  Object.assign(form, { name: a.name || '', host: a.host || '', upstreamHost: a.upstreamHost || '', upstreamPort: a.upstreamPort || 80, statsEnabled: !!a.statsEnabled })
  showAdd.value = true
}

async function submit() {
  if (!form.host.trim() || !form.upstreamHost.trim()) { ElMessage.warning('域名和上游地址必填'); return }
  saving.value = true
  try {
    if (editingId.value) {
      await api.updateApp(editingId.value, { ...form })
      ElMessage.success('已修改，引擎热加载中（约 60s 生效）')
    } else {
      await api.addApp({ ...form })
      ElMessage.success('已添加，引擎热加载中（约 60s 生效）')
    }
    showAdd.value = false
    editingId.value = null
    Object.assign(form, { name: '', host: '', upstreamHost: '', upstreamPort: 80, statsEnabled: true })
    await load()
  } catch (e) { /* 拦截器已提示 */ } finally { saving.value = false }
}
async function remove(a) {
  try {
    await ElMessageBox.confirm(`确认删除应用「${a.name}」？将停止对该域名的防护。`, '删除确认', { type: 'warning' })
    await api.delApp(a.id)
    ElMessage.success('已删除')
    await load()
  } catch (e) { /* 取消或失败 */ }
}

async function load() {
  try { list.value = await api.wafApps() } catch (e) { list.value = [] }
}
let timer = null
onMounted(() => { load(); timer = setInterval(load, 15000) })
onBeforeUnmount(() => clearInterval(timer))
</script>

<style scoped>
.apps { display: flex; flex-direction: column; gap: 14px; }
.toolbar { display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; }
.toolbar .left { display: flex; align-items: center; gap: 16px; }
.search { width: 260px; }
.grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
.app-card { padding: 16px; display: flex; flex-direction: column; gap: 10px; }
.card-head { display: flex; align-items: center; justify-content: space-between; }
.card-ops { display: flex; align-items: center; gap: 12px; }
.del { color: var(--muted); cursor: pointer; font-size: 15px; }
.del:hover { color: #ff4d6d; }
.edit { color: var(--muted); cursor: pointer; font-size: 15px; }
.edit:hover { color: #00e5ff; }
.tip { font-size: 11px; color: var(--muted); margin-top: 4px; }
.app-id { display: flex; align-items: center; gap: 8px; }
.a-ic { color: #00e5ff; font-size: 18px; }
.a-name { font-size: 16px; font-weight: 700; color: #cfe9ff; }
.detail { color: #9fc4e8; font-size: 12px; cursor: pointer; }
.detail:hover { color: #00e5ff; }
.badge-row { display: flex; gap: 8px; }
.mode-tag { cursor: pointer; transition: transform .15s; }
.mode-tag:hover { transform: scale(1.05); }
.mode-cards { display: flex; gap: 14px; }
.mode-card { flex: 1; padding: 18px 14px; border-radius: 10px; cursor: pointer; border: 1px solid rgba(255,255,255,0.08); background: rgba(255,255,255,0.02); transition: all .2s; }
.mode-card .mc-title { font-size: 16px; font-weight: 700; margin-bottom: 8px; }
.mode-card .mc-desc { font-size: 12px; color: var(--muted); line-height: 1.6; }
.mode-card.protect .mc-title { color: #00ff9d; }
.mode-card.observe .mc-title { color: #ffb020; }
.mode-card.maintenance .mc-title { color: #ff4d6d; }
.mode-card.active.protect { border-color: #00ff9d; box-shadow: 0 0 12px rgba(0,255,157,0.35); }
.mode-card.active.observe { border-color: #ffb020; box-shadow: 0 0 12px rgba(255,176,32,0.35); }
.mode-card.active.maintenance { border-color: #ff4d6d; box-shadow: 0 0 12px rgba(255,77,109,0.35); }
.mode-card:hover { transform: translateY(-2px); }
.meta { display: flex; flex-direction: column; gap: 4px; font-size: 12px; }
.meta-line { display: flex; gap: 10px; }
.meta-line .k { color: var(--muted); width: 36px; }
.meta-line .v { color: #cfe9ff; }
.today { display: flex; gap: 18px; padding: 8px 0; border-top: 1px dashed rgba(0,229,255,0.12); border-bottom: 1px dashed rgba(0,229,255,0.12); }
.t-item { display: flex; flex-direction: column; gap: 2px; }
.t-num { font-size: 20px; font-weight: 700; font-family: 'Orbitron', monospace; }
.t-num.cyan { color: #00e5ff; text-shadow: 0 0 8px #00e5ff; }
.t-num.red { color: #ff4d6d; text-shadow: 0 0 8px #ff4d6d; }
.t-num.green { color: #00ff9d; text-shadow: 0 0 8px #00ff9d; }
.t-lbl { font-size: 11px; color: var(--muted); }
.feats { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.ft { background: rgba(0,229,255,0.08) !important; border-color: rgba(0,229,255,0.3) !important; color: #9fc4e8 !important; }
.off-tag { font-size: 11px; color: #ffb020; }
.empty { padding: 40px; text-align: center; color: var(--muted); }
</style>
