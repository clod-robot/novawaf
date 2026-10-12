<template>
  <div class="dash">
    <!-- 顶部指标卡 -->
    <div class="kpis">
      <div v-for="k in kpis" :key="k.label" class="mecha-panel kpi">
        <div class="kpi-top"><span class="hud-title">{{ k.label }}</span><el-icon class="ic"><component :is="k.icon" /></el-icon></div>
        <div class="kpi-num" :style="{ color: k.color }">{{ k.val }}</div>
      </div>
    </div>

    <!-- 错误率 / QPS 行 -->
    <div class="row2">
      <div class="mecha-panel mini" v-for="e in errCards" :key="e.label">
        <div class="hud-title">{{ e.label }}</div>
        <div class="mini-big" :style="{color:e.color}">{{ e.val }}</div>
        <div class="mini-sub">{{ e.sub }}</div>
      </div>
      <div class="mecha-panel mini qps">
        <div class="hud-title">实时 QPS</div>
        <div class="mini-big glow-cyan">{{ d.traffic?.qps ?? 0 }}</div>
        <div ref="qpsEl" class="qps-chart"></div>
      </div>
    </div>

    <!-- 主区 -->
    <div class="main-grid">
      <div class="mecha-panel span2">
        <div class="hud-title">攻击拦截趋势 · TREND</div>
        <div ref="trendEl" class="chart big"></div>
      </div>
      <div class="mecha-panel">
        <div class="hud-title">攻击类型分布</div>
        <div ref="catEl" class="chart"></div>
      </div>

      <div class="mecha-panel">
        <div class="hud-title">攻击源 IP · TOP</div>
        <div class="rank">
          <div v-for="(r,i) in d.topIps" :key="r.name" class="rank-row">
            <span class="rk" :class="'rk'+(i+1)">{{ i+1 }}</span>
            <span class="rname">{{ r.name }}</span>
            <div class="rbar"><div class="rfill" :style="{width: pct(r.value, maxIp)+'%'}"></div></div>
            <span class="rval">{{ r.value }}</span>
          </div>
          <div v-if="!d.topIps || !d.topIps.length" class="empty">暂无数据</div>
        </div>
      </div>

      <div class="mecha-panel span2 live">
        <div class="hud-title">实时拦截事件 · LIVE</div>
        <div class="feed">
          <div v-for="(e,i) in d.events" :key="i" class="feed-row">
            <el-tag size="small" :type="tagType(e.action)" effect="dark">{{ e.action || 'block' }}</el-tag>
            <span class="fcat">{{ e.category }}</span>
            <span class="fip">{{ e.ip }}</span>
            <span class="frule">{{ e.ruleId }}</span>
            <span class="fmatch">{{ short(e.matched) }}</span>
            <span class="ftime">{{ fmt(e.ts) }}</span>
          </div>
          <div v-if="!d.events || !d.events.length" class="empty">暂无事件</div>
        </div>
      </div>

      <div class="mecha-panel">
        <div class="hud-title">拦截动作分布</div>
        <div ref="actEl" class="chart"></div>
      </div>
      <div class="mecha-panel">
        <div class="hud-title">规则命中分布</div>
        <div class="rank">
          <div v-for="r in ruleList" :key="r.name" class="rank-row">
            <span class="rname">{{ r.name }}</span>
            <div class="rbar"><div class="rfill rule" :style="{width: pct(r.value, maxRule)+'%'}"></div></div>
            <span class="rval">{{ r.value }}</span>
          </div>
          <div v-if="!ruleList.length" class="empty">暂无数据</div>
        </div>
      </div>
    </div>

    <!-- 访问分析：客户端 / 状态 / 地理 / 来源 -->
    <div class="main-grid">
      <div class="mecha-panel">
        <div class="hud-title">响应状态码分布</div>
        <div ref="statusEl" class="chart"></div>
      </div>
      <div class="mecha-panel">
        <div class="hud-title">客户端 · 浏览器</div>
        <div ref="browserEl" class="chart"></div>
      </div>
      <div class="mecha-panel">
        <div class="hud-title">操作系统分布</div>
        <div ref="osEl" class="chart"></div>
      </div>

      <div class="mecha-panel">
        <div class="hud-title">地理位置分布</div>
        <div class="rank">
          <div v-for="(r,i) in d.byCountry" :key="r.name" class="rank-row">
            <span class="rname wide">{{ r.name }}</span>
            <div class="rbar"><div class="rfill geo" :style="{width: pct(r.value, maxCountry)+'%'}"></div></div>
            <span class="rval">{{ r.value }}</span>
          </div>
          <div v-if="!arr(d.byCountry)" class="empty">暂无数据</div>
        </div>
      </div>
      <div class="mecha-panel">
        <div class="hud-title">来源域名 TOP</div>
        <div class="rank">
          <div v-for="r in d.byReferer" :key="r.name" class="rank-row">
            <span class="rname wide">{{ r.name }}</span>
            <div class="rbar"><div class="rfill ref" :style="{width: pct(r.value, maxRef)+'%'}"></div></div>
            <span class="rval">{{ r.value }}</span>
          </div>
          <div v-if="!arr(d.byReferer)" class="empty">暂无数据</div>
        </div>
      </div>
      <div class="mecha-panel">
        <div class="hud-title">受访域名 TOP</div>
        <div class="rank">
          <div v-for="r in d.byHost" :key="r.name" class="rank-row">
            <span class="rname wide">{{ r.name }}</span>
            <div class="rbar"><div class="rfill host" :style="{width: pct(r.value, maxHost)+'%'}"></div></div>
            <span class="rval">{{ r.value }}</span>
          </div>
          <div v-if="!arr(d.byHost)" class="empty">暂无数据</div>
        </div>
      </div>
    </div>

    <!-- 受访页面 TOP -->
    <div class="mecha-panel">
      <div class="hud-title">受访页面 · TOP</div>
      <div class="rank">
        <div v-for="r in d.topPages" :key="r.name" class="rank-row">
          <span class="rname page">{{ r.name }}</span>
          <div class="rbar"><div class="rfill page" :style="{width: pct(r.value, maxPage)+'%'}"></div></div>
          <span class="rval">{{ r.value }}</span>
        </div>
        <div v-if="!arr(d.topPages)" class="empty">暂无数据</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onBeforeUnmount, ref } from 'vue'
import * as echarts from 'echarts'
import { api } from '../api'

const d = ref({ traffic: {}, byCategory: {}, topIps: [], trend: [], events: [], byAction: {}, byRule: {}, byStatus: [], byCountry: [], byBrowser: [], byOs: [], byHost: [], byReferer: [], topPages: [] })
const trendEl = ref(), catEl = ref(), actEl = ref(), qpsEl = ref()
const statusEl = ref(), browserEl = ref(), osEl = ref()
let charts = []

const kpis = computed(() => [
  { label: '请求次数', val: d.value.traffic?.req ?? 0, color: '#00e5ff', icon: 'Connection' },
  { label: '访问次数 PV', val: d.value.traffic?.pv ?? 0, color: '#36cfc9', icon: 'View' },
  { label: '独立访客 UV', val: d.value.traffic?.uv ?? 0, color: '#40a9ff', icon: 'User' },
  { label: '独立 IP', val: d.value.traffic?.ip ?? 0, color: '#b37feb', icon: 'Monitor' },
  { label: '拦截次数', val: d.value.traffic?.blk ?? 0, color: '#ff4d6d', icon: 'Lock' },
  { label: '攻击 IP', val: d.value.traffic?.atk ?? 0, color: '#ff7a45', icon: 'Warning' }
])
const errCards = computed(() => {
  const t = d.value.traffic || {}
  const a4 = t.a4 || 0, a5 = t.a5 || 0, req = t.req || 1
  return [
    { label: '4xx 错误数', val: a4, sub: '错误率 ' + pctv(a4, req) + '%', color: '#ffb020' },
    { label: '4xx 拦截数', val: t.blk || 0, sub: '拦截率 ' + pctv(t.blk || 0, req) + '%', color: '#ff4d6d' },
    { label: '5xx 错误数', val: a5, sub: '错误率 ' + pctv(a5, req) + '%', color: '#ff7a45' }
  ]
})
const ruleList = computed(() => objToList(d.value.byRule))
const maxIp = computed(() => Math.max(1, ...(d.value.topIps || []).map(r => r.value)))
const maxRule = computed(() => Math.max(1, ...ruleList.value.map(r => r.value)))
const maxCountry = computed(() => Math.max(1, ...arr2(d.value.byCountry).map(r => r.value)))
const maxRef = computed(() => Math.max(1, ...arr2(d.value.byReferer).map(r => r.value)))
const maxHost = computed(() => Math.max(1, ...arr2(d.value.byHost).map(r => r.value)))
const maxPage = computed(() => Math.max(1, ...arr2(d.value.topPages).map(r => r.value)))

function arr(a) { return Array.isArray(a) && a.length > 0 }
function arr2(a) { return Array.isArray(a) ? a : [] }

function objToList(o) { return Object.entries(o || {}).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value) }
function pct(v, m) { return Math.round((v / m) * 100) }
function pctv(a, b) { return b ? ((a / b) * 100).toFixed(1) : '0.0' }
function short(s) { s = s || ''; return s.length > 28 ? s.slice(0, 28) + '…' : s }
function fmt(ts) { if (!ts) return ''; const d2 = new Date(ts * 1000); return d2.toLocaleTimeString('zh-CN', { hour12: false }) }
function tagType(a) { return a === 'block' ? 'danger' : (a === 'pass' ? 'success' : 'warning') }

function baseGrid() { return { left: 44, right: 16, top: 24, bottom: 28 } }
function axisStyle() { return { axisLabel: { color: '#6f8bb0' }, axisLine: { lineStyle: { color: '#2a4a6a' } }, splitLine: { lineStyle: { color: 'rgba(0,229,255,0.08)' } } } }

function drawTrend() {
  const data = d.value.trend || []
  const xs = data.map(p => fmt(p.t)), ys = data.map(p => p.count)
  const c = echarts.init(trendEl.value); charts.push(c)
  c.setOption({ grid: baseGrid(), tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: xs, ...axisStyle() },
    yAxis: { type: 'value', ...axisStyle() },
    series: [{ type: 'line', smooth: true, data: ys, symbol: 'none', lineStyle: { color: '#00e5ff', width: 2 },
      areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[{offset:0,color:'rgba(0,229,255,0.45)'},{offset:1,color:'rgba(0,229,255,0)'}]) } }] })
}
function drawDonut(el, data, colors) {
  const c = echarts.init(el.value); charts.push(c)
  c.setOption({ tooltip: { trigger: 'item' }, legend: { textStyle: { color: '#9fc4e8' }, bottom: 0, type: 'scroll' },
    series: [{ type: 'pie', radius: ['42%', '68%'], center: ['50%', '44%'], data,
      label: { color: '#cfe9ff', fontSize: 11 }, itemStyle: { borderColor: '#070b12', borderWidth: 2 }, color: colors }] })
  return c
}
function drawQps() {
  const c = echarts.init(qpsEl.value); charts.push(c)
  const data = Array.from({ length: 20 }, () => Math.round(Math.random() * (d.value.traffic?.qps || 1) * 3))
  c.setOption({ grid: { left: 0, right: 0, top: 4, bottom: 0 }, xAxis: { show: false }, yAxis: { show: false },
    series: [{ type: 'bar', data, barWidth: '55%', itemStyle: { color: '#00e5ff', borderRadius: [2,2,0,0] } }] })
}

async function load() {
  try { d.value = await api.dashboard() } catch (e) { d.value = { traffic: {}, byCategory: {}, topIps: [], trend: [], events: [], byAction: {}, byRule: {}, byStatus: [], byCountry: [], byBrowser: [], byOs: [], byHost: [], byReferer: [], topPages: [] } }
  await next()
  charts.forEach(c => c.dispose()); charts = []
  drawTrend()
  drawDonut(catEl, objToList(d.value.byCategory), ['#00e5ff','#ff4d6d','#ffb020','#00ff9d','#b37feb','#ff7a45','#36cfc9','#40a9ff'])
  drawDonut(actEl, objToList(d.value.byAction), ['#ff4d6d','#00ff9d','#ffb020','#00e5ff'])
  drawDonut(statusEl, arr2(d.value.byStatus), ['#00e5ff','#ffb020','#ff4d6d','#00ff9d','#b37feb','#ff7a45'])
  drawDonut(browserEl, arr2(d.value.byBrowser), ['#40a9ff','#00e5ff','#b37feb','#00ff9d','#ffb020','#ff4d6d','#36cfc9'])
  drawDonut(osEl, arr2(d.value.byOs), ['#00e5ff','#36cfc9','#40a9ff','#b37feb','#ffb020','#ff7a45'])
  drawQps()
}
function next() { return new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))) }
const timer = ref(null)
onMounted(() => { load(); timer.value = setInterval(load, 15000) })
onBeforeUnmount(() => { clearInterval(timer.value); charts.forEach(c => c.dispose()) })
window.addEventListener('resize', () => charts.forEach(c => c.resize()))
</script>

<style scoped>
.dash { display: flex; flex-direction: column; gap: 14px; }
.kpis { display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px; }
.kpi { padding: 14px 16px; }
.kpi-top { display: flex; justify-content: space-between; align-items: center; }
.ic { color: var(--muted); font-size: 16px; }
.kpi-num { font-size: 30px; font-weight: 700; margin-top: 8px; text-shadow: 0 0 12px currentColor; font-family: 'Orbitron', monospace; }
.row2 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
.mini { padding: 12px 16px; }
.mini-big { font-size: 26px; font-weight: 700; margin: 4px 0; text-shadow: 0 0 10px currentColor; }
.mini-sub { font-size: 11px; color: var(--muted); }
.qps-chart { height: 36px; margin-top: 2px; }
.main-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
.main-grid .mecha-panel { padding: 14px; }
.span2 { grid-column: span 2; }
.chart { height: 230px; }
.chart.big { height: 250px; }
.rank { display: flex; flex-direction: column; gap: 9px; margin-top: 8px; }
.rank-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.rk { width: 18px; text-align: center; font-weight: 700; color: var(--muted); }
.rk1 { color: #ff4d6d; } .rk2 { color: #ffb020; } .rk3 { color: #00e5ff; }
.rname { width: 130px; color: #cfe9ff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rbar { flex: 1; height: 8px; background: rgba(0,229,255,0.1); border-radius: 4px; overflow: hidden; }
.rfill { height: 100%; background: linear-gradient(90deg, #00e5ff, #00ff9d); border-radius: 4px; }
.rfill.rule { background: linear-gradient(90deg, #b37feb, #00e5ff); }
.rfill.geo { background: linear-gradient(90deg, #ffb020, #ff7a45); }
.rfill.ref { background: linear-gradient(90deg, #40a9ff, #b37feb); }
.rfill.host { background: linear-gradient(90deg, #00ff9d, #00e5ff); }
.rfill.page { background: linear-gradient(90deg, #ff4d6d, #ffb020); }
.rname.wide { width: 160px; }
.rname.page { width: 240px; font-family: monospace; }
.rval { width: 34px; text-align: right; color: var(--cyan); font-weight: 700; }
.live .feed { max-height: 250px; overflow: auto; margin-top: 6px; }
.feed-row { display: flex; align-items: center; gap: 10px; padding: 6px 0; border-bottom: 1px dashed rgba(0,229,255,0.12); font-size: 12px; }
.fcat { color: #ffb020; width: 90px; }
.fip { color: #cfe9ff; width: 130px; font-family: monospace; }
.frule { color: #00ff9d; width: 80px; }
.fmatch { flex: 1; color: #9fc4e8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ftime { color: var(--muted); }
.empty { color: var(--muted); text-align: center; padding: 30px 0; font-size: 12px; }
</style>
