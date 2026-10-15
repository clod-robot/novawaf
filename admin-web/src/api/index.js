import axios from 'axios'
import qs from 'qs'
import { ElMessage } from 'element-plus'
import router from '../router'

const http = axios.create({
  baseURL: '/api',
  timeout: 15000,
  withCredentials: true,   // 会话走 HttpOnly Cookie，防 XSS 窃取令牌
  // 参数序列化统一走 qs (数组带重复键、日期格式化)
  paramsSerializer: (p) => qs.stringify(p, { arrayFormat: 'repeat' })
})

http.interceptors.request.use((cfg) => {
  // 令牌已存 HttpOnly Cookie，由浏览器自动携带；这里不再从 localStorage 读取注入
  return cfg
})

http.interceptors.response.use(
  (resp) => {
    const body = resp.data
    if (body && typeof body === 'object' && 'code' in body) {
      if (body.code === 200) return body.data
      if (body.code === 401) {
        localStorage.removeItem('nova_authed')
        router.replace('/login')
      }
      ElMessage.error(body.msg || '请求失败')
      return Promise.reject(body)
    }
    return body
  },
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('nova_authed')
      router.replace('/login')
    }
    ElMessage.error(err.response?.data?.msg || err.message || '网络错误')
    return Promise.reject(err)
  }
)

export const api = {
  login: (d) => http.post('/auth/login', d),
  logout: () => http.post('/auth/logout'),
  info: () => http.get('/auth/info'),
  wafLogs: (p) => http.get('/waf/logs', { params: p }),
  wafEvents: (p) => http.get('/waf/events', { params: p }),
  wafStats: () => http.get('/waf/stats'),
  dashboard: () => http.get('/waf/dashboard'),
  wafApps: () => http.get('/waf/apps'),
  addApp: (d) => http.post('/waf/apps', d),
  updateApp: (id, d) => http.put('/waf/apps/' + id, d),
  setAppMode: (id, mode) => http.post('/waf/apps/' + id + '/mode', { mode }),
  delApp: (id) => http.delete('/waf/apps/' + id),
  wafRules: () => http.get('/waf/rules'),
  saveRules: (json) => http.post('/waf/rules', { json }),
  reloadRules: () => http.post('/waf/rules/reload'),
  wafIoc: () => http.get('/waf/ioc'),
  // 黑白名单(联动 GeoIP)
  ipList: (type, q) => http.get('/waf/iplist', { params: { type, q } }),
  addIp: (d) => http.post('/waf/iplist', d),
  delIp: (type, ip) => http.delete('/waf/iplist', { params: { type, ip } }),
  toggleIp: (type, ip) => http.post('/waf/iplist/toggle', { type, ip }),
  clearIp: (type) => http.delete('/waf/iplist/all', { params: { type } }),
  syslogStatus: () => http.get('/waf/syslog'),
  saveSyslog: (cfg) => http.put('/waf/syslog', cfg),
  testSyslog: (cfg) => http.post('/waf/syslog/test', cfg || {}),
  wafEvents2: (p) => http.get('/waf/events', { params: p }),
  // SSE 实时流：同源 EventSource 自动携带 HttpOnly 会话 Cookie，无需在 URL 暴露令牌
  streamUrl: () => {
    const base = (import.meta.env && import.meta.env.VITE_API_BASE) || '/api'
    return `${base}/waf/stream`
  },
  // API 路径级防护策略：block 拦截 / log 仅记录 / pass 跳过WAF检测，保存即发布
  apiPolicyList: () => http.get('/waf/api-policy/list'),
  apiPolicyCreate: (d) => http.post('/waf/api-policy', d),
  apiPolicyUpdate: (d) => http.put('/waf/api-policy', d),
  apiPolicyToggle: (id, enabled) => http.put('/waf/api-policy/' + id + '/enabled', { enabled }),
  apiPolicyDelete: (id) => http.delete('/waf/api-policy/' + id),
  // 通用设置-部署方式：网络类型探测(nat)与 HA 配置读写
  deployGet: () => http.get('/system/deploy'),
  deploySave: (d) => http.put('/system/deploy', d),
  deployDetectNat: () => http.post('/system/deploy/nat/detect'),
  // 通用设置-IP 组：组管理 + GeoIP 地域策略
  ipGroupList: () => http.get('/waf/ipgroup/list'),
  ipGroupCreate: (d) => http.post('/waf/ipgroup', d),
  ipGroupUpdate: (id, d) => http.put('/waf/ipgroup/' + id, d),
  ipGroupDelete: (id) => http.delete('/waf/ipgroup/' + id),
  ipGroupEntries: (id, p) => http.get('/waf/ipgroup/' + id + '/entries', { params: p }),
  ipGroupAddEntry: (id, value) => http.post('/waf/ipgroup/' + id + '/entries', { value }),
  ipGroupImport: (id, text) => http.post('/waf/ipgroup/' + id + '/import', { text }),
  ipGroupDelEntry: (id, value) => http.delete('/waf/ipgroup/' + id + '/entries', { data: { value } }),
  ipGroupClear: (id) => http.put('/waf/ipgroup/' + id + '/entries/clear'),
  ipGroupUpdateRun: (id) => http.post('/waf/ipgroup/' + id + '/update'),
  ipGroupTask: (id) => http.get('/waf/ipgroup/' + id + '/task'),
  geoStats: () => http.get('/waf/ipgroup/geo/stats'),
  geoPolicyGet: () => http.get('/waf/ipgroup/geo/policy'),
  geoPolicySave: (d) => http.put('/waf/ipgroup/geo/policy', d),
  users: (p) => http.get('/system/users', { params: p }),
  addUser: (d) => http.post('/system/users', d),
  updUser: (id, d) => http.put('/system/users/' + id, d),
  delUser: (id) => http.delete('/system/users/' + id),
  resetPwd: (id, password) => http.post('/system/users/' + id + '/password', { password }),
  operLogs: (p) => http.get('/system/logs', { params: p })
}
export default http
