import axios from 'axios'
import qs from 'qs'
import { ElMessage } from 'element-plus'
import router from '../router'

const http = axios.create({
  baseURL: '/api',
  timeout: 15000,
  // 参数序列化统一走 qs (数组带重复键、日期格式化)
  paramsSerializer: (p) => qs.stringify(p, { arrayFormat: 'repeat' })
})

http.interceptors.request.use((cfg) => {
  const token = localStorage.getItem('nova_token')
  if (token) cfg.headers.Authorization = 'Bearer ' + token
  return cfg
})

http.interceptors.response.use(
  (resp) => {
    const body = resp.data
    if (body && typeof body === 'object' && 'code' in body) {
      if (body.code === 200) return body.data
      if (body.code === 401) {
        localStorage.removeItem('nova_token')
        router.replace('/login')
      }
      ElMessage.error(body.msg || '请求失败')
      return Promise.reject(body)
    }
    return body
  },
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('nova_token')
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
  users: (p) => http.get('/system/users', { params: p }),
  addUser: (d) => http.post('/system/users', d),
  updUser: (id, d) => http.put('/system/users/' + id, d),
  delUser: (id) => http.delete('/system/users/' + id),
  resetPwd: (id, password) => http.post('/system/users/' + id + '/password', { password }),
  operLogs: (p) => http.get('/system/logs', { params: p })
}
export default http
