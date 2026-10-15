// 纯函数工具：便于本地单元测试，无 DOM / 网络依赖

/** 格式化时间戳(ms) 为 zh-CN 本地字符串；空值返回占位符 */
export function fmtTime(t, placeholder = '—') {
  if (!t) return placeholder
  const d = new Date(t)
  if (Number.isNaN(d.getTime())) return placeholder
  return d.toLocaleString('zh-CN', { hour12: false })
}

/** 地理标签类型映射（用于 el-tag type） */
export function geoType(g) {
  if (g === '内网' || g === '未知') return 'info'
  if (['中国', '中国香港', '中国台湾'].includes(g)) return 'success'
  return 'warning'
}

/** IP/CIDR 合法性校验：支持 IPv4 与 IPv4/CIDR */
export function isValidIpOrCidr(s) {
  if (typeof s !== 'string') return false
  const v = s.trim()
  if (!v) return false
  const m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/)
  if (!m) return false
  for (let i = 1; i <= 4; i++) {
    const n = Number(m[i])
    if (n < 0 || n > 255) return false
  }
  if (m[5] !== undefined) {
    const bits = Number(m[5])
    if (bits < 0 || bits > 32) return false
  }
  return true
}

/** 分页切片：返回指定页的数据 */
export function paginate(list, page, pageSize) {
  if (!Array.isArray(list)) return []
  const p = Math.max(1, page || 1)
  const s = Math.max(1, pageSize || 10)
  return list.slice((p - 1) * s, p * s)
}

/** 命中总数汇总 */
export function sumHits(rows) {
  if (!Array.isArray(rows)) return 0
  return rows.reduce((acc, r) => acc + (Number(r && r.hits) || 0), 0)
}
