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

const SUP = { 0: '⁰', 1: '¹', 2: '²', 3: '³', 4: '⁴', 5: '⁵', 6: '⁶', 7: '⁷', 8: '⁸', 9: '⁹' }

/** 大数科学计数法：|n| >= 1e8 显示为 a.b×10^n（Unicode 上标），否则千分位。
 *  防止大屏数字卡片/表格位宽溢出；尾随零压缩（1.50→1.5、2.00→2）。 */
export function fmtBig(n) {
  const v = Number(n)
  if (!Number.isFinite(v)) return '0'
  if (Math.abs(v) < 1e8) return v.toLocaleString('en-US')
  let exp = Math.floor(Math.log10(Math.abs(v)))
  let mant = (v / 10 ** exp).toFixed(2)
  if (Number(mant) >= 10) { exp += 1; mant = (v / 10 ** exp).toFixed(2) } // 尾数进位规格化
  const m = mant.replace(/\.?0+$/, '')
  const eStr = String(exp).split('').map(c => SUP[c] || c).join('')
  return m + '×10' + eStr
}
