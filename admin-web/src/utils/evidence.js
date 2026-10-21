// 电子证据导出工具：一次性强密码 + AES-256-CBC 加密 + HMAC-SHA256 认证 + SHA-256 摘要
// 说明：浏览器无法给下载文件设置系统级只读属性，因此通过强加密实现"无密码不可查看、被改动即被发现"。
// 实现使用纯 JS（crypto-js）而非 Web Crypto：管理后台常以 http://内网IP 访问，属于非安全上下文，
// crypto.subtle 不可用，纯 JS 实现可保证 http/https 下行为一致。
import CryptoJS from 'crypto-js'

const PWD_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*-_=+'
const ITER = 20000

// 生成高强度随机密码（默认 32 位，含大小写/数字/符号）
export function genPassword(len = 32) {
  const buf = new Uint8Array(len)
  crypto.getRandomValues(buf)
  let out = ''
  for (let i = 0; i < len; i++) out += PWD_CHARS[buf[i] % PWD_CHARS.length]
  return out
}

function wordArrayToB64(wa) { return CryptoJS.enc.Base64.stringify(wa) }
function b64ToWordArray(s) { return CryptoJS.enc.Base64.parse(s) }
function randomBytes(n) { return CryptoJS.lib.WordArray.random(n) }

export function sha256Hex(text) {
  return CryptoJS.SHA256(text).toString(CryptoJS.enc.Hex)
}

/**
 * 生成加密证据包文本（保存为 .enc）
 * 加密：AES-256-CBC(随机 IV) → HMAC-SHA256(iv || 密文) 认证（Encrypt-then-MAC，防篡改）
 * 密钥：PBKDF2-HMAC-SHA256(密码, 随机 salt, ITER 次) 派生 64 字节 = AES Key(32) + MAC Key(32)
 * @param {string} plainText 明文内容
 * @param {string} password 一次性密码
 * @param {object} meta { filename, operator }
 */
export function encryptEvidence(plainText, password, meta = {}) {
  const salt = randomBytes(16)
  const iv = randomBytes(16)
  const derived = CryptoJS.PBKDF2(password, salt, {
    keySize: 512 / 32, iterations: ITER, hasher: CryptoJS.algo.SHA256
  })
  const aesKey = CryptoJS.lib.WordArray.create(derived.words.slice(0, 8), 32)
  const macKey = CryptoJS.lib.WordArray.create(derived.words.slice(8, 16), 32)

  // 明文按 UTF-8 原样加密（不额外加盐，便于第三方按标准流程复算）
  const cipher = CryptoJS.AES.encrypt(
    CryptoJS.enc.Utf8.parse(plainText),
    aesKey,
    { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
  ).ciphertext

  const macInput = iv.clone().concat(cipher)
  const mac = CryptoJS.HmacSHA256(macInput, macKey)
  const digest = sha256Hex(plainText)
  const byteLen = CryptoJS.enc.Utf8.parse(plainText).sigBytes

  const header = [
    '# NOVAWAF 电子证据加密包 v1',
    '# 算法: AES-256-CBC / PKCS7   认证: HMAC-SHA256(iv||密文)',
    '# KDF: PBKDF2-HMAC-SHA256  迭代次数: ' + ITER + '  派生长度: 64 字节(AES Key 32 | MAC Key 32)',
    '# 明文文件: ' + (meta.filename || '-'),
    '# 明文字节数: ' + byteLen,
    '# 明文 SHA-256: ' + digest,
    '# 导出时间: ' + new Date().toLocaleString('zh-CN', { hour12: false }),
    '# 导出操作人: ' + (meta.operator || '-'),
    '# SALT(b64): ' + wordArrayToB64(salt),
    '# IV(b64): ' + wordArrayToB64(iv),
    '# MAC(b64): ' + wordArrayToB64(mac),
    '# ---- 以下为 Base64 密文，任何改动都会导致 MAC 校验失败 ----'
  ].join('\n')

  return {
    text: header + '\n' + wordArrayToB64(cipher),
    digest,
    bytes: byteLen,
    mac: mac.toString(CryptoJS.enc.Hex)
  }
}

export function download(filename, content, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1500)
}

export async function copyText(text) {
  const t = String(text == null ? '' : text)
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(t); return true } catch { /* 走降级 */ }
  }
  // 非安全上下文（http 访问）降级方案
  const ta = document.createElement('textarea')
  ta.value = t
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.select()
  let ok = false
  try { ok = document.execCommand('copy') } catch { ok = false }
  ta.remove()
  return ok
}

// 导出操作人（登录名）
export function operatorName() {
  return localStorage.getItem('nova_user') || 'operator'
}

// 时间戳：20260101_120000
export function nowStamp() {
  const d = new Date(), p = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
}

// CSV 字段转义
export function csvEscape(v) {
  if (v === null || v === undefined) return ''
  const s = Array.isArray(v) ? v.join(' | ') : String(v)
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s
}

export function buildCsv(header, rows) {
  return [header.map(csvEscape).join(','), ...rows.map(r => r.map(csvEscape).join(','))].join('\r\n')
}
