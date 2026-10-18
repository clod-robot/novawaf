import { describe, it, expect } from 'vitest'
import { fmtTime, geoType, isValidIpOrCidr, paginate, sumHits, fmtBig } from './format'

describe('fmtBig 大数科学计数法', () => {
  it('阈值以下保持千分位', () => {
    expect(fmtBig(0)).toBe('0')
    expect(fmtBig(99999999)).toBe('99,999,999')
    expect(fmtBig(1234)).toBe('1,234')
  })
  it('阈值以上转科学计数法(×10^n 上标)', () => {
    expect(fmtBig(1e8)).toBe('1×10⁸')
    expect(fmtBig(123456789)).toBe('1.23×10⁸')
    expect(fmtBig(999999999999)).toBe('1×10¹²')
    expect(fmtBig(5.2e9)).toBe('5.2×10⁹')
  })
  it('尾随零压缩', () => {
    expect(fmtBig(200000000)).toBe('2×10⁸')
    expect(fmtBig(1500000000)).toBe('1.5×10⁹')
  })
  it('负数与非有限值', () => {
    expect(fmtBig(-250000000)).toBe('-2.5×10⁸')
    expect(fmtBig(null)).toBe('0')
    expect(fmtBig(undefined)).toBe('0')
    expect(fmtBig(NaN)).toBe('0')
    expect(fmtBig('abc')).toBe('0')
  })
})


describe('fmtTime', () => {
  it('空值返回占位符', () => {
    expect(fmtTime(null)).toBe('—')
    expect(fmtTime(0)).toBe('—')
    expect(fmtTime(undefined, 'N/A')).toBe('N/A')
  })
  it('非法时间返回占位符', () => {
    expect(fmtTime('not-a-date')).toBe('—')
  })
  it('合法时间戳返回字符串', () => {
    expect(typeof fmtTime(1700000000000)).toBe('string')
    expect(fmtTime(1700000000000).length).toBeGreaterThan(0)
  })
})

describe('geoType', () => {
  it('内网/未知 -> info', () => {
    expect(geoType('内网')).toBe('info')
    expect(geoType('未知')).toBe('info')
  })
  it('中国区域 -> success', () => {
    expect(geoType('中国')).toBe('success')
    expect(geoType('中国香港')).toBe('success')
    expect(geoType('中国台湾')).toBe('success')
  })
  it('其他国家 -> warning', () => {
    expect(geoType('美国')).toBe('warning')
    expect(geoType('')).toBe('warning')
  })
})

describe('isValidIpOrCidr', () => {
  it('合法 IPv4', () => {
    expect(isValidIpOrCidr('1.2.3.4')).toBe(true)
    expect(isValidIpOrCidr('  10.0.0.1 ')).toBe(true)
  })
  it('合法 CIDR', () => {
    expect(isValidIpOrCidr('10.0.0.0/8')).toBe(true)
    expect(isValidIpOrCidr('192.168.1.0/24')).toBe(true)
    expect(isValidIpOrCidr('0.0.0.0/0')).toBe(true)
    expect(isValidIpOrCidr('1.2.3.4/32')).toBe(true)
  })
  it('非法输入', () => {
    expect(isValidIpOrCidr('')).toBe(false)
    expect(isValidIpOrCidr(null)).toBe(false)
    expect(isValidIpOrCidr('999.1.1.1')).toBe(false)
    expect(isValidIpOrCidr('1.2.3')).toBe(false)
    expect(isValidIpOrCidr('1.2.3.4/33')).toBe(false)
    expect(isValidIpOrCidr('1.2.3.4/-1')).toBe(false)
    expect(isValidIpOrCidr('abc')).toBe(false)
  })
})

describe('paginate', () => {
  const list = [1, 2, 3, 4, 5]
  it('第一页', () => {
    expect(paginate(list, 1, 2)).toEqual([1, 2])
  })
  it('最后一页(不足一页)', () => {
    expect(paginate(list, 3, 2)).toEqual([5])
  })
  it('越界页返回空', () => {
    expect(paginate(list, 10, 2)).toEqual([])
  })
  it('非数组返回空', () => {
    expect(paginate(null, 1, 10)).toEqual([])
  })
})

describe('sumHits', () => {
  it('求和', () => {
    expect(sumHits([{ hits: 3 }, { hits: 5 }, { hits: 0 }])).toBe(8)
  })
  it('缺省/非法视为 0', () => {
    expect(sumHits([{ hits: undefined }, { a: 1 }])).toBe(0)
  })
  it('空/非数组返回 0', () => {
    expect(sumHits([])).toBe(0)
    expect(sumHits(null)).toBe(0)
  })
})
