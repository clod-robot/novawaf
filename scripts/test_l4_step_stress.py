"""l4_step_stress.py 统计口径单元测试（mock 网络层，不发起真实请求）。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l4_step_stress as m


class TestPct(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(m.pct([], 0.5), 0)

    def test_single(self):
        self.assertEqual(m.pct([0.1], 0.99), 100.0)

    def test_sorted_percentiles(self):
        # 分位数取法与旧版 l4_stress.py 一致：sorted[int(n*p)]（0 基）
        lats = [i / 1000.0 for i in range(1, 101)]  # 1..100ms
        self.assertEqual(m.pct(lats, 0.50), 51.0)   # lats[50]
        self.assertEqual(m.pct(lats, 0.95), 96.0)   # lats[95]
        self.assertEqual(m.pct(lats, 0.99), 100.0)  # lats[99]


class TestStepStats(unittest.TestCase):
    """核心改进点：所有 worker 线程的请求全部计入统计（修复旧版只记主线程的口径缺陷）。"""

    def test_all_worker_requests_counted(self):
        orig = m.one_req
        m.one_req = lambda p, me, b, c: (0.010, True)
        try:
            row = m.step("t", "/x", "GET", None, None, conc=5, dur=1)
        finally:
            m.one_req = orig
        # 5 线程 × 1s / 10ms 理论约 500 次，放宽下限排除调度抖动
        self.assertGreater(row["total"], 200)
        self.assertEqual(row["err"], 0)
        self.assertEqual(row["err_pct"], 0.0)
        self.assertEqual(row["p50"], 10.0)
        self.assertEqual(row["p99"], 10.0)
        # rps 用未舍入 real_dur 计算，dur 字段保留 1 位小数，允许 2% 相对误差
        self.assertAlmostEqual(row["rps"] / (row["total"] / row["dur"]), 1.0, delta=0.02)

    def test_errors_counted(self):
        orig = m.one_req
        state = {"n": 0}

        def fake(p, me, b, c):
            state["n"] += 1
            return 0.005, state["n"] % 2 == 0

        m.one_req = fake
        try:
            row = m.step("t", "/x", "GET", None, None, conc=2, dur=1)
        finally:
            m.one_req = orig
        self.assertGreater(row["err"], 0)
        self.assertLess(row["err"], row["total"])
        self.assertAlmostEqual(row["err_pct"], row["err"] * 100.0 / row["total"], places=1)


if __name__ == "__main__":
    unittest.main()
