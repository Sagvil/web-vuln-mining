#!/usr/bin/env python3
"""补天公益SRC 全量爬虫（GET 分页 + 断点续爬 + 自动重试）"""
import requests, json, time, os, sys

BASE = '/home/sagvil/web-vuln-mining/projects/butian-welfare-20260803'
OUT = os.path.join(BASE, 'welfare-projects.json')

s = requests.Session()
s.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                  'Referer': 'https://www.butian.net/Reward/plan/1'})

# Load existing
all_projects = {}
if os.path.exists(OUT):
    try:
        all_projects = {p['company_id']: p for p in json.load(open(OUT))['all_projects']}
    except Exception:
        pass

start_page = int(sys.argv[1]) if len(sys.argv) > 1 else 30
print(f"已有 {len(all_projects)} 个, 从 page {start_page} 继续")

p = start_page
consec_fail = 0
while p <= 300:
    lst = []
    ok = False
    for attempt in range(3):
        try:
            r = s.get('https://www.butian.net/Reward/pub', params={'name': '', 'p': p}, timeout=20)
            lst = r.json().get('data', {}).get('list', [])
            ok = True
            break
        except Exception as e:
            print(f"  page {p} 失败({attempt+1}): {str(e)[:40]}")
            time.sleep(5)
    if not ok:
        consec_fail += 1
        if consec_fail >= 3:
            print(f">>> 连续失败 {consec_fail} 次, 停止")
            break
        continue
    consec_fail = 0
    new = 0
    for item in lst:
        if item['company_id'] not in all_projects:
            all_projects[item['company_id']] = item
            new += 1
    print(f"page {p}: +{len(lst)} (新 {new}, 累计 {len(all_projects)})")
    if len(lst) < 30 and new == 0:
        print(">>> 到达末页")
        break
    # 每 5 页保存
    if p % 5 == 0:
        json.dump({'source': '补天公益SRC GET /Reward/pub?name=&p=N', 'crawl_time': '2026-08-03',
                   'total_projects': len(all_projects), 'all_projects': list(all_projects.values())},
                  open(OUT, 'w'), ensure_ascii=False, indent=1)
    p += 1
    time.sleep(0.8)

json.dump({'source': '补天公益SRC GET /Reward/pub?name=&p=N', 'crawl_time': '2026-08-03',
           'total_projects': len(all_projects), 'all_projects': list(all_projects.values())},
          open(OUT, 'w'), ensure_ascii=False, indent=1)
print(f"\n=== 最终: {len(all_projects)} 个项目 ===")
