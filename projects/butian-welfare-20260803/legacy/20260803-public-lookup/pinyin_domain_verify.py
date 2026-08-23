#!/usr/bin/env python3
"""拼音候选域名直接验证器：核心词拼音 → 生成候选域名 → 访问验证 title"""
import requests, re, json, time, sys, os, concurrent.futures
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pypinyin import lazy_pinyin

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

# 已知品牌域名映射（人工验证过的）
KNOWN = {
    '上海黑湖网络科技有限公司': 'blacklake.cn',
    '厦门快快网络科技有限公司': 'kkidc.com',
    '北京忆恒创源科技股份有限公司': 'memblaze.com',
    '上海禾赛科技有限公司': 'hesaitech.com',
    '上海收钱吧互联网科技股份有限公司': 'shouqianba.com',
    '江西师范大学': 'jxnu.edu.cn',
    '中国司法大数据研究院有限公司': 'data.court.gov.cn',
    '浙江省医疗保障局': 'ybj.zj.gov.cn',
    '杭州市人力资源和社会保障政务服务中心': 'hrss.hangzhou.gov.cn',
}

def core_pinyin(name):
    """提取核心词拼音（短词优先）"""
    SUFFIXES = ['股份有限公司','有限责任公司','有限公司','网络科技有限公司','信息技术有限公司',
        '科技发展有限公司','科技集团','科技','集团','公司','省','市','县','区','人民政府','办公室',
        '管理局','局','中心','大学','学院','研究院','银行','医院','学校','委员会','政务服务中心',
        '服务','大数据研究院','传媒','文化','生物技术','医疗器械','仪器设备','基金管理','私募',
        '投资','产权','知识产权','运营','管理','建设','工程','网络']
    n = name
    for s in sorted(SUFFIXES, key=len, reverse=True):
        n = n.replace(s, '')
    n = n.strip('()（）')
    CITY = ['北京','上海','天津','重庆','杭州','南京','厦门','长沙','深圳','广州','武汉','成都','西安',
        '济南','青岛','石家庄','哈尔滨','长春','沈阳','大连','郑州','太原','合肥','南昌','福州','昆明',
        '贵阳','南宁','兰州','银川','西宁','乌鲁木齐','呼和浩特','拉萨','海口','苏州','无锡','宁波',
        '温州','嘉兴','绍兴','金华','台州','湖州','衢州','舟山','丽水','东莞','佛山','珠海','中山',
        '惠州','江门','汕头','湛江','肇庆','扬州','常州','南通','徐州','盐城','泰州','镇江','淮安',
        '连云港','宿迁','江西','山东','浙江','江苏','湖南','湖北','河南','河北','山西','陕西','甘肃',
        '青海','四川','贵州','云南','福建','广东','广西','安徽','新疆','西藏','宁夏','内蒙古',
        '黑龙江','吉林','辽宁','海南','中国']
    for c in CITY:
        if n.startswith(c):
            n = n[len(c):]
            break
    for s in ('省', '市', '县', '区'):
        if n.endswith(s):
            n = n[:-1]
            break
    words = re.findall(r'[\u4e00-\u9fa5]{2,}', n)
    words.sort(key=len)
    return [''.join(lazy_pinyin(w)) for w in words]

def gen_candidates(pys):
    cands = set()
    for py in pys[:2]:
        for tld in ['com', 'cn', 'net', 'com.cn', 'cc', 'top', 'vip']:
            cands.add(f'{py}.{tld}')
            cands.add(f'www.{py}.{tld}')
        if len(py) > 6:
            cands.add(f'{py[:4]}.com')
    return cands

def check(domain, kw_pys, kw_chars):
    for scheme in ('https://', 'http://'):
        try:
            r = requests.get(scheme + domain, headers=UA, timeout=6, allow_redirects=True)
            if r.status_code < 400:
                t = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.S | re.I)
                if t:
                    title = t.group(1).lower()
                    # title 含中文核心词 或 拼音
                    if any(c in title for c in kw_chars):
                        return domain, 'confirmed', t.group(1).strip()[:60]
                    if any(p in title for p in kw_pys):
                        return domain, 'confirmed', t.group(1).strip()[:60]
                    return domain, 'alive', t.group(1).strip()[:50]
        except Exception:
            continue
    return None

def main():
    data = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'welfare-projects.json')))
    projects = data['all_projects'][:30]
    results = []
    for p in projects:
        name = p['company_name']
        if name in KNOWN:
            results.append({'company_id': p['company_id'], 'company_name': name,
                            'domain': KNOWN[name], 'status': 'confirmed', 'title': '(人工验证)'})
            print(f"✅ [已知] {name} → {KNOWN[name]}")
            continue
        pys = core_pinyin(name)
        cands = gen_candidates(pys)
        found = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(check, d, pys, name): d for d in cands}
            for f in concurrent.futures.as_completed(futs):
                res = f.result()
                if res and res[1] == 'confirmed':
                    found = res
                    break
        if found:
            results.append({'company_id': p['company_id'], 'company_name': name,
                            'domain': found[0], 'status': 'confirmed', 'title': found[2]})
            print(f"✅ {name} → {found[0]} ({found[2][:40]})")
        else:
            # 汇报存活的（未确认）
            alive = []
            for d in cands:
                res = None
                try:
                    r = requests.get(f'https://{d}', headers=UA, timeout=5, allow_redirects=True)
                    if r.status_code < 400:
                        alive.append(d)
                except Exception:
                    pass
            results.append({'company_id': p['company_id'], 'company_name': name,
                            'domain': None, 'status': 'not_found', 'alive': alive[:3]})
            print(f"❌ {name} (拼音:{pys[:2]}) → {'存活但未确认:' + str(alive[:2]) if alive else '无'}")
        time.sleep(0.5)

    json.dump(results, open('/home/sagvil/web-vuln-mining/projects/butian-welfare-20260803/welfare-pinyin-verify.json', 'w'),
              ensure_ascii=False, indent=1)
    print(f"\n完成: {sum(1 for r in results if r['status']=='confirmed')}/{len(results)} 确认")

if __name__ == '__main__':
    main()
