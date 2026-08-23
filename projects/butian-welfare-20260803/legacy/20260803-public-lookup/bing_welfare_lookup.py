#!/usr/bin/env python3
"""
补天公益SRC → 官网域名 自动解析 v3
核心改进: 品牌核心词提取 + pypinyin 拼音相关性验证 + 多轮搜索
用法: python3 bing_welfare_lookup.py [--limit N] [--start N] [--fresh]
"""
import requests, re, json, time, sys, os, urllib.parse
from pypinyin import lazy_pinyin

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
      'Accept-Language': 'zh-CN,zh;q=0.9'}

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, 'welfare-domains-final.json')

NOISE_BASES = {'bing.com','microsoft.com','msn.com','weibo.com','zhihu.com','baidu.com','sogou.com',
    'so.com','360.cn','qq.com','163.com','126.com','qcc.com','tianyancha.com','aiqicha.baidu.com',
    'bilibili.com','douyin.com','youtube.com','facebook.com','twitter.com','x.com','w3.org',
    'wikipedia.org','github.com','gitee.com','csdn.net','cnblogs.com','juejin.cn','sina.com.cn',
    'sohu.com','ifeng.com','thepaper.cn','36kr.com','huxiu.com','ithome.com','sspai.com','appinn.com',
    'klook.com','toutiao.com','sdzk.cn','sdchina.com','ctrip.com','trip.com','visitxm.com','xiamenair.com',
    'gizmodo.com','reuters.com','bbc.com','reddit.com','google.com','superpages.com','dant.us','wish.com',
    'neal.fun','westelm.com','daspot.co','yr.no','freemeteo.co.uk','thcount.com','calculator.net',
    'chinatraveljetso.com','rosaroundtheworld.com','shenzhen.com.cn','eastchinatrip.com','praktiker.bg',
    'shuidi.cn','zhipin.com','leshanvc.net','b2b168.com','96192.com','360kuai.com','cnr.cn','youth.cn',
    'people.com.cn','xinhuanet.com','news.cn','cctv.com','huanqiu.com','gmw.cn','cyol.com','china.com.cn',
    'ce.cn','stdaily.com','workercn.cn','legaldaily.com.cn','chinanews.com.cn','ecns.cn','chinadaily.com.cn',
    'globaltimes.cn','cri.cn','iqiyi.com','iyf.tv','xinjiangtrip.com','voachinese.com','halmstad.se',
    'cricinfo.com','flashscore.com','bowmangrayracing.com','ncfootballnews.com','twitch.tv','britannica.com',
    'wiktionary.org','zdic.net','chinahighlights.com','dmv-permit-test.com','dot.ca.gov','buzzfile.com',
    'whereorg.com','bibliatodo.com','wol.jw.org','kkday.com','powerthesaurus.org','promova.com','tiqets.com',
    'chinaz.com','renrendoc.com','doc88.com','docin.com','baike.com','hudong.com'}

def is_noise(domain):
    base = '.'.join(domain.rsplit('.', 2)[-2:])
    return base in NOISE_BASES

SUFFIXES = ['股份有限公司','有限责任公司','有限公司','网络科技有限公司','信息技术有限公司','科技发展有限公司',
    '科技集团','科技','集团','公司','省','市','县','区','人民政府','办公室','管理局','局','中心','大学','学院',
    '研究院','银行','医院','学校','中学','小学','委员会','政务服务中心','服务','大数据研究院','传媒','文化',
    '生物技术','医疗器械','仪器设备','基金管理','私募','投资','产权','知识产权','运营','管理','建设','工程']

CITY_PREFIX = ['北京','上海','天津','重庆','杭州','南京','厦门','长沙','深圳','广州','武汉','成都','西安',
    '济南','青岛','石家庄','哈尔滨','长春','沈阳','大连','郑州','太原','合肥','南昌','福州','昆明','贵阳',
    '南宁','兰州','银川','西宁','乌鲁木齐','呼和浩特','拉萨','海口','苏州','无锡','宁波','温州','嘉兴',
    '绍兴','金华','台州','湖州','衢州','舟山','丽水','东莞','佛山','珠海','中山','惠州','江门','汕头',
    '湛江','肇庆','扬州','常州','南通','徐州','盐城','泰州','镇江','淮安','连云港','宿迁','江西','山东',
    '浙江','江苏','湖南','湖北','河南','河北','山西','陕西','甘肃','青海','四川','贵州','云南','福建',
    '广东','广西','安徽','新疆','西藏','宁夏','内蒙古','黑龙江','吉林','辽宁','海南','中国']

def extract_core(name):
    """提取品牌核心词（去地名前缀+后缀），返回 [(词, 拼音), ...]"""
    n = name
    for s in SUFFIXES:
        n = n.replace(s, '')
    n = n.strip('()（）')
    # 去城市/省份前缀
    for c in CITY_PREFIX:
        if n.startswith(c):
            n = n[len(c):]
            break
    # 去尾部行政区划字
    for s in ('省', '市', '县', '区'):
        if n.endswith(s):
            n = n[:-1]
            break
    words = re.findall(r'[\u4e00-\u9fa5]{2,}', n)
    result = []
    for w in words:
        if len(w) >= 2:
            py = ''.join(lazy_pinyin(w))
            result.append((w, py))
    # 最短核心词优先（黑湖网络 → 黑湖），便于拼音/品牌匹配
    result.sort(key=lambda x: len(x[0]))
    return result

def bing_rss_search(query, retries=2):
    url = f'https://www.bing.com/search?q={urllib.parse.quote(query)}&format=rss&count=10'
    for i in range(retries + 1):
        try:
            r = requests.get(url, headers=UA, timeout=15)
            if r.status_code == 200 and '<item>' in r.text:
                return re.findall(r'<item><title>(.*?)</title><link>(.*?)</link>', r.text, re.S)
        except Exception:
            pass
        time.sleep(3)
    return []

def extract_domain(url):
    m = re.search(r'https?://([a-zA-Z0-9][a-zA-Z0-9.-]*)', url)
    return m.group(1) if m else None

def score_domain(domain, cores):
    """域名相关性打分: 拼音/英文匹配"""
    parts = domain.lower().replace('www.', '').split('.')
    d = parts[0]  # www.hesaitech.com → hesaitech; zhengtushouyou.com.cn → zhengtushouyou
    score = 0
    for word, py in cores:
        if py and py in d:  # 拼音匹配 hesai in hesaitech
            score += 10
        if word in domain.lower():  # 中文不会出现在域名，跳过（保英文品牌）
            score += 5
    # 政府/教育域名加分
    if domain.endswith('.gov.cn'): score += 3
    if domain.endswith('.edu.cn'): score += 3
    return score

def verify_title(domain, cores):
    """访问首页验证 title 含核心词（中文词 或 拼音/英文品牌）"""
    for scheme in ('https://', 'http://'):
        try:
            r = requests.get(scheme + domain, headers=UA, timeout=8, allow_redirects=True)
            if r.status_code < 400:
                title = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.S | re.I)
                if title:
                    t = title.group(1)
                    hits = [w for w, _ in cores if w in t]
                    if hits:
                        return True, t.strip()[:70]
                    # 拼音/英文品牌验证（大小写不敏感）
                    t_lower = t.lower()
                    py_hits = [py for _, py in cores if py and py in t_lower]
                    if py_hits:
                        return True, t.strip()[:70]
                    return False, t.strip()[:70]
        except Exception:
            continue
    return False, ''

def main():
    src = os.path.join(BASE, 'welfare-projects.json')
    data = json.load(open(src))
    projects = data['all_projects']

    results = {}
    if os.path.exists(OUT) and '--fresh' not in sys.argv:
        try:
            results = {r['company_id']: r for r in json.load(open(OUT))['results']}
        except Exception:
            pass

    limit, start = None, 0
    if '--limit' in sys.argv:
        limit = int(sys.argv[sys.argv.index('--limit') + 1])
    if '--start' in sys.argv:
        start = int(sys.argv[sys.argv.index('--start') + 1])

    to_do = [p for p in projects if p['company_id'] not in results or results[p['company_id']]['status'] == 'not_found']
    to_do = to_do[start:]
    if limit:
        to_do = to_do[:limit]

    print(f"待解析: {len(to_do)} (已有 {len(results)})")
    for i, p in enumerate(to_do):
        name = p['company_name']
        cores = extract_core(name)
        # 机构类（大学/学院/医院/局/办/中心/研究院）用全名优先；企业用核心词优先
        INST_KW = ('大学', '学院', '医院', '局', '办', '中心', '研究院', '学校', '政府')
        is_inst = any(k in name for k in INST_KW)
        queries = []
        if cores:
            w, py = cores[0]
            if is_inst:
                queries = [name, f'{name} 官网', w]
            else:
                queries = [w, f'{w} 官网', name, py.capitalize()]
        else:
            queries = [name, f'{name} 官网']
        all_items = []
        for q in queries:
            items = bing_rss_search(q)
            all_items.extend(items)
            if len(all_items) >= 6:
                break
            time.sleep(1)
        # 提取去重域名 + 打分
        cands = []
        for title, url in all_items:
            d = extract_domain(url)
            if not d or is_noise(d) or any(c[0] == d for c in cands):
                continue
            cands.append((d, score_domain(d, cores)))
        cands.sort(key=lambda x: -x[1])
        # 取高分候选验证
        verified, status = [], 'not_found'
        for d, sc in cands[:4]:
            ok, t = verify_title(d, cores)
            if ok:
                verified.append({'domain': d, 'score': sc, 'title': t})
                status = 'confirmed'
                break
        if status != 'confirmed' and cands and cands[0][1] > 0:
            status = 'candidate'
        elif status != 'confirmed' and cands:
            status = 'weak'
        results[p['company_id']] = {
            'company_id': p['company_id'], 'company_name': name,
            'core_words': [w for w, _ in cores], 'cores_pinyin': [py for _, py in cores],
            'candidates': [{'domain': d, 'score': s} for d, s in cands[:4]],
            'verified': verified, 'status': status,
        }
        mark = {'confirmed': '✅', 'candidate': '⚠️', 'weak': '◐', 'not_found': '❌'}[status]
        print(f"[{i+1}/{len(to_do)}] {mark} {name} (核心:{cores}) → {verified if verified else cands[:2]}")
        if (i + 1) % 5 == 0:
            json.dump({'results': list(results.values())}, open(OUT, 'w'), ensure_ascii=False, indent=1)
        time.sleep(1.5)

    json.dump({'results': list(results.values())}, open(OUT, 'w'), ensure_ascii=False, indent=1)
    cnt = {}
    for r in results.values():
        cnt[r['status']] = cnt.get(r['status'], 0) + 1
    print(f"\n完成: {len(results)} {cnt} → {OUT}")

if __name__ == '__main__':
    main()
