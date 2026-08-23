# DNS 子域名 10k 字典

`subdomains-10000.txt` 是初筛 DNS 枚举的固定 10,000 条标签字典。

- 来源：SecLists `Discovery/DNS/subdomains-top1million-110000.txt` 的前 10,000 个去重、非空条目。
- SHA-256：`4f87d41b64f9bb606e5922a8040875205229e6574956b123cdc8965e891d5731`
- 使用方式：仅由 Nmap `dns-brute` 在 `-sn -n -Pn` DNS 枚举模式下读取；不进行端口或服务探测。
- 替换方式：通过 `--subdomain-wordlist PATH` 指定其他本地字典，不在运行时下载字典。
