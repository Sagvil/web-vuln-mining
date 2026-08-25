# 特变电工 sunoasis.com.cn R1 挖掘报告（2026-08-25）

**模式:** approved_scope_profile（shadow） | **项目:** 补天 64777 | **目标:** 全力挖掘高危

## 一、子域发现（完成）
- 历史 21 子域 **100% 存活**；万级词表 brute **0 新增** → 资产面收敛
- Web 服务 8 个：www/info/access/bigdata/em/portal/english/spanish

## 二、三目标面挖掘（战略优先级 T1>T2>T3）

### T1 SSL VPN 网管 ×4（access/bigdata/em/portal）
- 指纹：国产 VPN 网管 wnm 管理面（Metronic 模板 + AES 前端加密 + Server: HTTPD）
- **瓶颈：全部静态资源被网关 400 拦截，版本不可见** → 无法精确核对已知 CVE
- 未做登录爆破/伪造（遵守授权边界）
- 结论：**recon-limited**

### T2 info Nuxt 资料中心 ⭐ 最有价值产出
- 从 entry.js (1.2MB) 提取 **27 个 v1 API 端点**完整清单：
  - 认证类：login/register/refresh/logout/verify-email/resetpassword/change-password/send-code
  - 资料类：files/files-search/download/products/detail/relation/comment
  - 用户类：personal/favorites/likes/avatar
- **但所有 /v1/* 与 /api/common/upload 当前被 nginx catch-all 返回 SPA HTML(3106B)** → API 服务器未暴露（可能仅内网或维护中）
- **证书过期发现**: *.sunoasis.com.cn 通配符证书 2026-08-23 已过期（DigiCert）
- 结论：API 面已测绘，**待 API 恢复可达即为完整攻击面**

### T3 www 官网 /search/
- **WAF 字符黑名单确认**：keyword 含 `' " ; ( % | < > &#39; %u0027 %df%27 %2527` → 404 phpstudy 模板(1524B)；正常字符/反斜杠/tab/换行/反引号/%a0/%c0%a7 → 正常搜索(31KB)
- 404 页泄露 **phpstudy** 品牌模板（服务器指纹）
- 结论：WAF 规则有效，常规编码无法绕过，**无可注入点**

## 三、发现清单
| ID | 类型 | 定级 | 状态 |
|---|---|---|---|
| S1-1 | info 证书过期（2026-08-23） | info | confirmed |
| S1-2 | www 404 页泄露 phpstudy 品牌 | info | confirmed |
| S1-3 | info 27 个 API 端点清单（API 暂不可达） | info | reproduced |
| S1-4 | www /search/ WAF 字符黑名单（404 伪装） | info | reproduced |
| S1-5 | VPN 网管 ×4 同批次指纹（版本不可见） | info | recon-limited |

## 四、待后续轮
1. **info API 恢复监控**（27 端点随时可用）
2. **浏览器级渲染**观察前端真实 API 调用（若调外部/内网域直接暴露）
3. VPN 网管版本探针换思路（JS 渲染后行为）
