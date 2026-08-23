# 补天公益 SRC 官方资产初筛

## 当前入口

```bash
cd /home/sagvil/web-vuln-mining/projects/butian-welfare-20260803
./run_pipeline.sh --help
./run_pipeline.sh batch --resume
```

- `butian_src_pipeline.py`：公开目录、登录态官方资产提取、初筛、子域证据、中筛命令。
- `run_pipeline.sh`：虚拟环境启动封装。
- `PIPELINE.zh-CN.md`：配置、登录、批次、初筛和报告说明。
- `runs/butian-src/state.sqlite`：可恢复状态与全局去重结果。
- `runs/butian-src/targets/`：每个通过初筛网址的独立证据档案。
- `runs/butian-src/archive/`：完成运行的追溯记录及压缩变更历史。

## 当前状态

- 最近完成批次：`batch-0002`，公益 SRC 第 7–12 页。
- 本轮初筛累计 `keep=5`，AI 中筛处于暂停状态。
- 下一目录页游标：第 13 页。

## 历史材料

旧版公开目录、搜索与拼音推断脚本和快照已整理到 `legacy/20260803-public-lookup/`。这些内容不代表补天官方范围，正式流程只使用登录后提交页中 `official_submit_page + scope=include` 的资产。
