# v8.6 三Agent协作任务书 — Test-First闭环修复

> 原则：不是三个独立coding prompt，是一个小型集成项目。
> 合约测试必须先 FAIL，再修复，否则"看起来完成"但实际未验证。

## 当前v8.6缺陷清单（7项）

| # | 缺陷 | 文件 | 严重度 |
|---|------|------|--------|
| D1 | `BusinessGraph.flows` schema 与 `scheduler._flow_completion_endpoints` 不匹配：scheduler 读 `flow.get("steps")` 但 graph 产 `{"object":obj,"endpoints":keys}` | business_graph.py / scheduler.py | P0 |
| D2 | `BusinessGraph.endpoint_map` 无 `"value"` 字段，scheduler tier-2 排序全部退化为 medium | business_graph.py / scheduler.py | P0 |
| D3 | `domains_covered` 和 `surface_index` 在 blackboard v2 schema 中声明但从未被填充 | orchestrator.py / graph.py | P1 |
| D4 | `scheduler_stats` 未在 orchestrator 输出中设置，run.py 读取时始终为空 | orchestrator.py | P1 |
| D5 | `low_roi_advisory` 未接入终止逻辑，PLAN要求"高价值节点未测时LOW_ROI无效" | orchestrator.py | P1 |
| D6 | `run_summary.md` 从未生成，PLAN Section 7 明确要求 | orchestrator.py / run.py | P1 |
| D7 | `run.py:1091` 拼写错误 `AssertionError` — Python内置应为 `AssertionError` | run.py | P2 |

## 执行顺序

### Phase 0 — 环境准备（已完成）
- [x] 从 main (263d388) 创建 v8.6-fix 分支

### Phase 1 — Agent C: 合约测试（必须先FAIL）

创建 `tests/` 目录，编写以下测试文件。**在 v8.6 当前代码上运行，必须全部 FAIL。**

```
tests/
  conftest.py                     # pytest fixtures: mock inventory, mock facts, temp dirs
  test_business_graph.py          # D1+D2: value字段 + flows schema
  test_scheduler_integration.py   # D1+D2: tier-2排序 + tier-3 flow completion
  test_blackboard_population.py   # D3: domains_covered + surface_index 被填充
  test_orchestrator_output.py     # D4+D5+D6: scheduler_stats + low_roi + run_summary.md
  test_run_assertions.py          # D7: AssertionError typo
```

**每个测试必须：**
1. 独立可运行（不依赖真实靶场）
2. 使用 mock/fixture 数据
3. 在 v8.6 当前代码上 pytest 结果为 FAIL
4. 修复后 pytest 结果为 PASS
5. 测试逻辑清晰，注释说明对应哪个缺陷编号

**Phase 1 完成标准：**
```bash
cd C:/claw/Atoolkit
python -m pytest tests/ -v
# 结果：所有测试 FAIL（红色），无 ERROR（报错 ≠ 断言失败）
```

### Phase 2 — Agent A + Agent B 并行修复

**Agent A 负责（数据层 + 报告）：**

| 缺陷 | 修复内容 |
|------|----------|
| D3 | orchestrator 中填充 `domains_covered`（domain→已测/总数）和 `surface_index`（endpoint→domain映射）写入 blackboard |
| D6 | 在 `_conclude` 或 run 结束时生成 `run_summary.md`（统计+findings+intents+negatives） |
| D7 | run.py:1091 `AssertionError` → `AssertionError` |

Agent A 不改的文件：`business_graph.py`, `scheduler.py`

**Agent B 负责（引擎层 + 集成）：**

| 缺陷 | 修复内容 |
|------|----------|
| D1 | 统一 `BusinessGraph.flows` schema 为 `{"object":obj,"steps":[{"endpoint":k,"order":i}],"domain":d}` 或修改 scheduler 适配当前 schema |
| D2 | `BusinessGraph` 在 `build_from_inventory` 时为每个 endpoint 推断并写入 `"value"` 字段（high/medium/low） |
| D4 | orchestrator 在 compute_run_scope 后保存 `scheduler_stats` 到输出 dict |
| D5 | 终止逻辑中调用 `biz_graph.low_roi_advisory()`，高价值未测时阻止 LOW_ROI 早退 |

Agent B 不改的文件：`run.py`（除通过 orchestrator 间接影响）

**冲突规则：**
- `orchestrator.py` 是共享文件。Agent A 改 domains_covered/surface_index 填充 + run_summary 生成。Agent B 改 scheduler_stats 保存 + low_roi_advisory 调用。
- 两人改 orchestrator.py 的不同区域，Agent B 后合入并处理冲突。

**Phase 2 完成标准：**
```bash
python -m pytest tests/ -v
# 结果：所有测试 PASS（绿色）
python run.py --self-check
# 结果：19/19 assertions pass
```

### Phase 3 — 集成验证

1. Agent A 和 B 的代码合入 v8.6-fix 分支
2. 跑全量合约测试
3. 跑 `--self-check`
4. 跑双轮 dry-run 验证 blackboard 继承
5. 确认 `business_graph.json`、`run_scope.json`、`run_summary.md` 均被生成
