"""v9.8.3 · AGENTS.md 二次瘦身（只留边界/纪律/报告标准）双向完整性测试。

安全网（v9.8.2 W3 测试演化到新保留政策）：
① 保留清单——铁律 7 条 + 报告验证门 7 问 + 终止 4 标记 + 速查卡边界条目 +
   覆盖七状态，逐条断言仍存在于瘦身后的 v3 源文件；
② 移出清单——每个被移出主题的关键词在 skillmode-reference.md 中存在（漏并即红）；
③ §7 决策树段落体积 ≤ 3.5KB；
④ v3 章节骨架（## 0.0 到 ## 11）存在且顺序不变；
⑤ v3 头部维护约定保留。

断言一律使用稳定子串/关键词，不用长散文整段匹配，避免措辞微调假红。
"""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
V3 = ROOT / "skill" / "核心技能文件.v3.md"
REFERENCE = ROOT / "skill" / "skillmode-reference.md"

SECTION7_MAX_BYTES = 3584  # 3.5KB，设计文档 M2 验收线


def _read(path):
    return path.read_text(encoding="utf-8")


def _section(text, start_marker, end_marker):
    s = text.index(start_marker)
    e = text.index(end_marker)
    return text[s:e]


# ---------------------------------------------------------------- 保留清单

def test_iron_rules_preserved():
    """§4 铁律 7 条要点逐条存在。"""
    sec = _section(_read(V3), "## 4. 铁律", "## 5. 验证门")
    for kw in [
        "不在授权范围外的任何资产上发包",
        "不执行破坏性操作",
        "不做横向扩散",
        "不外传数据",
        "不为绕过限制而伪造授权",
        "写文件只写指定临时目录",
        "不做超出取证所需的进一步利用",
    ]:
        assert kw in sec, f"铁律缺失要点: {kw}"


def test_report_gate_preserved():
    """§5 报告验证门 7 问逐条存在（测试信号门已移 reference，不在此断言）。"""
    sec = _section(_read(V3), "## 5. 验证门", "## 6. 覆盖完整性")
    assert "报告验证门" in sec
    for kw in [
        "在授权范围内吗？",
        "有完整可重现的 PoC",
        "危害是可直接演示的",
        "影响已经在 PoC 中复现了吗？",
        "可控参数 + 异常响应",
        "不懂安全的开发者能看懂危害吗？",
        "发到漏洞平台会被接受还是关闭？",
    ]:
        assert kw in sec, f"报告验证门缺问: {kw}"


def test_termination_markers_preserved():
    """§9 终止协议 4 标记存在。"""
    sec = _section(_read(V3), "## 9. 终止协议", "## 10. 防遗忘指令")
    for marker in ["VULN_FOUND", "LOW_ROI", "NEED_INPUT", "ERROR"]:
        assert marker in sec, f"终止协议缺标记: {marker}"


def test_quick_card_boundary_items_preserved():
    """§3 速查卡只保留边界/报告标准条目，逐条存在。"""
    sec = _section(_read(V3), "## 3. 速查卡", "## 4. 铁律")
    for kw in [
        "CORS ≠ 漏洞",
        "登录墙 ≠ 停手",
        "状态码 200 ≠ 业务漏洞",
        "只报「已证明」",
        "报告必须带 curl",
        "物理证据 > 自我声明",
        "越界即停",
        "一等攻击面",
    ]:
        assert kw in sec, f"速查卡缺边界条目: {kw}"


def test_coverage_seven_states_preserved():
    """§6 覆盖七状态值全部存在。"""
    sec = _section(_read(V3), "## 6. 覆盖完整性", "## 7. 决策树")
    for status in [
        "not_tested",
        "confirmed",
        "not_vulnerable",
        "shallow_negative",
        "blocked",
        "not_applicable",
        "exploring",
    ]:
        assert status in sec, f"覆盖七状态缺失: {status}"


def test_coverage_disciplines_preserved():
    """§6 代码绑定的覆盖纪律保留：实验有效性门 / 高价值格 / LOW_ROI 条件 / 阻塞分类。"""
    sec = _section(_read(V3), "## 6. 覆盖完整性", "## 7. 决策树")
    for kw in [
        "coverage-ledger.json",
        "实验有效性门",
        "barrier_signals",
        "高价值格不得空白",
        "LOW_ROI",
        "超过 5 个 not_tested 高价值",
        "阻塞要分类",
        "captcha/SMS/2FA 不是阻塞条件",
        "depth_floor",
        "proof_ready",
    ]:
        assert kw in sec, f"§6 缺纪律: {kw}"


# ---------------------------------------------------------------- 移出清单

def test_moved_topics_landed_in_reference():
    """每个移出主题的关键词必须在 skillmode-reference.md 中存在（漏并即红）。"""
    ref = _read(REFERENCE)
    topics = {
        "SQLi 上下文清单": ["等值查询", "LIKE 模糊查询", "ORDER BY", "DBMS"],
        "payload 编码变体": ["双重 URL 编码", "Unicode"],
        "WAF 绕过技术": ["传输层绕过", "解析层绕过", "盲注"],
        "密码重置方向清单": ["验证码回显", "步骤跳过", "可控目标"],
        "用户枚举三通道": ["用户枚举", "消息差异", "时间差异", "行为差异"],
        "业务逻辑 6 模式": ["竞态条件", "支付回调伪造", "响应篡改"],
        "端点变体推测": ["端点变体", "兄弟端点"],
        "验证码绕过方向清单": ["通用码", "字段省略", "逻辑跳步", "验证码绑用户"],
        "存储型闭环": ["存储型", "闭环"],
        "链式评估": ["chain_assessment"],
        # v9.8.3 二次瘦身新移出主题
        "测试信号门": ["测试信号门", "响应有可观察的异常吗？", "这个异常能链接到具体危害吗？"],
        "depth floor 细则": ["弹性 depth floor", "快速确认", "阴性 depth floor"],
        "跨阶段阴性重测": ["编码族", "策略族"],
        "速查卡方法论": ["假阴性陷阱", "替换 ID 至少 3-5 个", "响应异常嗅探", "Content-Type"],
        "数据预备与聚合缝隙": ["数据预备", "seam_gap"],
        "引擎合同附录": ["引擎合同附录", "dead_ends.json", "js_ref", "execution-contracts.json"],
    }
    for topic, keywords in topics.items():
        for kw in keywords:
            assert kw in ref, f"移出主题未并入 reference: {topic} (缺关键词 {kw})"


# ---------------------------------------------------------------- §7 体积与内容

def test_section7_size_within_budget():
    """v3 中 §7 段落（## 7. 标题到 ## 8. 之前）≤ 3.5KB。"""
    v3 = _read(V3)
    sec = _section(v3, "## 7. 决策树", "## 8. 漏洞确立证据链")
    size = len(sec.encode("utf-8"))
    assert size <= SECTION7_MAX_BYTES, f"§7 体积 {size}B 超过 {SECTION7_MAX_BYTES}B 预算"


def test_section7_kept_disciplines_and_pointers():
    """§7 瘦身后仍保留：路由表、量化门槛、纪律原则与触发式指针。"""
    sec = _section(_read(V3), "## 7. 决策树", "## 8. 漏洞确立证据链")
    for kw in [
        # 参数语义 → risk_tag 路由表（保留内联）
        "amount-tamper", "time-tamper", "idor", "redirect-chain",
        "ssrf", "file-upload", "input-validation", "privilege",
        # 保留的纪律原则
        "无凭据黑盒协议",
        "二次验证绕过优先协议",
        "≥5",                      # 穷尽 ≥5 个方向的量化门槛（M4 不删数字）
        "SQLi 与 IDOR 是独立测试面",
        "匿名 200 ≠ 未授权",
        "Intent",
        # 触发式指针
        "skillmode-reference.md",
        "§密码重置", "§验证码绕过",
        "§SQL 注入", "§WAF", "§链式利用评估", "§端点变体", "§攻击模式库",
    ]:
        assert kw in sec, f"§7 保留项缺失: {kw}"


# ---------------------------------------------------------------- 结构与维护约定

def test_section_skeleton_order():
    """v3 章节骨架（## 0.0 到 ## 11）全部存在且顺序不变。"""
    headings = [
        "## 0.0 ", "## 0.1 ", "## 0.2 ", "## 0.3 ", "## 0.4 ",
        "## 0. Phase 0",
        "## 1. 垃圾洞清单", "## 2. 灵魂金句", "## 3. 速查卡",
        "## 4. 铁律", "## 5. 验证门", "## 6. 覆盖完整性",
        "## 7. 决策树", "## 8. 漏洞确立证据链", "## 8.5 ",
        "## 9. 终止协议", "## 10. 防遗忘指令", "## 11. Skill Mode 自检查清单",
    ]
    pos = -1
    text = _read(V3)
    for h in headings:
        marker = "\n" + h
        idx = text.find(marker, pos + 1)
        assert idx != -1, f"章节标题缺失或顺序错误: {h.strip()}"
        assert idx > pos, f"章节顺序错误: {h.strip()}"
        pos = idx


def test_maintenance_convention_in_header():
    """v3 头部引言区含维护约定（新增规则先分类；本文件只减不增方法论）。"""
    v3 = _read(V3)
    head = v3[: v3.index("## 0.0")]
    assert "本文件只减不增方法论" in head, "v3 头部缺维护约定"
    assert "skillmode-reference.md" in head, "维护约定未指向 reference/知识卡"
