"""
Codex 适配器 —— 把 `codex exec` 包成 orchestrator.py 需要的 ModelAdapter。

这是"模型无关"的唯一耦合点：编排外壳（计时器 / 50轮重启 / 外部强制 / PoC重放 / 认知状态）
全部与模型无关；换模型只换这个文件。Codex 在这里扮演"带 shell 的 Agent 运行时"。

用法：
    from codex_adapter import CodexAdapter
    adapter = CodexAdapter(model="gpt-5.5-codex", workdir="runs/sess-xxx")
    for chunk in adapter.run(prompt, session_id="sess-xxx"):
        ...   # 交给 orchestrator 的强制层/解析层

依赖：codex CLI 在 PATH（已确认 codex-cli 0.131.0 可用）。
注意：实际 flag 名以 `codex exec --help` 为准，不同版本可能不同；下方按通用语义给出。
"""
import os
import subprocess
from typing import Iterator


class CodexAdapter:
    name = "codex"

    def __init__(self, model: str = "gpt-5.5-codex", workdir: str = ".",
                 allow_hosts: list[str] | None = None):
        self.model = model
        self.workdir = workdir
        # host 白名单：Codex 沙箱不做 host 级限制，所以这里建议配合一个
        # 本地出站代理（如 mitmproxy/自写转发）只放行 allow_hosts，把"授权范围"硬约束落到网络层。
        self.allow_hosts = allow_hosts or []

    def run(self, prompt: str, *, session_id: str) -> Iterator[str]:
        wd_abs = os.path.abspath(self.workdir)
        cmd = [
            "codex", "exec",
            "--skip-git-repo-check",             # 工作区可能非 git 仓库（runs/ 下）
            "-m", self.model,
            "--sandbox", "workspace-write",      # 硬约束地板：只能写工作区
            # 网络出站：workspace-write 默认关网，必须显式开，否则模型 curl 不到靶场。
            # ⚠ 这会放开「全部」出站，不止 allow_hosts；授权范围收口仍需配合出站代理。
            "-c", "sandbox_workspace_write.network_access=true",
            # 写盘收口：默认还放开 /tmp、$TMPDIR，模型会把证据写到工作目录外、采集层看不到
            # （合格报告被漏判 low_roi）。把可写根钉死为本会话目录，机制上消除目录漂移。
            "-c", f'sandbox_workspace_write.writable_roots=["{wd_abs}"]',
            "--cd", self.workdir,                # 证据落在本会话目录
            "-",                                 # 从 stdin 读 prompt
        ]
        # 注：codex exec(0.131)无 `--ask-for-approval`，非交互默认 approval=never；
        # “危险命令打断”由 orchestrator 的 hits_danger() 流式拦截兜底。
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        assert proc.stdin and proc.stdout
        proc.stdin.write(prompt)
        proc.stdin.close()
        for line in proc.stdout:          # 流式回吐，orchestrator 实时做危险命令拦截
            yield line
        proc.wait()


# ── 与 orchestrator 的对接（伪代码，仅示意） ──────────────────────
if __name__ == "__main__":
    import sys, pathlib
    sid = "sess-demo"
    wd = pathlib.Path("runs") / sid
    wd.mkdir(parents=True, exist_ok=True)
    (wd / "authz.md").write_text("# 授权范围\n- 仅限：https://target.example\n", encoding="utf-8")
    adapter = CodexAdapter(model="gpt-5.5-codex", workdir=str(wd),
                           allow_hosts=["target.example"])
    # 真实使用时由 orchestrator.assemble_prompt() 拼装；这里直接喂一段
    prompt = sys.stdin.read() if not sys.stdin.isatty() else "对 https://target.example 做授权 SRC 测试，先告诉我首个攻击面。"
    for chunk in adapter.run(prompt, session_id=sid):
        print(chunk, end="")
