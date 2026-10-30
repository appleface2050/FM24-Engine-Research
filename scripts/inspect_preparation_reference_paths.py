"""从原PE重建准备函数的本地分支图，定位球员引用写入后的待查调用。"""

import argparse
import json
import re
import subprocess
from pathlib import Path

from verify_goal_lifecycle import verify_target_identity


ROOT = Path(__file__).resolve().parents[1]
ENTRY = 0x1443C1691  # 已通过“旧球员引用不等于本次P”的入口检查。
CLEAR = 0x1443C47A5  # 清除比赛标志的末段入口。
WRITES = {0x1443C379B, 0x1443C39CB, 0x1443C4460}


def walk(starts, graph, blocked=()):
    """遍历本地分支；不解释条件真假、被调函数或异常退出。"""
    seen, pending = set(), list(starts)
    while pending:
        address = pending.pop()
        if address in seen or address in blocked:
            continue
        seen.add(address)
        pending.extend(graph[address])
    return seen


def inspect(exe: Path):
    """核对既有目标身份，重新解码全部本地分支并检查写入集合是否必经。"""
    identity = json.loads((ROOT / "20261019_fm24_target_identity.json").read_text())
    verify_target_identity(exe.read_bytes(), identity)
    output = subprocess.check_output([
        "objdump", "-d", "-Mintel", "--insn-width=16",
        "--start-address=0x1443c1640", "--stop-address=0x1443c4eeb", str(exe),
    ], text=True)
    rows = {}
    for line in output.splitlines():
        match = re.match(
            r"^\s*([0-9a-f]+):\s*([0-9a-f]{2}(?: [0-9a-f]{2})*)\s+(.+)$", line
        )
        if match:
            rows[int(match[1], 16)] = (len(bytes.fromhex(match[2])), match[3].strip())
    graph = {}
    for address, (size, instruction) in rows.items():
        if "(bad)" in instruction or ".byte" in instruction:
            raise ValueError(f"Undecoded instruction at {address:#x}")
        parts = instruction.split()
        op = parts[0]
        if op.startswith("j") or op.startswith("loop"):
            target = re.fullmatch(r"0x([0-9a-f]+)", parts[1])
            if not target:
                raise ValueError(f"Unresolved local branch at {address:#x}")
            graph[address] = [int(target[1], 16)]
            if op != "jmp":
                graph[address].append(address + size)
        elif op.startswith("ret") or op in {"int3", "ud2", "hlt"}:
            graph[address] = []
        else:
            graph[address] = [address + size]  # CALL只按正常返回处理。
    for address, targets in graph.items():
        if any(target not in rows for target in targets):
            raise ValueError(f"Uncovered successor at {address:#x}")
    for address in WRITES:
        instruction = re.sub(r"\s+", " ", rows[address][1])
        if instruction != "mov QWORD PTR [rax+0xe378],r12":
            raise ValueError(f"Reference write differs at {address:#x}")
    reached = walk([ENTRY], graph)
    if CLEAR not in reached or CLEAR in walk([ENTRY], graph, WRITES):
        raise ValueError("Reference write cut no longer holds; reopen the causal claim")

    reverse = {address: [] for address in rows}
    for address, targets in graph.items():
        for target in targets:
            reverse[target].append(address)
    before_clear = walk([CLEAR], reverse, WRITES)
    calls = {}
    for writer in sorted(WRITES):
        after_write = walk(graph[writer], graph, WRITES) & before_clear
        calls[hex(writer)] = [
            {"site": hex(address), "instruction": rows[address][1]}
            for address in sorted(after_write)
            if rows[address][1].startswith("call")
        ]
    return {
        "entry": hex(ENTRY), "clear_tail": hex(CLEAR),
        "decoded_instructions": len(rows),
        "clear_reachable_avoiding_all_three_writes": False,
        "calls_after_each_write_without_crossing_another_write": calls,
        "limits": [
            "All conditional branches allowed; natural reachability and termination unproved.",
            "CALL treated as normal return; callee effects and exception paths unproved.",
            "P/M identity, aliases and retention of the reference after writing remain conditional.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    print(json.dumps(inspect(parser.parse_args().exe), indent=2, ensure_ascii=False))
