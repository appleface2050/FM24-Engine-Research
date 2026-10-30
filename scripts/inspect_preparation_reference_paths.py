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


def decode_graph(exe: Path, start: int, end: int, *, external_stops=()):
    """解码本地条件边；CALL接正常返回，显式外部尾跳仅作边界节点。"""
    output = subprocess.check_output([
        "objdump", "-d", "-Mintel", "--insn-width=16",
        f"--start-address={start:#x}", f"--stop-address={end:#x}", str(exe),
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
    outside = {target for targets in graph.values() for target in targets if target not in rows}
    if outside - set(external_stops):
        raise ValueError(f"Uncovered successors: {sorted(hex(address) for address in outside)}")
    # 明确列出的外部边只作边界节点，不伪装为已分析的原生指令。
    for address in outside:
        rows[address] = (0, "external_boundary")
        graph[address] = []
    return rows, graph


def inspect(exe: Path):
    """核对目标身份和引用写入必经关系，定位正常路径上必须处理的子调用。"""
    identity = json.loads((ROOT / "20261019_fm24_target_identity.json").read_text())
    verify_target_identity(exe.read_bytes(), identity)
    rows, graph = decode_graph(exe, 0x1443C1640, 0x1443C4EEB)
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
    calls, mandatory = {}, {}
    for writer in sorted(WRITES):
        suffix = walk(graph[writer], graph, WRITES)
        if CLEAR not in suffix:
            raise ValueError(f"Selected suffix is unreachable after {writer:#x}")
        after_write = suffix & before_clear
        calls[hex(writer)] = [
            {"site": hex(address), "instruction": rows[address][1]}
            for address in sorted(after_write)
            if rows[address][1].startswith("call")
        ]
        mandatory[hex(writer)] = [
            call for call in calls[hex(writer)]
            if CLEAR not in walk(graph[writer], graph, WRITES | {int(call["site"], 16)})
        ]

    cache_rows, cache_graph = decode_graph(exe, 0x1443BC460, 0x1443BE43A)
    cache_entry, valid_write, epilogue = 0x1443BC4A2, 0x1443BE080, 0x1443BE088
    if (epilogue not in walk([cache_entry], cache_graph)
            or epilogue in walk([cache_entry], cache_graph, {valid_write})):
        raise ValueError("Cache computation can bypass valid write; reopen second-call claim")
    expected = {
        0x1443C418E: "mov BYTE PTR [r12+0x1870],0x0",
        0x1443C419A: "call 0x1443bc460",
        0x1443C41A7: "cmp BYTE PTR [r12+0x1870],0x0",
        0x1443C41B0: "jne 0x1443c41ba",
        valid_write: "mov BYTE PTR [r13+0x1870],0x1",
    }
    for address, instruction in expected.items():
        source = cache_rows if address == valid_write else rows
        if re.sub(r"\s+", " ", source[address][1]) != instruction:
            raise ValueError(f"Cache caller/write differs at {address:#x}")

    history_checks = {
        0x1443BD325: "mov eax,DWORD PTR [r13+0xf10]",
        0x1443BD32C: "lea ecx,[rax-0x49]",
        0x1443BD32F: "cmp ecx,0x6",
        0x1443BD332: "jb 0x1443bd34e",
        0x1443BD334: "add eax,0xffffffb8",
        0x1443BD337: "cmp eax,0x8",
        0x1443BD33A: "ja 0x1443bd4a5",
        0x1443BD38B: "call 0x1443ee610",
    }
    for address, instruction in history_checks.items():
        if re.sub(r"\s+", " ", cache_rows[address][1]) != instruction:
            raise ValueError(f"Cache history branch differs at {address:#x}")
    without_history_load = walk([cache_entry], cache_graph, {0x1443BD325})
    if {0x1443BD332, 0x1443BD33A} & without_history_load:
        raise ValueError("History branches can bypass the checked field load")
    history_90 = dict(cache_graph)
    history_90[0x1443BD332] = [0x1443BD334]  # uint32(0x90-0x49)>=6。
    history_90[0x1443BD33A] = [0x1443BD4A5]  # uint32(0x90-0x48)>8。
    if 0x1443BD38B in walk([cache_entry], history_90):
        raise ValueError("Ball query still reachable under history 0x90 branches")
    record_bindings = {
        0x1443BD842: (0x1443BD854, 0x1443BD8BE, 0x1443BD92A,
                       0x1443BD9B8, 0x1443BDA34),
        0x1443BDA29: (0x1443BDF62, 0x1443BE2B3, 0x1443BE3E0),
    }
    for address, instruction in {
        0x1443BD842: "lea rbx,[r13+0xc40]",
        0x1443BDA29: "mov QWORD PTR [rsp+0x80],rbx",
    }.items():
        if re.sub(r"\s+", " ", cache_rows[address][1]) != instruction:
            raise ValueError(f"Record container binding differs at {address:#x}")
    for binding, sites in record_bindings.items():
        if set(sites) & walk([cache_entry], cache_graph, {binding}):
            raise ValueError(f"Record query can bypass binding at {binding:#x}")
    position_rows, position_graph = decode_graph(exe, 0x1443B61F0, 0x1443B6881)
    position_conditions = {
        0x1443B6228: ("je 0x1443b624f", 0x1443B624F),
        0x1443B6500: ("je 0x1443b652f", 0x1443B652F),
        0x1443B63D0: ("jne 0x1443b6698", 0x1443B63D6),
    }
    selected_position_graph = dict(position_graph)
    for address, (instruction, successor) in position_conditions.items():
        if re.sub(r"\s+", " ", position_rows[address][1]) != instruction:
            raise ValueError(f"Position-state gate differs at {address:#x}")
        selected_position_graph[address] = [successor]
    selected_position = walk([0x1443B61F0], selected_position_graph)
    selected_calls = [
        {"site": hex(address), "instruction": position_rows[address][1]}
        for address in sorted(selected_position)
        if position_rows[address][1].startswith("call")
    ]
    if {int(call["site"], 16) for call in selected_calls} != {0x1443B6361, 0x1443B6398}:
        raise ValueError("Additional position helper remains reachable under selected gates")
    reset_suffix_graph = dict(graph)
    for address, (instruction, successor) in {
        0x1443C3A7A: ("je 0x1443c3b9b", 0x1443C3B9B),
        0x1443C3C05: ("je 0x1443c3d69", 0x1443C3D69),
        0x1443C3D85: ("je 0x1443c3ec8", 0x1443C3EC8),
        0x1443C4095: ("jg 0x1443c418e", 0x1443C418E),
    }.items():
        if re.sub(r"\s+", " ", rows[address][1]) != instruction:
            raise ValueError(f"Reset suffix gate differs at {address:#x}")
        reset_suffix_graph[address] = [successor]
    reset_suffix = walk([0x1443C3A5F], reset_suffix_graph, {0x1443C419A})
    reset_suffix_calls = [
        hex(address) for address in sorted(reset_suffix)
        if rows[address][1].startswith("call")
    ]
    if reset_suffix_calls != ["0x1443c3ecd"]:
        raise ValueError("Unexpected reset-to-cache call under selected conditions")
    if not any(0x1443C419A in reset_suffix_graph[address] for address in reset_suffix):
        raise ValueError("Selected reset suffix no longer reaches the first cache call")

    update_rows, update_graph = decode_graph(exe, 0x1443B5100, 0x1443B6156)
    update_reached = walk([0x1443B5100], update_graph)
    update_calls = {
        hex(address): update_rows[address][1]
        for address in sorted(update_reached)
        if update_rows[address][1].startswith("call")
    }
    if set(update_calls) != {
        "0x1443b5239", "0x1443b525f", "0x1443b532a", "0x1443b535a",
        "0x1443b5378", "0x1443b5bbb", "0x1443b5c77", "0x1443b603b",
    }:
        raise ValueError("Position update has an unreviewed reachable call")
    if 0x1443B605B in walk([0x1443B5100], update_graph, {0x1443B600C}):
        raise ValueError("Indirect scalar store bypasses its player-field address binding")
    judgment_sites = (0x1443BDC2A, 0x1443BE128, 0x1443BE166,
                      0x1443BE20C, 0x1443BE424)
    for address in judgment_sites:
        if re.sub(r"\s+", " ", cache_rows[address - 3][1]) != "xor r9d,r9d":
            raise ValueError(f"Cache judgment time argument differs at {address:#x}")
    judgment_rows, judgment_graph = decode_graph(exe, 0x1443C54B0, 0x1443C5919)
    for address, successor in ((0x1443C564D, 0x1443C5689),
                               (0x1443C57EA, 0x1443C5860)):
        if re.sub(r"\s+", " ", judgment_rows[address][1]) != f"jbe {successor:#x}":
            raise ValueError(f"Zero-time judgment branch differs at {address:#x}")
        judgment_graph[address] = [successor]
    judgment_reached = walk([0x1443C54B0], judgment_graph)
    judgment_calls = [
        hex(address) for address in sorted(judgment_reached)
        if judgment_rows[address][1].startswith("call")
    ]
    if judgment_calls != ["0x1443c57e1"]:
        raise ValueError("Zero-time judgment retains an unreviewed call")
    cache_call_targets = sorted({
        cache_rows[address][1].split()[-1]
        for address in walk([cache_entry], cache_graph)
        if cache_rows[address][1].startswith("call")
    })
    if cache_call_targets != sorted({
        "0x141b4a970", "0x141b40bd0", "0x141b408e0", "0x141b42f50",
        "0x141b41670", "0x1443ee610", "0x14557e9b0", "0x14557ea20",
        "0x1443c54b0", "0x1443f7d90",
    }):
        raise ValueError("Cache has a call target outside the reviewed set")
    return_graph = dict(graph)
    for address, (instruction, successor) in {
        0x1443C41B0: ("jne 0x1443c41ba", 0x1443C41BA),
        0x1443C421F: ("je 0x1443c437a", 0x1443C4225),
        0x1443C42F8: ("jne 0x1443c4599", 0x1443C4599),
        0x1443C45DB: ("jne 0x1443c46ca", 0x1443C46CA),
        0x1443C46D4: ("je 0x1443c4713", 0x1443C4713),
    }.items():
        if re.sub(r"\s+", " ", rows[address][1]) != instruction:
            raise ValueError(f"Preparation return gate differs at {address:#x}")
        return_graph[address] = [successor]
    return_reached = walk([0x1443C419F], return_graph)
    if any(rows[address][1].startswith("call") for address in return_reached):
        raise ValueError("Preparation return suffix still has a reachable call")
    if (0x1443C47FE not in return_reached
            or 0x1443C47FE in walk([0x1443C419F], return_graph, {0x1443C47A5})):
        raise ValueError("Preparation return no longer crosses the clear tail")
    if 0x1443C39CB in walk([ENTRY], graph, {0x1443C181F}):
        raise ValueError("Second reference write can bypass the parameter save")
    roster_rows, roster_graph = decode_graph(exe, 0x141B42780, 0x141B42F46)
    for address, (instruction, successor) in {
        0x141B42B02: ("ja 0x141b42c93", 0x141B42B08),
        0x141B42DB0: ("jg 0x141b42e72", 0x141B42DB6),
    }.items():
        if re.sub(r"\s+", " ", roster_rows[address][1]) != instruction:
            raise ValueError(f"Small roster sort bound differs at {address:#x}")
        roster_graph[address] = [successor]
    roster_reached = walk([0x141B42780], roster_graph)
    roster_calls = [
        hex(address) for address in sorted(roster_reached)
        if roster_rows[address][1].startswith("call")
    ]
    if roster_calls != ["0x141b42791", "0x141b42904", "0x141b42b4c",
                         "0x141b42d8d", "0x141b42dec"]:
        raise ValueError("Small roster query retains another subcall")
    context_rows, context_graph = decode_graph(exe, 0x14441A3B0, 0x14441FFE1)
    for address, (instruction, successor) in {
        0x14441A4DB: ("jbe 0x14441a4f8", 0x14441A4F8),
        0x14441AF4C: ("jbe 0x14441af6a", 0x14441AF4E),
    }.items():
        if re.sub(r"\s+", " ", context_rows[address][1]) != instruction:
            raise ValueError(f"Near-context producer branch differs at {address:#x}")
        context_graph[address] = [successor]
    context_prefix = walk([0x14441A3B0], context_graph, {0x14441AF65})
    context_calls = [
        hex(address) for address in sorted(context_prefix)
        if context_rows[address][1].startswith("call")
    ]
    if context_calls != ["0x14441a661", "0x14441a68b", "0x14441a6bc",
                          "0x14441a78d", "0x14441af2c"]:
        raise ValueError("Near-context prefix retains another subcall")
    if not any(0x14441AF65 in context_graph[address] for address in context_prefix):
        raise ValueError("Near-context producer checkpoint is unreachable")
    # 仅取AF65出发且正常能到BE35的路径，不把其他出口隐式排除为不可达。
    later_graph = {address: list(targets) for address, targets in context_graph.items()}
    for address, instruction, successor in (
        (0x14441B164, "jbe 0x14441b919", 0x14441B919),
        (0x14441B60B, "jne 0x14441b615", 0x14441B615),
        (0x14441B62B, "je 0x14441b925", 0x14441B631),
    ):
        if re.sub(r"\s+", " ", context_rows[address][1]) != instruction:
            raise ValueError(f"Later context condition differs at {address:#x}")
        later_graph[address] = [successor]
    later_reverse = {address: [] for address in later_graph}
    for address, targets in later_graph.items():
        for target in targets:
            later_reverse[target].append(address)
    later_prefix = (walk([0x14441AF65], later_graph, {0x14441BE35})
                    & walk([0x14441BE35], later_reverse))
    later_calls = [hex(address) for address in sorted(later_prefix)
                   if context_rows[address][1].startswith("call")]
    if later_calls != ["0x14441b039", "0x14441ba1a", "0x14441bb75",
                       "0x14441bb84", "0x14441bd76", "0x14441bd9b"]:
        raise ValueError("Later context prefix retains an unreviewed subcall")
    for required in (0x14441B076, 0x14441BD9B):
        if required not in later_prefix:
            raise ValueError("Flag clearing or uncached-speed call was lost from coverage")
    leaf_rows, leaf_graph = decode_graph(exe, 0x141B47A60, 0x141B4806A)
    if any(row[1].startswith("call") for row in leaf_rows.values()):
        raise ValueError("Context boolean helper now contains a subcall")
    speed_rows, speed_graph = decode_graph(exe, 0x1443F9200, 0x1443F9320)
    speed_calls = [hex(address) for address in sorted(walk([0x1443F9200], speed_graph))
                   if speed_rows[address][1].startswith("call")]
    if speed_calls != ["0x1443f9269"]:
        raise ValueError("Speed recomputation has another unreviewed call")
    getter_rows, getter_graph = decode_graph(exe, 0x141B62DC0, 0x141B62DEF)
    if re.sub(r"\s+", " ", getter_rows[0x141B62DD3][1]) != "jne 0x141b62ddd":
        raise ValueError("Player cache getter valid branch differs")
    getter_graph[0x141B62DD3] = [0x141B62DDD]  # 同一P+1870=1。
    if any(getter_rows[address][1].startswith("call")
           for address in walk([0x141B62DC0], getter_graph)):
        raise ValueError("Valid player cache getter can still recompute")
    gate_rows, gate_graph = decode_graph(exe, 0x144448FB0, 0x14444931E)
    gate_calls = {address: row[1] for address, row in gate_rows.items()
                  if row[1].startswith("call")}
    if (sum(value == "call   0x1443b3fc0" for value in gate_calls.values()) != 8
            or gate_calls.get(0x144449128) != "call   0x1443b9140"
            or len(gate_calls) != 9):
        raise ValueError("Attribute gate subcall boundary differs")
    state_rows, state_graph = decode_graph(exe, 0x1443B9140, 0x1443BB231)
    if re.sub(r"\s+", " ", state_rows[0x1443B91A2][1]) != "jne 0x1443b9254":
        raise ValueError("State query flag branch differs")
    state_graph[0x1443B91A2] = [0x1443B91A8]  # 同一P+16f8 bit0=0。
    state_reached = walk([0x1443B9140], state_graph)
    if 0x1443B932A in state_reached:
        raise ValueError("State query still reaches motion-producing helper")
    state_targets = sorted({state_rows[address][1].split()[1]
                            for address in state_reached
                            if state_rows[address][1].startswith("call")})
    if state_targets != sorted([
        "0x141a9b4a0", "0x141b40bd0", "0x141b41670", "0x141b419b0",
        "0x141b41ab0", "0x141b45fe0", "0x141b460a0", "0x141b461a0",
        "0x141b462a0", "0x141b47470", "0x141b47820", "0x141b57800",
        "0x1443bc460", "0x1443f7c80", "0x1443f7d90", "0x1443fd280",
    ]):
        raise ValueError("State query has an unreviewed target")
    state_keys = sorted(state_rows)
    for address in state_reached:
        if state_rows[address][1] != "call   0x1443bc460":
            continue
        index = state_keys.index(address)
        binding = [item for item in state_keys[max(0, index - 3):index]
                   if state_rows[item][1] == "mov    rcx,r14"]
        if not binding or address in walk([0x1443B9140], state_graph, binding):
            raise ValueError(f"State query cache call lacks same-P binding at {address:#x}")
    for call, binding in ((0x1443BA3B6, 0x1443BA3AE),
                          (0x1443BA3ED, 0x1443BA3E5),
                          (0x1443BA6BA, 0x1443BA6B2),
                          (0x1443B9B89, 0x1443B9B7E),
                          (0x1443BA7D3, 0x1443BA7CB)):
        if state_rows[binding][1] != "lea    rdx,[rsp+0x30]":
            raise ValueError("State query scalar output is no longer a stack slot")
        if call in walk([0x1443B9140], state_graph, {binding}):
            raise ValueError("State query scalar output binding can be bypassed")
    for call, binding in ((0x1443BAD6E, 0x1443BAD6B),
                          (0x1443BB0D0, 0x1443BB0CD),
                          (0x1443BB209, 0x1443BB206)):
        if state_rows[binding][1] != "xor    r9d,r9d":
            raise ValueError("Angle helper optional write pointer is no longer null")
        if call in walk([0x1443B9140], state_graph, {binding}):
            raise ValueError("Angle helper null-output binding can be bypassed")
    # 不要求入口命中缓存；检查未命中时正常返回必须经过有效位写点之一。
    cold_graph = {address: list(targets) for address, targets in state_graph.items()}
    if re.sub(r"\s+", " ", state_rows[0x1443B9188][1]) != "je 0x1443b919a":
        raise ValueError("State query cold-entry branch differs")
    cold_graph[0x1443B9188] = [0x1443B919A]
    avoiding_valid_writes = walk([0x1443B9140], cold_graph,
                                {0x1443B988A, 0x1443B9ABB, 0x1443BB224})
    if any(state_rows[address][1].startswith("ret") for address in avoiding_valid_writes):
        raise ValueError("Cold state query can return without setting its valid flag")
    state_leaves = (
        (0x141B47820, 0x141B4792C), (0x141B47470, 0x141B4756A),
        (0x141B460A0, 0x141B46115), (0x141B45FE0, 0x141B4603B),
        (0x141B462A0, 0x141B46315), (0x141B461A0, 0x141B46215),
        (0x141B57800, 0x141B57846), (0x141B419B0, 0x141B41AA1),
        (0x141B41AB0, 0x141B41B25), (0x1443F7C80, 0x1443F7D8B),
        (0x141A9B4A0, 0x141A9B584), (0x1443FD280, 0x1443FD36A),
    )
    for start, end in state_leaves:
        leaf, leaf_edges = decode_graph(exe, start, end)
        if any(leaf[address][1].startswith("call")
               for address in walk([start], leaf_edges)):
            raise ValueError(f"State helper {start:#x} contains another subcall")
    complete_context = {address: list(targets) for address, targets in later_graph.items()}
    for address, instruction, successor in (
        (0x14441D7A4, "je 0x14441d80a", 0x14441D80A),
        (0x14441BEF8, "jne 0x14441bf07", 0x14441BEFA),
    ):
        if re.sub(r"\s+", " ", context_rows[address][1]) != instruction:
            raise ValueError("Late context flag gate differs")
        complete_context[address] = [successor]
    late_context = walk([0x14441BE3A], complete_context)
    context_returns = {address for address, row in context_rows.items()
                       if row[1].startswith("ret")}
    if context_returns != {0x14441F49C}:
        raise ValueError("Context normal-return boundary differs")
    if context_returns & walk([0x14441AF65], complete_context, {0x14441BE35}):
        raise ValueError("Context can return while bypassing the attribute gate")
    if 0x14441D7A4 in walk([0x14441EF12], complete_context):
        raise ValueError("Action-flag update can precede the ball-push exclusion")
    late_targets = sorted({context_rows[address][1].split()[1]
                           for address in late_context
                           if context_rows[address][1].startswith("call")})
    if late_targets != sorted([
        "0x1418b7140", "0x141b40bd0", "0x141b40fe0", "0x141b41670",
        "0x141b41ab0", "0x141b42f50", "0x141b45b90", "0x141b45f00",
        "0x141b460a0", "0x141b461a0", "0x141b4fe90", "0x141b57440",
        "0x1443b9140", "0x1443bc460", "0x1443f9200", "0x1443f9710",
        "0x1443fd280", "0x14557e9b0", "0x14557ea20",
    ]):
        raise ValueError("Late context has an unreviewed subcall")
    context_keys = sorted(context_rows)
    for address in late_context:
        if context_rows[address][1] != "call   0x1443fd280":
            continue
        prior = context_keys[context_keys.index(address) - 1]
        if context_rows[prior][1] != "xor    r9d,r9d":
            raise ValueError("Late angle query can write a non-null optional output")
        if address in walk([0x14441BE3A], complete_context, {prior}):
            raise ValueError("Late angle query can bypass its null-output binding")
    record_nulls = {
        0x14441E71B: (0x14441E6EE,), 0x14441E783: (0x14441E74B,),
        0x14441E877: (0x14441E80F, 0x14441E84E),
        0x14441E8DD: (0x14441E7B5, 0x14441E8A9, 0x14441E974),
        0x14441E946: (0x14441E920,), 0x14441E9FD: (0x14441E9D8,),
        0x14441F9EC: (0x14441F345, 0x14441F7D5, 0x14441F9C7),
    }
    for call, bindings in record_nulls.items():
        expected = ("mov QWORD PTR [rsp+0x90],0x0"
                    if call in (0x14441E783, 0x14441E8DD)
                    else "mov QWORD PTR [rsp+0x40],0x0")
        for binding in bindings:
            # E8dd有第三个R8=&stackC0入口，不能误称所有分支都传stack80。
            actual_expected = ("mov QWORD PTR [rsp+0xd0],0x0"
                               if binding == 0x14441E7B5 else expected)
            if re.sub(r"\s+", " ", context_rows[binding][1]) != actual_expected:
                raise ValueError("Late record query optional write binding differs")
        if call in walk([0x14441BE3A], complete_context, bindings):
            raise ValueError("Late record query can bypass every null-output write")
        if call in walk([0x14441BE3A], complete_context, {0x14441E710, 0x14441E7EB}):
            raise ValueError("Late record query can bypass the existing-list pointer load")
    for call, binding in ((0x14441C8B1, 0x14441C8A6),
                          (0x14441C8D3, 0x14441C8C5),
                          (0x14441CC02, 0x14441CBF7),
                          (0x14441CC61, 0x14441CC56)):
        if not re.fullmatch(r"lea\s+rdx,\[rsp\+0x(?:30|80)\]", context_rows[binding][1]):
            raise ValueError("Late pair-distance output is not a stack slot")
        if call in walk([0x14441BE3A], complete_context, {binding}):
            raise ValueError("Late pair-distance output binding can be bypassed")
    flag_pointers = {0x14441C021, 0x14441C076, 0x14441C08D}
    for binding in flag_pointers:
        if context_rows[binding][1] != "lea    rsi,[r13+0x5ff]":
            raise ValueError("Late byte-store pointer differs")
    for store in (0x14441C048, 0x14441C505, 0x14441C635,
                  0x14441C757, 0x14441CE0F):
        if store in walk([0x14441BE3A], complete_context, flag_pointers):
            raise ValueError("Late indirect byte store bypasses context-byte binding")
    if (context_rows[0x14441C75A][1] != "mov    QWORD PTR [rsp+0x78],rsi"
            or context_rows[0x14441D6EF][1] != "mov    rbp,QWORD PTR [rsp+0x78]"
            or context_rows[0x14441D80A][1] != "lea    rbp,[r13+0x60d]"):
        raise ValueError("Late restored byte-store pointer differs")
    for store, bindings in ((0x14441D780, {0x14441C75A, 0x14441D6EF}),
                            (0x14441D811, {0x14441D80A})):
        for binding in bindings:
            if store in walk([0x14441BE3A], complete_context, {binding}):
                raise ValueError("Late RBP byte store can bypass its pointer producer")
    caller_rows, caller_graph = decode_graph(
        exe, 0x144417950, 0x14441A3A7,
        external_stops=(0x14441FFF0, 0x144420220))
    caller_conditions = (
        (0x1444179C9, "jne 0x144417a24", 0x1444179CB),
        (0x1444179D0, "je 0x144417a7e", 0x144417A7E),
        (0x144417A83, "je 0x144417aa7", 0x144417AA7),
        (0x144417ADB, "jne 0x144417d6b", 0x144417D6B),
        (0x144417D76, "jne 0x144417e6a", 0x144417D7C),
        (0x144417DEF, "jne 0x144417e7a", 0x144417DF5),
        (0x144417E1A, "je 0x144417e8a", 0x144417E8A),
        (0x144417EC3, "jne 0x144417ee8", 0x144417EC5),
        (0x144417EE2, "je 0x1444187ec", 0x1444187EC),
        (0x1444187F3, "je 0x14441a27f", 0x14441A27F),
        (0x14441A28C, "jne 0x14441a2db", 0x14441A28E),
    )
    for address, instruction, successor in caller_conditions:
        if re.sub(r"\s+", " ", caller_rows[address][1]) != instruction:
            raise ValueError("Context-return caller condition differs")
        caller_graph[address] = [successor]
    caller_suffix = walk([0x1444179A4], caller_graph, {0x14441A29F})
    caller_calls = [hex(address) for address in sorted(caller_suffix)
                    if caller_rows[address][1].startswith("call")]
    if caller_calls != ["0x14441a285", "0x14441a294"]:
        raise ValueError("Unexpected helper before the actual near-candidate call")
    if any(caller_rows[address][1].startswith("ret")
           or caller_rows[address][1] == "external_boundary" for address in caller_suffix):
        raise ValueError("Caller can exit before the near-candidate call")
    guard_rows, guard_graph = decode_graph(exe, 0x144421930, 0x144421BB0)
    if re.sub(r"\s+", " ", guard_rows[0x144421954][1]) != "je 0x144421ba3":
        raise ValueError("First candidate guard zero-result branch differs")
    guard_graph[0x144421954] = [0x144421BA3]  # 已证141b46830返回0。
    guard_path = walk([0x144421930], guard_graph)
    if [address for address in guard_path if guard_rows[address][1].startswith("call")] != [0x144421949]:
        raise ValueError("First candidate guard has another actual call")
    alternate_rows, alternate_graph = decode_graph(
        exe, 0x144421BB0, 0x144421D29,
        external_stops=(0x144423E01, 0x144421D29))
    if re.sub(r"\s+", " ", alternate_rows[0x144421D23][1]) != "je 0x144423e01":
        raise ValueError("Alternate candidate flag branch differs")
    alternate_graph[0x144421D23] = [0x144423E01]  # 动作标志两种值的bit0均0。
    if any(alternate_rows[address][1].startswith("call")
           for address in walk([0x144421BB0], alternate_graph)):
        raise ValueError("Alternate-candidate early prefix contains an actual call")
    return {
        "entry": hex(ENTRY), "clear_tail": hex(CLEAR),
        "decoded_instructions": len(rows),
        "clear_reachable_avoiding_all_three_writes": False,
        "calls_after_each_write_without_crossing_another_write": calls,
        "mandatory_calls_on_each_selected_suffix": mandatory,
        "cache_computation": {
            "entry_after_zero_valid_check": hex(cache_entry),
            "valid_write": hex(valid_write), "epilogue": hex(epilogue),
            "decoded_instructions": len(cache_rows),
            "epilogue_reachable_avoiding_valid_write": False,
            "caller_second_call_skipped_on_normal_return_with_same_player_storage": True,
            "ball_query_call": "0x1443bd38b",
            "ball_query_unreachable_if_history_90_at_0x1443bd325": True,
            "record_query_calls_require_prior_binding_points": {
                hex(binding): [hex(site) for site in sites]
                for binding, sites in record_bindings.items()
            },
        },
        "position_judgment": {
            "entry": "0x1443b61f0",
            "decoded_instructions": len(position_rows),
            "conditions_at_reads": ["B+d63=0 at both loops", "P+16f8 bit0=0"],
            "reachable_calls": selected_calls,
            "limits": "Local branches only; callee effects, reset-to-query state retention and natural inputs remain conditional.",
        },
        "reset_to_first_cache": {
            "start": "0x1443c3a5f", "stop_before_call": "0x1443c419a",
            "conditions_at_reads": ["M+e3bb=0", "M+e388=P", "signed P+26c>-101"],
            "remaining_call_sites": reset_suffix_calls,
            "limits": "Local condition selection; producer reachability and memory/alias validity remain conditional.",
        },
        "position_update": {
            "entry": "0x1443b5100", "decoded_instructions": len(update_rows),
            "all_reachable_calls": update_calls,
            "scalar_store_0x1443b605b_requires_binding_0x1443b600c": True,
            "limits": "CALLs return normally in this graph; preservation uses the separately bounded callee contracts.",
        },
        "cache_zero_time_judgment": {
            "caller_sites": [hex(address) for address in judgment_sites],
            "time_argument_bits": "0x00000000",
            "remaining_call_sites": judgment_calls,
            "cache_all_call_targets": cache_call_targets,
            "limits": "Call inventory and zero-time branches only; typed write ranges and bounded callee contracts are documented separately.",
        },
        "post_cache_preparation_return": {
            "entry": "0x1443c419f", "return": "0x1443c47fe",
            "conditions": [
                "P+1870=1", "M+e388=P with coherent player/team references",
                "M+aa4 bit0x10000=1 until clear tail",
                "Valid ring storage; if M+e2e0>7 then M+e328<=7",
            ],
            "reachable_instructions": len(return_reached), "reachable_calls": [],
            "return_can_bypass_clear_tail": False,
            "second_reference_write_requires_parameter_save": "0x1443c181f",
            "limits": "Conditioned local CFG; write-domain/identity reasoning is separate, and earlier natural preparation inputs remain unproved.",
        },
        "candidate_roster_queries": {
            "entry": "0x141b42780", "output_count_bound": "0..11",
            "remaining_calls_including_tail_sort": roster_calls,
            "output_blocks": ["C+300..470", "C+20..190", "C+190..300"],
            "position_query_contract": "At float32 lookahead 0, each valid A=Q+80 has A+e8!=-1 or A+94>=max(tick,0), so 144407a40 is not called.",
            "limits": "No claim for cold position production; bounded output/sort write domains and alias conditions are established separately.",
        },
        "candidate_near_distance_producer": {
            "entry": "0x14441a3b0", "checkpoint": "0x14441af65",
            "conditions_at_branches": ["Finite P+e3c<=0", "C+5c4<3.6600000858306885"],
            "prefix_call_sites": context_calls,
            "limits": "Requires the separately documented ready-position/roster contracts and P flag condition; no claim for later context generation or natural reachability.",
        },
        "candidate_context_to_attribute_gate": {
            "start": "0x14441af65", "stop_before_call": "0x14441be35",
            "conditions_at_reads": ["C+578=0", "P+1870=1", "C+300>0"],
            "path_scope": "Only paths that reach BE35; no claim that every path reaches it.",
            "instructions_on_paths": len(later_prefix), "call_sites": later_calls,
            "speed_virtual_slot": "MATCH_PLAYER 145a1a048+38 -> 141b62dc0",
            "valid_getter_has_calls": False,
            "limits": "Preservation uses typed callee/write bounds and storage contracts, not CFG alone. C+610 can clear; natural record readiness, type retention and later attribute-gate calls remain unresolved.",
        },
        "candidate_attribute_gate": {
            "site": "0x14441be35", "return": "0x14441be3a",
            "gate_calls": {hex(address): value for address, value in gate_calls.items()},
            "state_query": "0x1443b9140..0x1443bb231",
            "condition_at_read": "P+16f8 bit0=0",
            "remaining_targets": state_targets,
            "motion_query_site_0x1443b932a_reachable": False,
            "cache_calls_bound_to_same_P": True,
            "scalar_outputs_bound_to_stack_and_optional_angle_writes_null": True,
            "cold_normal_return_can_bypass_all_valid_writes": False,
            "limits": "Preservation additionally needs P1870=1, bounded pair-cache/geometry storage, valid player/team objects and the reviewed public attribute-reader contract. Boolean output semantics do not establish natural shot choice or goal probability.",
        },
        "candidate_context_normal_return": {
            "return": "0x14441f49c", "late_call_targets": late_targets,
            "late_instructions": len(late_context),
            "normal_return_can_bypass_attribute_gate": False,
            "action_flag_or_0x1000_can_precede_ball_gate": False,
            "late_record_optional_outputs_null": True,
            "action_flag_outputs": ["0x810", "0x1810"],
            "limits": "Write-domain contracts permit RNG, owned byte-vector growth and caches. No natural input or RNG-output witness is established by this graph.",
        },
        "context_return_to_near_candidate": {
            "entry": "0x1444179a4", "candidate_call": "0x14441a29f",
            "conditions": ["P11a8=810 or 1810", "Maa4 bit10000=1", "First guard AL=0"],
            "actual_prefix_calls": caller_calls,
            "first_guard_actual_call": "0x144421949 -> 141b46830; P16f8 bit0=0",
            "alternate_prefix_has_calls": False,
            "limits": "Requires valid caller/context storage. Candidate creation is documented using prior native evidence; model computation, selection and natural goal remain open.",
        },
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
