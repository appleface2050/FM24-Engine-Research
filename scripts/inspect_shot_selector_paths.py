"""从原PE复核单一近距3f候选的评分写域、首次接受及行动块复制边界。"""

import argparse
import json
import re
import struct
from pathlib import Path

from inspect_preparation_reference_paths import decode_graph, walk
from verify_goal_lifecycle import verify_target_identity

ROOT = Path(__file__).resolve().parents[1]
TABLES = ((0x144427546, 0x144427C90, 9), (0x1444275DD, 0x144427CB4, 9),
          (0x1444339C4, 0x144439894, 5), (0x144420093, 0x1444201F0, 9))


def normalize(ins):
    """只规范objdump空白，不推断寄存器或对象身份。"""
    return re.sub(r"\s+", " ", ins)


def stores(rows, reached):
    """列本轮本体的非栈显式写点；RBP也按对象寄存器检查，不把它默认当栈帧。"""
    result = []
    for address in sorted(reached):
        ins = normalize(rows[address][1])
        first = ins.split(",", 1)[0]
        if "[" not in first or "[rsp" in first:
            continue
        if ins.split()[0] not in {"cmp", "test", "ucomiss", "comiss", "nop", "cs", "call", "jmp", "lea"}:
            result.append({"site": hex(address), "instruction": ins})
    return result


def inspect(exe):
    """复核有条件的实际分支与指针保存恢复；CALL按正常返回，不执行原函数。"""
    data = exe.read_bytes()
    verify_target_identity(data, json.loads((ROOT / "20261019_fm24_target_identity.json").read_text()))
    pe = struct.unpack_from("<I", data, 60)[0]
    section_start = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    sections = [struct.unpack_from("<IIII", data, section_start + i * 40 + 8)
                for i in range(struct.unpack_from("<H", data, pe + 6)[0])]

    def offset(address):
        for _, rva, size, raw in sections:
            if rva <= address - 0x140000000 < rva + size:
                return raw + address - 0x140000000 - rva
        raise ValueError(f"No file bytes at {address:#x}")

    tables, indirect = [], {}
    for site, base, n in TABLES:
        raw = data[offset(base):offset(base) + n * 4]
        targets = [base + value for value in struct.unpack(f"<{n}i", raw)]
        indirect[site] = targets
        tables.append({"site": hex(site), "base": hex(base), "bytes": raw.hex(),
                       "targets": [hex(target) for target in targets]})
    if indirect[0x1444339C4][1] != 0x1444339FB:
        raise ValueError("Family1 table no longer selects recorded shot branch")
    second_rows, second_graph = decode_graph(exe, 0x144433930, 0x144439894,
                                            indirect_targets=indirect)
    second = dict(second_graph)
    second[0x1444339C4] = [0x1444339FB]
    for site, target in {0x1444339B0: 0x1444339B6, 0x144433A18: 0x144433A1E,
                         0x144433A2B: 0x144433A31, 0x144433A3F: 0x144433A45,
                         0x144433A55: 0x14443461E}.items():
        if target not in second_graph[site]:
            raise ValueError(f"Not a native second-multiplier edge {site:#x}")
        second[site] = [target]
    second_reached = walk([0x144433930], second)
    second_calls = {a: normalize(second_rows[a][1]) for a in sorted(second_reached)
                    if second_rows[a][1].startswith("call")}
    expected_calls = {0x144434DFF: "call 0x141b51c90", 0x144434EC7: "call 0x141b51c90",
                      0x144434F22: "call 0x141b51c90", 0x144435182: "call 0x14557eb50",
                      0x14443518B: "call 0x14557ea00"}
    if second_calls != expected_calls:
        raise ValueError("Near family1 has another helper to analyze")
    for site, zero in ((0x144434DFF, 0x144434DFC), (0x144434EC7, 0x144434EC4),
                       (0x144434F22, 0x144434F1F)):
        if normalize(second_rows[zero][1]) != "xor r8d,r8d" or site in walk([0x144433930], second, {zero}):
            raise ValueError(f"Direction call bypasses null-output producer {site:#x}")
    cuts = []
    for start, uses, restore in (
        (0x144434F4C, {0x144439707, 0x144439754}, {0x14443587A}),
        (0x144434DFF, {0x144439711}, {0x144435657, 0x1444359A2}),
    ):
        if uses & walk(second[start], second, restore):
            raise ValueError(f"Pointer use bypasses restoration after {start:#x}")
        cuts.append({"after": hex(start), "uses": [hex(a) for a in sorted(uses)],
                     "required_restore_union": [hex(a) for a in sorted(restore)]})
    for site, expected in {
        0x144433980: "mov r10,r9", 0x144433986: "mov r12,rdx",
        0x144434EDA: "mov QWORD PTR [rsp+0x28],rdi",
        0x144434EE1: "mov rsi,r12", 0x144434FB9: "mov QWORD PTR [rsp+0x68],rsi",
        0x14443587A: "mov r12,QWORD PTR [rsp+0x68]",
        0x144435657: "mov r10,QWORD PTR [rsp+0x28]",
        0x1444359A2: "mov r10,QWORD PTR [rsp+0x28]",
    }.items():
        if normalize(second_rows[site][1]) != expected:
            raise ValueError(f"Pointer binding differs {site:#x}")
    candidate_saves = {0x144434DA4, 0x144434DBA, 0x144434DD0, 0x144434DDC}
    for site in candidate_saves:
        if normalize(second_rows[site][1]) != "mov rdi,r10":
            raise ValueError("Candidate nonvolatile save differs")
    if {0x144434DFF, 0x144434EDA} & walk([0x144433930], second, candidate_saves):
        raise ValueError("Candidate stack save bypasses the nonvolatile source")
    # 输出保存值在被复用之前建立；这些检查不替代正文中的寄存器写入审计。
    for site, required in ((0x144434F4C, 0x144434EE1), (0x14443587A, 0x144434FB9)):
        if site in walk([0x144433930], second, {required}):
            raise ValueError("Output save/restoration source can be bypassed")
    second_returns = {a for a in second_reached if second_rows[a][1].startswith("ret")}
    if second_returns != {0x1444397AD}:
        raise ValueError("Near family1 has another normal return")
    second_stores = stores(second_rows, second_reached)
    allowed = {0x1444339A5, 0x14443472E, 0x14443473B, 0x1444347D5, 0x1444347E2,
               0x1444347EA, 0x1444347F1, 0x1444348B6, 0x1444348C3, 0x14443491C,
               0x144434929, 0x144434CDB, 0x144434CE2, 0x144439707, 0x144439754}
    if {int(row["site"], 16) for row in second_stores} != allowed:
        raise ValueError("Second-multiplier nonstack write domain changed")

    direction = []
    for start, end, choices in (
        (0x141B51C90, 0x141B51E0C, {0x141B51CAC: 0x141B51E05}),
        (0x141B51E10, 0x141B51F26, {0x141B51E8A: 0x141B51E9D, 0x141B51EEC: 0x141B51F23,
                                   0x141B51EF7: 0x141B51F0A, 0x141B51F1D: 0x141B51F23}),
    ):
        rows, graph = decode_graph(exe, start, end)
        selected = dict(graph)
        for site, target in choices.items():
            if target not in graph[site]:
                raise ValueError("Null direction output branch changed")
            selected[site] = [target]
        reached = walk([start], selected)
        if stores(rows, reached):
            raise ValueError("Null-output direction helper retains an external store")
        # R8原值不能在进入子帮助函数前被指令改写。
        if any(re.match(r"(?!cmp |test )\w+ r8[bwd]?,", normalize(rows[a][1])) for a in reached):
            raise ValueError("Direction helper overwrites null R8")
        calls = {hex(a): normalize(rows[a][1]) for a in sorted(reached) if rows[a][1].startswith("call")}
        direction.append({"entry": hex(start), "calls": calls, "null_output_external_stores": []})
    if direction[0]["calls"] != {"0x141b51e00": "call 0x141b51e10"} or direction[1]["calls"]:
        raise ValueError("Direction subtree has another callee")

    # 家族1第一个乘数的真实入口及返回片段，显式保留未选家族边界。
    first_rows, first = decode_graph(exe, 0x144431760, 0x1444317D1,
                                    external_stops=(0x1444317D1, 0x1444334EF))
    tail_rows, tail = decode_graph(exe, 0x1444334EF, 0x144433549)
    first_rows.update(tail_rows)
    first.update(tail)
    first[0x1444317C1] = [0x1444317C3]
    first_reached = walk([0x144431760], first)
    if any(first_rows[a][1] == "external_boundary" or first_rows[a][1].startswith("call") for a in first_reached):
        raise ValueError("First multiplier no longer has the family1 direct return")

    if {int(row["site"], 16) for row in stores(first_rows, first_reached)} != {0x1444317C9}:
        raise ValueError("First multiplier has another external write")
    if struct.unpack_from("<f", data, offset(0x145A1D4B0))[0] != 1.0:
        raise ValueError("First multiplier constant differs")
    for site, expected in {0x1444317B6: "mov r14,rdx",
                           0x1444317C9: "mov DWORD PTR [r14],eax"}.items():
        if normalize(first_rows[site][1]) != expected:
            raise ValueError("First multiplier output binding differs")

    selector_rows, selector_graph = decode_graph(exe, 0x144427400, 0x144427C90,
                                                indirect_targets=indirect, external_stops=(0x144427C90,))
    selector = dict(selector_graph)
    # 一条原候选；两个被调乘数保持向量/动作/标志，P1640零与非零均保留。
    choices = {0x14442745C: 0x144427462, 0x144427500: 0x14442755A,
               0x144427561: 0x144427567, 0x144427575: 0x144427590,
               0x144427593: 0x144427697, 0x14442769A: 0x144427700,
               0x14442770C: 0x144427712, 0x144427723: 0x144427729,
               0x144427858: 0x14442785A, 0x1444278A9: 0x1444278AB,
               0x14442791F: 0x14442795E, 0x1444279DC: 0x1444274B6,
               0x1444274F5: 0x144427C48}
    for site, target in choices.items():
        if target not in selector_graph[site]:
            raise ValueError(f"Not a native selector edge {site:#x}")
        selector[site] = [target]
    selected = walk([0x144427400], selector)
    if 0x144427C90 in selected:
        raise ValueError("Selector reaches inline table boundary")
    selector_calls = {hex(a): normalize(selector_rows[a][1]) for a in sorted(selected)
                      if selector_rows[a][1].startswith("call")}
    if set(selector_calls) != {"0x14442780d", "0x144427831", "0x1444278d1", "0x1444278ee"}:
        raise ValueError("Single candidate selector reaches another helper")
    for write, use in ((0x14442772D, 0x14442791A), (0x144427468, 0x14442772D)):
        if use in walk([0x144427400], selector, {write}):
            raise ValueError("Best-index save/restore source can be bypassed")
    selector_stores = stores(selector_rows, selected)
    selector_allowed = {0x1444277D9, 0x1444278F7, 0x1444279AE, 0x1444279BC}
    if {int(row["site"], 16) for row in selector_stores} != selector_allowed:
        raise ValueError("Selected selector write domain changed")
    if 0x1444274C6 not in selected or 0x144427C8C in walk([0x144427400], selector, {0x1444274C6}):
        raise ValueError("Normal return can bypass accepting first index")

    chooser_rows, chooser = decode_graph(exe, 0x14441FFF0, 0x1444201F0, indirect_targets=indirect, external_stops=(0x1444201F0,))
    for site, target in {0x144420008: 0x14442000E, 0x14442003A: 0x144420053,
                         0x144420059: 0x144420068, 0x14442006E: 0x144420070}.items():
        if target not in chooser[site]:
            raise ValueError("Selected shot dispatch differs")
        chooser[site] = [target]
    before_generator = walk([0x14441FFF0], chooser, {0x144420076})
    if 0x1444201F0 in before_generator:
        raise ValueError("Selected dispatch reaches inline table boundary")
    if 0x144420076 not in {t for a in before_generator for t in chooser[a]}:
        raise ValueError("Shot generator call cannot be reached")
    if 0x144420076 in walk([0x14441FFF0], chooser, {0x14442002A}):
        raise ValueError("Generator dispatch bypasses selected-candidate copy")
    generator_rows, generator = decode_graph(exe, 0x1444290E0, 0x144429171,
                                            external_stops=(0x144429171,))
    generator_reached = walk([0x1444290E0], generator)
    if 0x144429171 in walk([0x1444290E0], generator, {0x14442915F}):
        raise ValueError("Generator initial state bypasses action-block copy")

    # 新增标量logf与既有expf按原PE导入名绑定；不读取运行IAT。
    imports = []
    lookup, _, _, module, iat = struct.unpack_from("<IIIII", data, offset(0x15CF4A2A8))
    for thunk, slot, symbol in ((0x14557EB50, 0x145D50F78, "logf"),
                                (0x14557EA00, 0x145D50F30, "expf")):
        start = offset(thunk)
        if data[start:start + 2] != b"\xff\x25" or thunk + 6 + struct.unpack_from("<i", data, start + 2)[0] != slot:
            raise ValueError("Math thunk binding changed")
        item = lookup + slot - 0x140000000 - iat
        hint = 0x140000000 + struct.unpack_from("<Q", data, offset(0x140000000 + item))[0]
        begin = offset(hint) + 2
        if data[begin:data.index(b"\0", begin)].decode() != symbol:
            raise ValueError("Math import name differs")
        imports.append({"thunk": hex(thunk), "iat": hex(slot), "symbol": symbol,
                        "descriptor": "0x15cf4a2a8", "lookup": hex(0x140000000 + item),
                        "hint_name": hex(hint)})
    return {"evidence_type": "original_PE_conditional_CFG_not_execution",
            "conditions": ["one same live candidate, action3f, flags4, extension0; M+6a0>23",
                           "existing post-model-guard conditions; near C5c4=1.5; flags810 or1810",
                           "valid direction lookup/reference geometry and independent stack/object storage",
                           "ordinary Windows x64 ABI, scalar CRT and memcpy normal return"],
            "tables": tables, "math_imports": imports,
            "first_multiplier": {"returns": "1.0", "calls": []},
            "second_multiplier": {"calls": {hex(a): ins for a, ins in second_calls.items()},
                                  "pointer_restore_cuts": cuts, "stores": second_stores,
                                  "direction_subtree": direction,
                                  "numeric_output": "not frozen or evaluated; selected scene branches retained"},
            "selector": {"branches": {hex(a): hex(t) for a, t in choices.items()},
                         "calls": selector_calls, "stores": selector_stores,
                         "manual_dataflow": "initial index0/best-1; best stack save/restore; accept0; count remains1; loop exits",
                         "return_if_stated_callee_contracts_hold": 0,
                         "decision_cache_zero_branch_retained": True},
            "dispatch": {"selected_copy": "0x14442002a: R -> C+470, length d0",
                         "generator": "0x144420076 -> 0x1444290e0",
                         "initial_action_copy": "0x14442915f: C+470 -> P+dc0, length d0",
                         "checkpoint": "0x144429171 before subsequent target preparation",
                         "fields": {"P+e40": "3f", "P+e44": 0, "P+e28": 4, "P+e3c": "same C+578=0"}},
            "unproved": ["natural production/retention of prior cache, zero-slot and compatibility inputs",
                         "later target/solver/perturbation, same new trajectory, defense/rules and goal"],
            "limits": "Local CFG and transfer checks are not an automatic alias proof or game execution"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(inspect(args.exe), ensure_ascii=False, indent=2) + "\n")
    print("PASS: near-family helper/write coverage; null direction outputs; single-candidate first acceptance; dispatch/copy boundaries.")
    print("Conditional static result only; natural inputs, later execution and goal remain unproved.")
