"""从原PE核对非空mode1模型的分支、排序子树与调用者阈值；不执行原生代码。"""

import argparse
import json
import re
import struct
from pathlib import Path

from inspect_preparation_reference_paths import decode_graph, walk
from verify_goal_lifecycle import verify_target_identity

ROOT = Path(__file__).resolve().parents[1]
TABLES = (
    (0x144529D7C, 0x14452AE90, 8),
    (0x144387482, 0x144387644, 7),
    (0x14438751F, 0x14438760C, 7),
    (0x144387556, 0x144387628, 7),
)
RANGES = (
    (0x144528BB0, 0x14452ACEA),
    (0x14452B070, 0x14452B1BC),
    (0x14452B1C0, 0x14452B742),
    (0x14452B750, 0x14452BDDC),
    (0x15CBEF2F0, 0x15CBEF3BF),
    (0x144386FA0, 0x14438760C),
    (0x144387660, 0x1443876CD),
    (0x1443876D0, 0x14438773D),
    (0x144387740, 0x1443877AD),
    (0x15A2CB2E0, 0x15A2CB4A7),
    (0x1443203D0, 0x1443208D4),
    (0x159A6CB10, 0x159A6CC75),
    (0x1443201D0, 0x1443202A2),
    (0x1443202B0, 0x1443203C5),
    (0x14431FFA0, 0x144320089),
)


def inspect(exe):
    """检查已知分支能否排除球预测；其余分支保留双边并列出未闭合调用。"""
    data = exe.read_bytes()
    verify_target_identity(data, json.loads(
        (ROOT / "20261019_fm24_target_identity.json").read_text()))
    pe = struct.unpack_from("<I", data, 60)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    section_start = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    sections = [struct.unpack_from("<IIII", data, section_start + i * 40 + 8)
                for i in range(count)]

    def offset(address):
        for _, rva, size, raw in sections:
            if rva <= address - 0x140000000 < rva + size:
                return raw + address - 0x140000000 - rva
        raise ValueError(f"No file bytes at {address:#x}")

    tables, indirect = [], {}
    for site, base, size in TABLES:
        raw = data[offset(base):offset(base) + size * 4]
        targets = [base + value for value in struct.unpack(f"<{size}i", raw)]
        indirect[site] = targets
        tables.append({"site": hex(site), "base": hex(base), "bytes": raw.hex(),
                       "targets": [hex(target) for target in targets]})
    decoded = {}
    inventories = []
    for start, end in RANGES:
        rows, graph = decode_graph(exe, start, end, indirect_targets=indirect,
                                   external_stops={0x14452B750: (0x14557E730,),
                                                   0x14431FFA0: (0x1452ED750,)}.get(start, ()))
        reached = walk([start], graph)
        decoded[start] = (rows, graph)
        inventories.append({
            "entry": hex(start), "end_exclusive": hex(end),
            "reachable_instructions": len(reached),
            "normal_returns": [hex(a) for a in sorted(reached)
                               if rows[a][1].startswith("ret")],
            "external_boundaries": [hex(a) for a in sorted(reached)
                                    if rows[a][1] == "external_boundary"],
            "calls": [{"site": hex(a), "instruction": rows[a][1]}
                      for a in sorted(reached) if rows[a][1].startswith("call")],
        })
    rows, graph = decoded[0x144528BB0]
    expected = {
        0x144528C31: "mov rsi,QWORD PTR [rdx+0xe378]",
        0x144528C38: "mov rdi,rsi",
        0x144528C45: "jne 0x144528c4f",
        0x144528CAA: "je 0x144528cd0",
        0x144528CC5: "je 0x144528d7d",
        0x144528D00: "mov ecx,DWORD PTR [rsi+0xf10]",
        0x144528D0C: "jb 0x144528d27",
        0x144528D1B: "ja 0x144528d93",
        0x144529C47: "jge 0x144529c77",
        0x144529C2D: "je 0x144529c68",
        0x144529D3E: "jne 0x144529d48",
        0x14452A5BB: "jbe 0x14452a615",
        0x144529576: "jne 0x1445295ab",
        0x14452A45D: "jne 0x14452a495",
    }
    for address, instruction in expected.items():
        if re.sub(r"\s+", " ", rows[address][1]) != instruction:
            raise ValueError(f"Changed selected branch at {address:#x}")
    selected = dict(graph)
    choices = {
        0x144528C45: 0x144528C4F,  # mode1。
        0x144528CAA: 0x144528CAC,  # 同一非空P。
        0x144528CC5: 0x144528CCB,
        0x144528D0C: 0x144528D0E,  # 历史0x90。
        0x144528D1B: 0x144528D93,
        0x144529C2D: 0x144529C2F,
        0x144529C47: 0x144529C77,  # 准备流程已有B+d2c=t。
        0x144529D3E: 0x144529D48,
        0x144529576: 0x1445295AB,  # 既有已初始化池契约。
        0x14452A45D: 0x14452A495,
    }
    for address, target in choices.items():
        if target not in graph[address]:
            raise ValueError(f"Not a native successor: {address:#x}")
        selected[address] = [target]
    reached = walk([0x144528BB0], selected)
    if 0x144529C61 in reached:
        raise ValueError("Prediction remains reachable; reopen same-ball claim")
    returns = {a for a in reached if rows[a][1].startswith("ret")}
    if not returns or returns & walk([0x144528BB0], selected, {0x14452ABAE}):
        raise ValueError("Selected normal return can bypass calculator call")
    if returns & walk([0x144528BB0], selected, {0x144528CA4}):
        raise ValueError("Selected normal return can bypass output publication")
    # 不把池清理视为纯函数：输出剩余真实调用，后续逐个处理。
    selected_calls = [{"site": hex(a), "instruction": rows[a][1]}
                      for a in sorted(reached) if rows[a][1].startswith("call")]
    reverse = {a: [] for a in selected}
    for source, targets in selected.items():
        for target in targets:
            reverse[target].append(source)
    prefix = walk([0x144529C47], reverse) & walk([0x144528BB0], selected, {0x144529C47})
    before_prediction_calls = [{"site": hex(a), "instruction": rows[a][1]}
                               for a in sorted(prefix) if rows[a][1].startswith("call")]
    if 0x14452A6C1 not in prefix:
        raise ValueError("Pre-prediction cleanup was lost from the backward slice")
    # 数量界与临时堆分配的排除单列；不混入上述保守双边图。
    sort_bound = {"source": "signed positive team+3c1; two scans; at most one interval per player",
                  "max_intervals": 254, "max_half_scratch": (254 + 1) // 2,
                  "heap_scratch_threshold": 512,
                  "branch_if_bound_established": "0x14452a5bb -> 0x14452a615",
                  "limitation": "CFG inventory does not prove loop/alias bounds"}
    sort_rows, sort_graph = decoded[0x14452B070]
    if re.sub(r"\s+", " ", sort_rows[0x14452B138][1]) != "jle 0x14452b168":
        raise ValueError("Top sort scratch comparison changed")
    buffered_sort = dict(sort_graph)
    buffered_sort[0x14452B138] = [0x14452B168]  # ceil(n/2) <= actual scratch count。
    sort_reached = walk([0x14452B070], buffered_sort)
    if {0x14452B14B, 0x14452B161} & sort_reached:
        raise ValueError("Top sort recursion remains reachable under sufficient scratch")
    merge_rows, merge_graph = decoded[0x14452B750]
    for address, expected in {0x14452B826: "jg 0x14452b831",
                              0x14452B834: "jle 0x14452bcf2"}.items():
        if re.sub(r"\s+", " ", merge_rows[address][1]) != expected:
            raise ValueError(f"Buffered merge comparison changed: {address:#x}")
    buffered_merge = dict(merge_graph)
    buffered_merge[0x14452B826] = [0x14452B828]  # 左段修剪后 <= ceil(n/2)。
    buffered_merge[0x14452B834] = [0x14452BCF2]  # 右段修剪后 <= floor(n/2) <= scratch。
    merge_reached = walk([0x14452B750], buffered_merge)
    if {0x14452B83A, 0x14452BBD5} & merge_reached:
        raise ValueError("Unbuffered merge/recursion remains reachable")
    buffered_calls = [merge_rows[a][1] for a in sorted(merge_reached)
                      if merge_rows[a][1].startswith("call")]
    if any(re.sub(r"\s+", " ", ins) != "call 0x14557e730" for ins in buffered_calls):
        raise ValueError("Buffered merge has a non-memmove callee")
    thunk = offset(0x14557EA00)
    if data[thunk:thunk + 2] != b"\xff\x25" or (
            0x14557EA06 + struct.unpack_from("<i", data, thunk + 2)[0] != 0x145D50F30):
        raise ValueError("Calculator math thunk changed")
    descriptor = offset(0x15CF4A2A8)
    lookup, _, _, module, iat = struct.unpack_from("<IIIII", data, descriptor)
    if iat != 0x5D50EB0:
        raise ValueError("Math IAT descriptor changed")
    module_offset = offset(0x140000000 + module)
    if data[module_offset:module_offset + 31] != b"api-ms-win-crt-math-l1-1-0.dll\0":
        raise ValueError("Math import module changed")
    slot = lookup + ((0x5D50F30 - iat) // 8) * 8
    name = struct.unpack_from("<Q", data, offset(0x140000000 + slot))[0]
    if data[offset(0x140000000 + name + 2):offset(0x140000000 + name + 2) + 5] != b"expf\0":
        raise ValueError("Calculator import is not expf")
    # 导入名称来自原PE查找表，不能把磁盘IAT当作运行中的函数地址。
    import_rva, _ = struct.unpack_from("<II", data, pe + 24 + 112 + 8)
    descriptor = offset(0x140000000 + import_rva)
    names = {}
    while any(data[descriptor:descriptor + 20]):
        lookup, _, _, module, iat = struct.unpack_from("<IIIII", data, descriptor)
        begin = offset(0x140000000 + module)
        dll = data[begin:data.index(b"\0", begin)].decode()
        index = 0
        while True:
            item = struct.unpack_from("<Q", data, offset(0x140000000 + lookup + index * 8))[0]
            if not item:
                break
            if not item >> 63:
                begin = offset(0x140000000 + item) + 2
                names[0x140000000 + iat + index * 8] = {
                    "dll": dll, "symbol": data[begin:data.index(b"\0", begin)].decode(),
                    "descriptor": hex(0x140000000 + import_rva),
                    "lookup": hex(0x140000000 + lookup + index * 8),
                    "hint_name": hex(0x140000000 + item),
                }
            index += 1
        descriptor += 20
        import_rva += 20
    pool_imports = {}
    for slot, symbol in {
        0x145D4FAB8: "InterlockedPopEntrySList", 0x145D4FAC0: "InterlockedPushEntrySList",
        0x145D4FC08: "SetEvent", 0x145D4FD18: "WaitForSingleObject",
        0x145D50E60: "_aligned_free", 0x145D50E68: "_aligned_malloc",
        0x145D50E90: "free",
    }.items():
        if names[slot]["symbol"] != symbol:
            raise ValueError(f"Pool import changed: {slot:#x}")
        pool_imports[hex(slot)] = names[slot]
    # 对寄存器间接CALL检查实际IAT加载必经，不按函数名称推断接口。
    indirect_calls = []
    for entry, binding, site, slot, register in (
        (0x1443203D0, 0x144320749, 0x144320774, 0x145D4FAC0, "r14"),
        (0x1443203D0, 0x144320790, 0x1443207A6, 0x145D4FAC0, "r14"),
        (0x1443203D0, 0x14432087E, 0x144320890, 0x145D50E90, "r15"),
        (0x1443203D0, 0x144320877, 0x1443208B4, 0x145D50E60, "r14"),
        (0x1443201D0, 0x1443201F0, 0x144320217, 0x145D4FAB8, "r13"),
        (0x1443201D0, 0x1443201F0, 0x14432025D, 0x145D4FAB8, "r13"),
        (0x1443201D0, 0x1443201F7, 0x144320249, 0x145D4FD18, "rbp"),
        (0x1443202B0, 0x144320361, 0x14432038E, 0x145D4FAC0, "r12"),
        (0x1443202B0, 0x144320368, 0x14432039F, 0x145D4FC08, "r13"),
    ):
        helper_rows, helper_graph = decoded[entry]
        load = re.sub(r"\s+", " ", helper_rows[binding][1])
        call = re.sub(r"\s+", " ", helper_rows[site][1])
        if not load.startswith(f"mov {register},QWORD PTR [rip+") or not load.endswith(f"# {slot:#x}"):
            raise ValueError(f"Indirect pool binding changed: {binding:#x}")
        if call != f"call {register}" or site in walk([entry], helper_graph, {binding}):
            raise ValueError(f"Indirect pool call bypasses load: {site:#x}")
        indirect_calls.append({"site": hex(site), "binding": hex(binding),
                               "iat": hex(slot), "symbol": names[slot]["symbol"],
                               "load_dominates_call": True})
    # 人工逐组恢复的写域；地址清单由完整本地图独立提取，新增写点必须重新分类。
    domains = {}
    for label, sites in {
        "new_output_X": [0x144528C66, 0x144528C71, 0x144528C74, 0x144528C7C,
                         0x144528C84, 0x144528C8C, 0x144528C94, 0x144528C9C,
                         0x144529003, 0x144529007, 0x144529015, 0x144529026,
                         0x144529564, 0x144529568, 0x144529A1D, 0x144529A96,
                         0x144529C02, 0x144529C0D, 0x144529C21, 0x144529D56,
                         0x144529D87, 0x144529D9E, 0x144529DA8, 0x144529DCC,
                         0x14452A54A, 0x14452A565, 0x14452A58F, 0x14452A6A0,
                         0x14452A6EC, 0x14452AAD5, 0x14452AB9B],
        "caller_stack_output_pointer": [0x144528CA4],
        "own_interval_array": [0x14452A2CE, 0x14452A2D1, 0x14452A349,
                               0x14452A34D, 0x14452A4E1, 0x14452A4E3, 0x14452A538],
        "own_merged_array": [0x14452A70A, 0x14452A70E, 0x14452A785, 0x14452A789,
                             0x14452A7D8, 0x14452A7DC, 0x14452A833, 0x14452A839,
                             0x14452A93B, 0x14452A941],
        "pool_cell_metadata": [0x144529BCB, 0x14452A3CF, 0x14452A8AE,
                               0x14452A9B5, 0x14452AB3F],
        "excluded_allocator_initialization": [0x1445295A4, 0x14452A48B],
    }.items():
        for site in sites:
            domains[site] = label
    writes = []
    for address, (_, instruction) in rows.items():
        ins = re.sub(r"\s+", " ", instruction)
        if ins.startswith("lock "):
            ins = ins[5:]
        first = ins.split(",", 1)[0]
        if "[" not in first or "[rsp" in first or "[rbp" in first:
            continue
        op = ins.split()[0]
        if op in {"cmp", "test", "ucomiss", "comiss", "nop", "cs", "call", "jmp"}:
            continue
        if address not in domains:
            raise ValueError(f"Unclassified model external store: {address:#x} {instruction}")
        writes.append({"site": hex(address), "instruction": instruction,
                       "domain_manual_derivation": domains[address],
                       "reachable_under_selected_branches": address in reached})
    interval_writes = {a for a, label in domains.items() if label == "own_interval_array"}
    for binding in (0x144529EF9, 0x144529F00, 0x144529F03):
        if interval_writes & walk([0x144528BB0], selected, {binding}):
            raise ValueError(f"Interval writes bypass empty initialization at {binding:#x}")
    thresholds = [struct.unpack_from("<f", data, offset(a))[0]
                  for a in (0x1456B08C4, 0x1455A9800)]
    return {"evidence_type": "original_PE_static_CFG_not_execution",
            "tables": tables, "functions": inventories,
            "selected_model_branches": {hex(a): hex(t) for a, t in choices.items()},
            "selected_model_calls": selected_calls,
            "calls_before_prediction_check": before_prediction_calls,
            "prediction_call_excluded": True,
            "calculator_call_mandatory_for_selected_normal_return": True,
            "output_publication_mandatory_for_selected_normal_return": True,
            "interval_empty_initializers_dominate_writes": True,
            "sort_bound_manual_derivation": sort_bound,
            "sufficient_scratch_sort": {
                "conditions": "actual model n<=254; scratch=ceil(n/2); top halves ceil/floor; trimming only reduces counts",
                "top_recursive_calls_excluded": True,
                "merge_rotation_and_recursion_excluded": True,
                "merge_calls": buffered_calls,
                "limits": "count/range/ownership derivation is manual; branch reachability is checked from original PE",
            },
            "calculator_import": "api-ms-win-crt-math-l1-1-0.dll!expf",
            "caller_thresholds_f32": thresholds,
            "pool_import_bindings": pool_imports,
            "pool_register_call_bindings": indirect_calls,
            "model_nonstack_stores": writes,
            "limitations": ["CALL edges assume normal return; not a side-effect proof",
                            "pool/array write domains require documented successful-storage ownership contracts",
                            "natural simultaneous inputs, candidate selection and goal unproven"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.exe)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print("PASS: four native switch tables; complete local CFGs; selected prediction exclusion; expf binding.")
    print("PASS: model store coverage; pool imports and dominating indirect-call bindings.\n"
          "Side-effect domains remain conditional on valid ownership/first-success storage; no game execution.")
