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
                                   external_stops=((0x14557E730,) if start == 0x14452B750 else ()))
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
    # 不把池清理视为纯函数：输出剩余真实调用，后续逐个处理。
    selected_calls = [{"site": hex(a), "instruction": rows[a][1]}
                      for a in sorted(reached) if rows[a][1].startswith("call")]
    # 数量界与临时堆分配的排除单列；不混入上述保守双边图。
    sort_bound = {"source": "signed positive team+3c1; two scans; at most one interval per player",
                  "max_intervals": 254, "max_half_scratch": (254 + 1) // 2,
                  "heap_scratch_threshold": 512,
                  "branch_if_bound_established": "0x14452a5bb -> 0x14452a615",
                  "limitation": "CFG inventory does not prove loop/alias bounds"}
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
    thresholds = [struct.unpack_from("<f", data, offset(a))[0]
                  for a in (0x1456B08C4, 0x1455A9800)]
    return {"evidence_type": "original_PE_static_CFG_not_execution",
            "tables": tables, "functions": inventories,
            "selected_model_branches": {hex(a): hex(t) for a, t in choices.items()},
            "selected_model_calls": selected_calls,
            "prediction_call_excluded": True,
            "sort_bound_manual_derivation": sort_bound,
            "calculator_import": "api-ms-win-crt-math-l1-1-0.dll!expf",
            "caller_thresholds_f32": thresholds,
            "limitations": ["CALL edges assume normal return; not a side-effect proof",
                            "pool flush and allocator calls remain explicit obligations",
                            "natural simultaneous inputs, candidate selection and goal unproven"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.exe)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print("PASS: four native switch tables; complete local CFGs; selected prediction exclusion; expf binding.")
    print("Remaining calls retain normal-return and side-effect obligations; no game execution.")
