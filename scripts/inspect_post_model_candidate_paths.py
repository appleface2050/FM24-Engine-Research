"""核对模型返回后四个实际候选调用的限定分支与本地记录来源，不执行游戏。"""

import argparse
import json
import re
from pathlib import Path

from inspect_preparation_reference_paths import decode_graph, walk
from verify_goal_lifecycle import verify_target_identity

ROOT = Path(__file__).resolve().parents[1]
RANGES = (
    (0x1444256C0, 0x144425DA9, (0x14530CF00,)),
    (0x144425DB0, 0x144426BEF, ()),
    (0x144426BF0, 0x144426FF6, (0x144420850,)),
    (0x144427000, 0x1444273F6, ()),
    (0x145325220, 0x145325E4B, ()),
)


def inspect(exe):
    """保留C610双边及标量比较分支；显式选择已有位条件和新增缓存下界。"""
    verify_target_identity(exe.read_bytes(), json.loads(
        (ROOT / "20261019_fm24_target_identity.json").read_text()))
    decoded = {}
    for start, end, stops in RANGES:
        decoded[start] = decode_graph(exe, start, end, external_stops=stops)

    selections = {
        0x1444256C0: {
            0x1444256E5: ("je 0x144425918", 0x144425918),
            0x1444259DC: ("jne 0x1444259e7", 0x1444259DE),
            0x1444259E5: ("jne 0x144425a04", 0x144425A04),
        },
        0x144425DB0: {
            0x144425DCE: ("je 0x144425e2a", 0x144425E2A),
            0x144425E44: ("ja 0x144425e6a", 0x144425E6A),
            0x144425E6C: ("je 0x144425eb3", 0x144425E6E),
            0x144425E75: ("jne 0x144425eb3", 0x144425E77),
            0x144425E92: ("jbe 0x144425eb3", 0x144425E94),
        },
        0x144426BF0: {0x144426BFD: ("je 0x144426fea", 0x144426FEA)},
        0x144427000: {0x144427017: ("je 0x1444273e5", 0x1444273E5)},
        0x145325220: {
            0x1453254C7: ("jbe 0x1453254ff", 0x1453254FF),
        },
    }
    records = []
    reached_by_entry = {}
    for entry, choices in selections.items():
        rows, graph = decoded[entry]
        selected = dict(graph)
        for site, (expected, target) in choices.items():
            if re.sub(r"\s+", " ", rows[site][1]) != expected or target not in graph[site]:
                raise ValueError(f"Changed guard at {site:#x}")
            selected[site] = [target]
        reached = walk([entry], selected)
        reached_by_entry[entry] = reached
        boundaries = [hex(a) for a in sorted(reached) if rows[a][1] == "external_boundary"]
        if boundaries:
            raise ValueError(f"Selected path reaches unresolved tail: {boundaries}")
        calls = [{"site": hex(a), "instruction": rows[a][1]}
                 for a in sorted(reached) if rows[a][1].startswith("call")]
        records.append({"entry": hex(entry),
                        "branches": {hex(a): hex(t) for a, (_, t) in choices.items()},
                        "calls": calls,
                        "normal_returns": [hex(a) for a in sorted(reached)
                                           if rows[a][1].startswith("ret")],
                        "limits": "CALLs assume normal return; pointer/value derivations documented separately"})
    first = records[0]["calls"]
    if [int(row["site"], 16) for row in first] != [0x1444257BA, 0x14442597F, 0x144425993]:
        raise ValueError("First guard has an unexpected callee")
    if any(record["calls"] for record in records[1:]):
        raise ValueError("A selected short return/helper still has a subcall")

    allowed_stores = {
        0x144425E2A: "C+5fa",
        0x145325340: "M+cde6", 0x14532534D: "M+cde0",
        0x1453253FA: "M+cde6", 0x145325407: "M+cde0",
        0x145325414: "M+cde6", 0x14532541B: "M+cde0",
    }
    stores = []
    for entry, reached in reached_by_entry.items():
        rows = decoded[entry][0]
        for address in sorted(reached):
            instruction = re.sub(r"\s+", " ", rows[address][1])
            first = instruction.split(",", 1)[0]
            if "[" not in first or "[rsp" in first or "[rbp" in first:
                continue
            if instruction.split()[0] in {"cmp", "test", "ucomiss", "comiss", "nop", "cs", "call", "jmp"}:
                continue
            if address not in allowed_stores:
                raise ValueError(f"Unexpected selected nonstack write {address:#x}: {instruction}")
            stores.append({"site": hex(address), "instruction": instruction,
                           "object_binding_manual_derivation": allowed_stores[address]})
    # 本地record+1c从真实stack20+1c生产，不能冻结helper第二参数的内容。
    rows, graph = decoded[0x1444256C0]
    expected = {
        0x144425732: "mov eax,DWORD PTR [rip+0x2003008] # 0x146428740",
        0x14442573C: "mov DWORD PTR [rsp+0x3c],eax",
        0x1444257AF: "lea rdx,[rsp+0x20]",
        0x1444257B4: "mov rcx,rdi",
        0x1444257B7: "mov r8,rsi",
        0x1444257BA: "call 0x145325220",
    }
    for address, ins in expected.items():
        if re.sub(r"\s+", " ", rows[address][1]) != ins:
            raise ValueError(f"Local record source changed: {address:#x}")
    for binding in (0x144425732, 0x14442573C, 0x1444257AF):
        if 0x1444257BA in walk([0x1444256C0], graph, {binding}):
            raise ValueError(f"Actual helper call bypasses local initialization {binding:#x}")
    helper_rows, helper_graph = decoded[0x145325220]
    for address, ins in {
        0x14532527C: "mov rdi,rdx",
        0x1453254A7: "cvtsi2ss xmm0,DWORD PTR [rbx+0x1640]",
        0x1453254BF: "movss xmm1,DWORD PTR [rdi+0x1c]",
        0x1453254C4: "ucomiss xmm1,xmm0",
    }.items():
        if re.sub(r"\s+", " ", helper_rows[address][1]) != ins:
            raise ValueError(f"Helper threshold binding changed: {address:#x}")
    if 0x1453254BF in walk([0x145325220], helper_graph, {0x14532527C}):
        raise ValueError("Helper threshold read bypasses parameter save")
    return {
        "evidence_type": "original_PE_conditional_CFG_not_execution",
        "conditions": [
            "same P/M/C and valid independent storage; existing model normal-return contract",
            "P+11a8 is 0x810 or 0x1810; M+e3bb=0; M+aa4 bit0x10000=1",
            "C+610 may be zero or nonzero; no restriction on first guard scalar x",
            "global146428740=0 at actual local-record initialization; signed P+1640>=0 at helper threshold",
            "P+16f8 bit0=0; M+6a0>23; P+db1=0; finite C+548>float32(0.1112*2)",
        ],
        "functions": records,
        "selected_nonstack_stores": stores,
        "local_record_initialization": {"store": "0x14442573c", "offset": "stack20+1c",
                                        "source": "global146428740; value zero remains a stated condition"},
        "kept_branches": ["C+610 zero/nonzero", "all first-guard scalar x branches", "helper cache hit/miss"],
        "output_boundary": "before actual selector CALL at 0x14441a2d6",
        "allowed_writes_manual_derivation": ["M+cde0/cde6 in local-record helper", "C+5fa=0 in second guard"],
        "unproved": ["natural production/retention of added cache bound and global zero",
                     "M+6a0 source; selector scoring/selection and full shot-to-goal"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(inspect(args.exe), ensure_ascii=False, indent=2) + "\n")
    print("PASS: conditional four-guard paths; local record production; no unresolved tail under stated inputs.")
    print("Not verified: natural cache/global input production, selector behavior, or a goal.")
