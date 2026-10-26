"""复核射门研究的原 PE 转录、直接调用与局部条件；不执行游戏或证明整场行为。"""

import argparse
import json
import re
import struct
from pathlib import Path

from verify_goal_lifecycle import verify_target_identity


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (
    "20261026_shot_submission_flight_static.txt",
    "20261026_shot_dispatch_continuity_static.txt",
    "20261026_shot3f_submission_static.txt",
    "20261026_shot_ball_handoff_static.txt",
    "20261026_shot_synchronous_event_static.txt",
    "20261026_shot_postcopy_sampling_static.txt",
    "20261026_shot_prediction_stop_static.txt",
    "20261026_shot_record_model_static.txt",
    "20261026_shot_record_attachment_static.txt",
    "20261020_payload_allocator_boundary_static.txt",
)


def verify(exe: Path) -> None:
    """绑定既有目标身份，核对指令转录、转移及导入/分派表。"""
    data = exe.read_bytes()
    identity = json.loads((ROOT / "20261019_fm24_target_identity.json").read_text())
    verify_target_identity(data, identity)
    pe = struct.unpack_from("<I", data, 60)[0]
    optional = pe + 24
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    sections = [
        struct.unpack_from("<IIII", data, optional + optional_size + i * 40 + 8)
        for i in range(count)
    ]

    def offset(address):
        """仅映射有文件字节的 VA，不把虚拟零填充当成原文件证据。"""
        for _, rva, raw_size, raw in sections:
            if rva <= address - 0x140000000 < rva + raw_size:
                return raw + address - 0x140000000 - rva
        raise AssertionError(f"No file bytes for {address:x}")

    def check(condition, message):
        """不依赖可被 python -O 禁用的 assert。"""
        if not condition:
            raise AssertionError(message)

    lines = 0
    instructions = {}
    for filename in EVIDENCE:
        text = (ROOT / filename).read_text()
        check("(bad)" not in text and ".byte" not in text, filename)
        for line in text.splitlines():
            match = re.match(r"^\s+([0-9a-f]+):\s*((?:[0-9a-f]{2}(?:[ \t]+|$))+)", line)
            if match:
                address = int(match[1], 16)
                expected = bytes.fromhex(match[2])
                start = offset(address)
                check(data[start:start + len(expected)] == expected, f"Bytes {address:x}")
                lines += 1
                fields = line.split("\t", 2)
                if len(fields) == 3 and fields[2].strip():
                    instructions[address] = re.sub(r"\s+", " ", fields[2].strip())

    calls = {
        0x144420076: 0x1444290E0,
        0x14441A2D6: 0x14441FFF0,
        0x15A11E608: 0x144417950,
        0x15A11E640: 0x1454E8A90,
        0x144452E62: 0x141B41670,
        0x144453679: 0x1443F1070,
        0x1444536ED: 0x1443ECC70,
        0x14445430D: 0x1443F1070,
        0x14445474E: 0x141ABCA90,
        0x15A0CA1B1: 0x1444482E0,
        0x14442958A: 0x14444ACC0,
        0x14442959A: 0x14444A4E0,
        0x14444AB53: 0x14443E9D0,
        0x14444B643: 0x14443E9D0,
        0x1443EDC82: 0x14557E720,
        0x1443EDCEA: 0x14557E740,
        0x1443EDEA2: 0x145300B10,
        0x1443EDED9: 0x14557E720,
        0x1443EE1B1: 0x14557E720,
        0x1443EE2C3: 0x1443EA8F0,
        0x1445298FA: 0x14452AEB0,
        0x144529912: 0x14452AEB0,
        0x14452ABAE: 0x144386FA0,
        0x14444A5B2: 0x141B50E00,
        0x14444B0EF: 0x141B50E00,
        0x1443EAC9F: 0x1453017D0,
        0x1443F1613: 0x1443D7F50,
        0x1443F1B8A: 0x141B6C7E0,
        0x1443F1E81: 0x141B6C7E0,
        0x1443F1E89: 0x141B6C7E0,
        0x144454474: 0x141B7FFC0,
        0x144454546: 0x1443FA490,
        0x1444545A6: 0x1443FA490,
        0x1443944D4: 0x144395230,
        0x1444543D3: 0x144485880,
        0x1444543FD: 0x144482710,
        0x14439838B: 0x141AD3400,
        0x144398537: 0x14439D690,
        0x14445442C: 0x141ABEF60,
        0x144454445: 0x141ACB310,
        0x151B724CA: 0x144408CC0,
        0x151B72553: 0x144408CC0,
        0x144454696: 0x1443EA8F0,
        0x1444546D6: 0x1443EA8F0,
        0x144454718: 0x1443EA8F0,
        0x141ABCAD4: 0x141AAC200,
        0x141ABCAE7: 0x144528BB0,
        0x141ABCB25: 0x1443D5FA0,
        0x141A0159F: 0x1418FEF20,
        0x141A015BC: 0x14557E730,
        0x1418FEFC4: 0x1452ED750,
        0x141A001DA: 0x141A00660,
        0x141A001F7: 0x141A01200,
        0x141A012A2: 0x141A012C0,
        0x141B5E68D: 0x141AD19D0,
        0x141AAC391: 0x1443D4E90,
        0x1454E8A66: 0x14557E810,
    }
    jumps = {
        0x15A11E653: 0x144450B80,
        0x1454E8A90: 0x1454E8A88,
        0x1454E8A88: 0x14557E7E0,
        0x144425674: 0x144445EA0,
        0x144445EA0: 0x15A0C9F80,
        0x1443D7F50: 0x159F8CEA0,
        0x1443F1EC5: 0x141B6C7E0,
        0x141B7FFC0: 0x151D37610,
        0x141AD3400: 0x151BB13E0,
        0x141ACB310: 0x151B72450,
    }
    for opcode, edges in ((0xE8, calls), (0xE9, jumps)):
        for address, target in edges.items():
            start = offset(address)
            actual = address + 5 + struct.unpack_from("<i", data, start + 1)[0]
            check(data[start] == opcode and actual == target, f"Transfer {address:x}")

    start = offset(0x14557E7E0)
    check(data[start:start + 2] == b"\xff\x25", "CRT free thunk opcode")
    slot = 0x14557E7E6 + struct.unpack_from("<i", data, start + 2)[0]
    check(slot == 0x145D50E90, "CRT free thunk slot")
    # 依据既有原 PE 导入记录，复核其 descriptor/lookup/name，不读取运行时 IAT。
    descriptor = struct.unpack_from("<IIIII", data, offset(0x15CF4A294))
    index = (slot - 0x140000000 - descriptor[4]) // 8
    lookup = 0x140000000 + descriptor[0] + 8 * index
    check(lookup == 0x145D4EFA8, "CRT import lookup slot")
    name_rva = struct.unpack_from("<Q", data, offset(lookup))[0]
    name_start = offset(0x140000000 + name_rva) + 2
    dll_start = offset(0x140000000 + descriptor[3])
    check(data[name_start:data.index(b"\0", name_start)] == b"free", "CRT symbol")
    check(data[dll_start:data.index(b"\0", dll_start)] == b"api-ms-win-crt-heap-l1-1-0.dll", "CRT DLL")

    descriptor = struct.unpack_from("<IIIII", data, offset(0x15CF4A03C))
    index = (0x145D4FAB8 - 0x140000000 - descriptor[4]) // 8
    lookup = 0x140000000 + descriptor[0] + 8 * index
    check(lookup == 0x145D4DBD0, "Pool pop lookup slot")
    name_rva = struct.unpack_from("<Q", data, offset(lookup))[0]
    name_start = offset(0x140000000 + name_rva) + 2
    dll_start = offset(0x140000000 + descriptor[3])
    check(data[name_start:data.index(b"\0", name_start)] == b"InterlockedPopEntrySList",
          "Pool pop import symbol")
    check(data[dll_start:data.index(b"\0", dll_start)] == b"KERNEL32.dll", "Pool pop DLL")
    # 复用已有分配边界的原PE导入身份，不把导入名称当成DLL实现验证。
    allocator = json.loads((ROOT / "20261020_payload_allocator_boundary_observations.json").read_text())
    for binding in allocator["import_bindings"]:
        if binding["symbol"] not in {"malloc", "memmove"}:
            continue
        descriptor = struct.unpack_from("<IIIII", data, offset(int(binding["descriptor"], 16)))
        slot = int(binding["iat"], 16)
        index = (slot - 0x140000000 - descriptor[4]) // 8
        lookup = 0x140000000 + descriptor[0] + 8 * index
        check(lookup == int(binding["lookup"], 16), f"Allocator lookup {binding['symbol']}")
        hint = 0x140000000 + struct.unpack_from("<Q", data, offset(lookup))[0]
        check(hint == int(binding["hint_name"], 16), f"Allocator name pointer {binding['symbol']}")
        start = offset(hint) + 2
        check(data[start:data.index(b"\0", start)].decode() == binding["symbol"], "Allocator symbol")
        start = offset(0x140000000 + descriptor[3])
        check(data[start:data.index(b"\0", start)].decode() == binding["dll"], "Allocator DLL")

    for action in (0x36, 0x3F):
        table = struct.unpack_from("<i", data, offset(0x144455704 + (action - 1) * 4))[0]
        check(0x144455704 + table == 0x1444535FF, f"Action {action:x} table")
    start = offset(0x145C405FC)
    check(data[start:start + 4] == bytes.fromhex("6f12033a"), "Submission fractional threshold")
    table = struct.unpack_from("<i", data, offset(0x144486B98))[0]
    check(0x144486B80 + table == 0x1444858AE, "Action 3f event producer")
    for code in (0x1FAA, 0x1FAE):
        slot = 0x144399384 + (code - 0x1F42) * 4
        relative = struct.unpack_from("<i", data, offset(slot))[0]
        check(0x144399384 + relative == 0x144398103, f"Event {code:x} return table")
    check(struct.unpack_from("<f", data, offset(0x145A1D534))[0] == 25.0,
          "Event distance coefficient")
    check(struct.unpack_from("<f", data, offset(0x145A1D5A0))[0] == 0.9150000214576721,
          "Event distance scale")
    check(struct.unpack_from("<f", data, offset(0x145A1D45C))[0] == 0.0,
          "Cached sample fractional threshold")
    encoded = struct.unpack_from("<I", data, offset(0x1546EEAD4))[0]
    check(encoded ^ 0x24048968 == 0x20, "Second team sample stack output")
    kind_target = struct.unpack_from("<i", data, offset(0x14452AEA4))[0]
    check(0x14452AE90 + kind_target == 0x144529D7E, "Action 3f model kind branch")
    check(struct.unpack_from("<Q", data, offset(0x145A19548))[0] == 0x141AD36A0,
          "Model payload type vtable slot")
    check(struct.unpack_from("<f", data, offset(0x145643730))[0] == 0.699999988079071,
          "Model kind upper threshold")
    check(struct.unpack_from("<f", data, offset(0x1456B08C4))[0] == 0.15000000596046448,
          "Model kind lower threshold")
    check(struct.unpack_from("<f", data, offset(0x145582410))[0] == 1.0,
          "Payload accumulation unit constant")
    start = offset(0x14557E810)
    check(data[start:start + 2] == b"\xff\x25", "Model malloc thunk")
    check(0x14557E816 + struct.unpack_from("<i", data, start + 2)[0] == 0x145D50E98,
          "Model malloc IAT binding")
    target = struct.unpack_from("<i", data, offset(0x1443D5F88))[0]
    check(0x1443D5F54 + target == 0x1443D5C0D, "Native event type15 association slot")

    # 对本次真正依赖的短叶函数，额外检查控制流和写入域；不扩展为通用模拟器。
    leaf = {a: ins for a, ins in instructions.items() if 0x141B50E00 <= a < 0x141B50EE8}
    check(leaf.get(0x141B50E00) == "mov rax,rdx", "Height leaf output binding")
    writes = {}
    for address, instruction in leaf.items():
        parts = instruction.split(" ", 1)
        mnemonic = parts[0]
        operands = parts[1] if len(parts) == 2 else ""
        destination = operands.split(",", 1)[0]
        check(mnemonic not in {"call", "push", "pop", "stos", "stosb", "stosd", "stosq"},
              f"Height leaf unexpected effect at {address:x}")
        if destination in {"rax", "eax", "ax", "al", "ah"}:
            check(address == 0x141B50E00, f"Height leaf output pointer changed {address:x}")
        if "[" in destination and mnemonic not in {"cmp", "test", "ucomiss", "comiss"}:
            writes[address] = instruction
        if mnemonic.startswith("j"):
            check(0x141B50E00 <= int(operands, 16) < 0x141B50EE8,
                  f"Height leaf external branch {address:x}")
    check(writes == {0x141B50EE3: "movss DWORD PTR [rax],xmm1"}, "Height leaf write domain")
    check(leaf.get(0x141B50EE7) == "ret", "Height leaf return")

    # 延迟行动复制叶：限定 RCX 输出区，并保留真实存在的固定全局写入。
    leaf = {a: ins for a, ins in instructions.items() if 0x159F8CEA0 <= a < 0x159F8D07D}
    stores = 0
    for address, instruction in leaf.items():
        parts = instruction.split(" ", 1)
        mnemonic = parts[0]
        operands = parts[1] if len(parts) == 2 else ""
        destination = operands.split(",", 1)[0]
        check(mnemonic in {"mov", "movaps", "movsx", "movzx", "test", "je", "jmp",
                           "xor", "lea", "sub", "ret"}, f"Clone leaf effect {address:x}")
        check(destination not in {"rcx", "ecx", "cx", "cl", "ch"},
              f"Clone leaf output pointer changed {address:x}")
        if mnemonic.startswith("j"):
            check(0x159F8CEA0 <= int(operands, 16) < 0x159F8D07D,
                  f"Clone leaf external branch {address:x}")
        if "[" in destination and mnemonic not in {"test"}:
            if address == 0x159F8CF2E:
                check(instruction == "sub QWORD PTR [rax],0xffffffff90a20f90",
                      "Clone leaf fixed global operation")
                continue
            match = re.fullmatch(r"(XMMWORD|QWORD|DWORD|WORD|BYTE) PTR \[rcx(?:\+0x([0-9a-f]+))?\]",
                                 destination)
            check(match is not None and mnemonic in {"mov", "movaps"},
                  f"Clone leaf unexpected store {address:x}")
            width = {"XMMWORD": 16, "QWORD": 8, "DWORD": 4, "WORD": 2, "BYTE": 1}[match[1]]
            displacement = int(match[2] or "0", 16)
            check(displacement + width <= 0xC2, f"Clone leaf output extent {address:x}")
            stores += 1
    check(stores > 0 and leaf.get(0x159F8D07C) == "ret", "Complete clone leaf")
    check(leaf.get(0x159F8CF27, "").startswith("lea rax,[rip+0x1eead92]"),
          "Clone leaf fixed global pointer")
    check(0x159F8CF2E + 0x1EEAD92 == 0x15BE77CC0, "Clone leaf global address")
    check(instructions.get(0x141B6C7F0) == "lock dec DWORD PTR [rcx]",
          "Reference release decrement")
    check(instructions.get(0x141B6C7F3) == "jne 0x141b6c87d",
          "Reference release nonzero branch")
    check(instructions.get(0x141B6C88D) == "ret", "Reference release early return")

    # 完整载荷 writer：检查除栈之外的显式写入及唯一调用，条件仍由报告限定。
    writer = {a: ins for a, ins in instructions.items() if 0x141ABEF60 <= a < 0x141ABF233}
    writes = {}
    writer_calls = []
    for address, instruction in writer.items():
        mnemonic, _, operands = instruction.partition(" ")
        destination = operands.split(",", 1)[0]
        if mnemonic == "call":
            writer_calls.append((address, operands))
        if mnemonic.startswith("j"):
            check(0x141ABEF60 <= int(operands, 16) < 0x141ABF233,
                  f"Payload writer external branch {address:x}")
        if "[" in destination and mnemonic not in {"cmp", "test", "nop", "cs"}:
            if "[rsp+" not in destination:
                writes[address] = instruction
    check(writer_calls == [(0x141ABF224, "0x141ad2c20")], "Payload writer sole growth call")
    check(writes == {
        0x141ABF17D: "movaps XMMWORD PTR [r10],xmm0",
        0x141ABF188: "movaps XMMWORD PTR [r10+0x10],xmm0",
        0x141ABF1FF: "movaps XMMWORD PTR [rdx+0x30],xmm3",
        0x141ABF203: "movaps XMMWORD PTR [rdx+0x20],xmm2",
        0x141ABF207: "movaps XMMWORD PTR [rdx+0x10],xmm1",
        0x141ABF20B: "movaps XMMWORD PTR [rdx],xmm0",
        0x141ABF20E: "add QWORD PTR [rcx+0xe228],0x40",
    }, "Payload writer explicit non-RSP stores")
    check(writer.get(0x141ABF115) == "lea r10,[rsp+0x30]", "Payload stack alias")
    check(writer.get(0x141ABF1DB) == "mov rdx,QWORD PTR [rcx+0xe228]", "Payload end alias")
    check(writer.get(0x141ABF232) == "ret", "Payload writer complete return")
    # 只核对实际空列表分支与调用者对输出/返回值的使用，不推断列表自然为空。
    for address, expected in {
        0x151D3763B: "je 0x151d37833",
        0x151D37835: "mov BYTE PTR [r15+0x2],al",
        0x144454479: "cmp BYTE PTR [rsp+0xfa],0x0",
        0x144454481: "je 0x144454532",
        0x1443FA4B3: "je 0x1443faa94",
        0x1443FAA94: "xor eax,eax",
        0x14445454B: "test rax,rax",
        0x14445454E: "je 0x14445458b",
        0x1444545AB: "test rax,rax",
        0x1444545AE: "je 0x1444545f2",
        0x1443943C5: "cmp ebp,r12d",
        0x1443943C8: "jle 0x1443944c3",
        0x1443955E9: "je 0x144397fe7",
        0x14439814B: "jg 0x144398383",
        0x14439847C: "ja 0x144398492",
        0x1443984C9: "jne 0x1443984e7",
        0x144398522: "je 0x144398529",
        0x14439D6BD: "ja 0x14439d813",
        0x14439D816: "mov QWORD PTR [rdi+r15*8],rax",
        0x151BB1432: "jne 0x151bb1466",
        0x144398753: "mov bpl,0x1",
        0x144398103: "mov eax,ebp",
        0x141ABF1E9: "je 0x141abf218",
        0x144408CDB: "jbe 0x144408d10",
        0x144408D20: "jne 0x144408d3c",
        0x144408D28: "jge 0x144408d3c",
        0x151B724D3: "mov DWORD PTR [rbp+0x1464],eax",
        0x151B7255C: "mov DWORD PTR [rbp+0x1464],eax",
        0x1443EAAE5: "lea ecx,[r11+rdi*1]",
        0x1443EAAF4: "cmovne eax,ecx",
        0x1443EC777: "mov ecx,DWORD PTR [rsp+0x60]",
        0x1443EC786: "add ecx,0x4",
        0x1443EC78D: "jg 0x1443ec797",
        0x1443EC78F: "movzx eax,BYTE PTR [r13+0x85]",
        0x1443EC797: "mov BYTE PTR [r15+0xd62],al",
        0x1443EA969: "jne 0x1443ec921",
        0x145302BE9: "shr cl,0x7",
        0x145302BEC: "mov BYTE PTR [rsi+0x85],cl",
        0x145302BFC: "mov BYTE PTR [rsi+0x85],0x1",
        0x1443EAC50: "mov QWORD PTR [rsp+0x58],rcx",
        0x1443EAD70: "lea r11,[r8+0x1]",
        0x1443EAE64: "mov QWORD PTR [rsp+0x78],r11",
        0x1443EB931: "mov r11,QWORD PTR [rsp+0x78]",
        0x1443EC395: "mov r12,r11",
        0x1443EC449: "mov rsi,r11",
        0x1443EC505: "mov r11,rsi",
        0x1443EC699: "mov r11,r12",
        0x144528CC5: "je 0x144528d7d",
        0x144528D7D: "movaps xmm0,XMMWORD PTR [r12+0x8e10]",
        0x144529C2D: "je 0x144529c68",
        0x144529D40: "mov eax,DWORD PTR [r12+0x8e80]",
        0x144529D87: "mov BYTE PTR [r15+0x34],0x7",
        0x144529D9E: "mov BYTE PTR [r15+0x34],0xa",
        0x144529DA8: "mov BYTE PTR [r15+0x34],0x2",
        0x141AD36A0: "mov al,0x2",
        0x141AD36A2: "ret",
        0x1443D613E: "movss DWORD PTR [rax+0x30],xmm1",
        0x1443D614D: "movss DWORD PTR [r12+0x1c8],xmm1",
        0x1443D574B: "mov ecx,0x203008",
        0x1443D5A85: "mov DWORD PTR [rbx+0x1c8],0x0",
        0x141A00016: "mov QWORD PTR [r12+0x48],0x0",
        0x141A0001F: "mov QWORD PTR [r12+0x50],0x0",
        0x141A00028: "mov QWORD PTR [r12+0x58],0x0",
        0x141AD1A92: "jne 0x141ad1aca",
        0x141AD1A97: "jne 0x141ad1ade",
        0x1443D57BF: "je 0x1443d5a7e",
        0x1443D5C16: "je 0x1443d5ec0",
        0x141AAC3A3: "jne 0x141aac3de",
        0x141A01548: "je 0x141a01557",
        0x141A015C4: "je 0x141a015df",
        0x141A015E6: "je 0x141a01664",
        0x141A0167E: "je 0x141a0169e",
        0x1418FEF30: "je 0x1418fefb9",
        0x1452ED774: "jne 0x1452ed820",
        0x1454E8A6E: "je 0x1454e8a57",
    }.items():
        check(instructions.get(address) == expected, f"Handoff branch {address:x}")
    print(f"PASS: target identity; {lines} byte lines; {len(calls)} CALLs; "
          f"{len(jumps)} JMPs; CRT/pool imports; action/event tables; "
          "height/clone/payload write domains; release/event/sample branches.")
    print("Not verified: natural simultaneous preconditions, intervening defense, full shot-to-goal path.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    verify(parser.parse_args().exe)
