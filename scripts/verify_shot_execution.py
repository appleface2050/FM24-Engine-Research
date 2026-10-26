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

    for action in (0x36, 0x3F):
        table = struct.unpack_from("<i", data, offset(0x144455704 + (action - 1) * 4))[0]
        check(0x144455704 + table == 0x1444535FF, f"Action {action:x} table")
    start = offset(0x145C405FC)
    check(data[start:start + 4] == bytes.fromhex("6f12033a"), "Submission fractional threshold")

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
    }.items():
        check(instructions.get(address) == expected, f"Handoff branch {address:x}")
    print(f"PASS: target identity; {lines} byte lines; {len(calls)} CALLs; "
          f"{len(jumps)} JMPs; CRT import; action table; height/clone leaf write domains; release branch.")
    print("Not verified: natural simultaneous preconditions, intervening defense, full shot-to-goal path.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    verify(parser.parse_args().exe)
