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
    "20261026_shot_clock_gate_static.txt",
    "20261026_shot_postregion_static.txt",
    "20261027_shot_motion_record_static.txt",
    "20261027_shot_opaque_event_static.txt",
    "20261027_shot_opaque_23bf_static.txt",
    "20261027_shot_goal_time_static.txt",
    "20261027_shot_event_history_static.txt",
    "20261027_shot_event_history_rules_static.txt",
    "20261027_event_resource_loading_static.txt",
    "20261027_event_resource_cache_static.txt",
    "20261027_shot_region_event_entry_static.txt",
    "20261027_goal_region_admission_static.txt",
    "20261027_goal_team_roster_static.txt",
    "20261027_goal_team_roster_continuation_static.txt",
    "20261027_goal_team_update_return_static.txt",
    "20261027_goal_pending_score_entry_static.txt",
    "20261027_goal_score_record_write_static.txt",
    "20261027_goal_after_score_event_static.txt",
    "20261027_goal_event2000_timing_static.txt",
    "20261027_goal_event2000_history_static.txt",
    "20261027_goal_event_vector_append_static.txt",
    "20261028_goal_post_event_timeline_static.txt",
    "20261028_goal_post_timeline_player_swap_static.txt",
    "20261028_goal_record_fixture_timing_static.txt",
    "20261028_goal_record_nonempty_registry_static.txt",
    "20261028_goal_nonempty_collection_static.txt",
    "20261028_goal_payload_latest_matching_static.txt",
    "20261028_goal_post_record_event20f9_static.txt",
    "20261028_goal_event20f9_history_entry_static.txt",
    "20261028_goal_event20f9_history_rule_static.txt",
    "20261028_goal_event_ring_growth_static.txt",
    "20261028_goal_post_event_mode1_return_static.txt",
    "20261028_goal_outer_team_update_entry_static.txt",
    "20261028_goal_team_context_initialization_static.txt",
    "20261028_goal_team_context_geometry_static.txt",
    "20261028_goal_team_context_score_classification_static.txt",
    "20261028_goal_team_context_position_rng_static.txt",
    "20261028_goal_team_context_position_return_static.txt",
    "20261028_goal_team_context_roster_scan_static.txt",
    "20261028_goal_team_update_context_consumer_static.txt",
    "20261028_goal_position_zero_flags_static.txt",
    "20261028_goal_team_zero_state_branch_static.txt",
    "20261028_goal_crossing_geometry_gate_static.txt",
    "20261028_goal_record_index_alignment_static.txt",
    "20261028_goal_initial_record_value_static.txt",
    "20261028_goal_physics_no_contact_record_static.txt",
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

    check(struct.unpack_from("<Q", data, offset(0x145608078 + 0x28))[0]
          == 0x140269570, "FIXTURE_RESULT +28 getter binding")
    check(struct.unpack_from("<f", data, offset(0x145A1D53C))[0] == 30.0,
          "Team geometry comparison constant")
    check(struct.unpack_from("<f", data, offset(0x145A1D4EC))[0] == 5.0,
          "Team geometry distance offset")
    for address, value in ((0x14558DD60, 0.25), (0x145A1D4F0, 6.0),
                           (0x145A1D50C, 12.0)):
        check(struct.unpack_from("<f", data, offset(address))[0] == value,
              f"Crossing prefilter constant {address:x}")

    event_table = 0x1443FF240
    displacement = struct.unpack_from("<i", data, offset(event_table + (0x71 - 0x30) * 4))[0]
    check(event_table + displacement == 0x1443FF215, "Event subtype 0x71 target")

    classifier_table = 0x144394524
    displacement = struct.unpack_from("<i", data, offset(classifier_table + 2 * 4))[0]
    check(classifier_table + displacement == 0x14439451F, "Event 0x2000 classification")
    displacement = struct.unpack_from(
        "<i", data, offset(classifier_table + (0x20F9 - 0x1FFE) * 4)
    )[0]
    check(classifier_table + displacement == 0x144394520, "Event 0x20f9 classification")

    final_table = 0x144399384
    displacement = struct.unpack_from("<i", data, offset(final_table + (0x2000 - 0x1F42) * 4))[0]
    check(final_table + displacement == 0x144398103, "Event 0x2000 final dispatch")

    timeline_table = 0x145306EC4
    for kind, target in ((0, 0x145306622), (1, 0x14530664F)):
        displacement = struct.unpack_from("<i", data, offset(timeline_table + kind * 4))[0]
        check(timeline_table + displacement == target, f"Timeline kind {kind}")

    check(struct.unpack_from("<Q", data, offset(0x145608078 + 0x30))[0]
          == 0x140269580, "FIXTURE_RESULT +30 getter binding")

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
        0x141B5E536: 0x1419FFF30,
        0x141A012A2: 0x141A012C0,
        0x151AF75E8: 0x141B78760,
        0x151AF760D: 0x141B77990,
        0x151AF76DB: 0x1443941A0,
        0x141B7889C: 0x14456CFA0,
        0x141B78EFD: 0x1444C3410,
        0x1444C351D: 0x1443AA3A0,
        0x1443AA4B2: 0x1444D38F0,
        0x1443EC342: 0x1443F4B80,
        0x1443EB101: 0x145300830,
        0x1443EE0FC: 0x145300FC0,
        0x1453023FC: 0x1445671F0,
        0x14456D033: 0x14456E6E0,
        0x14456D0DF: 0x14456E910,
        0x14456E205: 0x141ABED80,
        0x14456D7A8: 0x141AD1B20,
        0x151B9B79A: 0x14557E9B0,
        0x151B9B7A9: 0x14557EA20,
        0x141A9E036: 0x141ABCA90,
        0x141A9E057: 0x141B41670,
        0x141A9E10E: 0x1443941A0,
        0x141A9CE12: 0x144401F10,
        0x141A9CE5E: 0x144401F10,
        0x15A05AF88: 0x145306350,
        0x145306386: 0x141AA3070,
        0x14439D7E3: 0x14557E740,
        0x144394274: 0x1443944F0,
        0x1443944D4: 0x144395230,
        0x141A9C9DD: 0x14557EA20,
        0x141A9CD53: 0x141ABBDD0,
        0x141A9CDAD: 0x144486BB0,
        0x144486E3D: 0x1443FF1F0,
        0x144487021: 0x1443941A0,
        0x141A9C6E1: 0x141AB9390,
        0x141A9C88D: 0x141B85C90,
        0x141B729A1: 0x141B8B8D0,
        0x141B70CEF: 0x141B3CB50,
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
        0x141ABCD38: 0x1443EA8F0,
        0x141ABCD98: 0x1443EA8F0,
        0x141ABCDF8: 0x1443EA8F0,
        0x141ABCE58: 0x1443EA8F0,
        0x141ABD12B: 0x1454E8A4C,
        0x141ABD170: 0x1443D5FA0,
        0x14440515C: 0x141A9B6B0,
        0x141A9B6E2: 0x1443F2870,
        0x144405199: 0x1444A1AA0,
        0x1444051A1: 0x1444A2D70,
        0x1444051D1: 0x1443F0420,
        0x144405212: 0x141AA4050,
        0x14440521C: 0x141A9BAA0,
        0x144405224: 0x1445191C0,
        0x141AA418E: 0x1443F56D0,
        0x141AA423D: 0x1444912F0,
        0x1443F5800: 0x1443EA8F0,
        0x1443F5910: 0x1443EF8F0,
        0x1443F5A1F: 0x1443EA8F0,
        0x141A9BB49: 0x141B3E640,
        0x141A9BB7D: 0x144415F90,
        0x141A9BC04: 0x141B3E640,
        0x141A9BC38: 0x144415F90,
        0x141B3EBF6: 0x1443BF120,
        0x15A172FFE: 0x1443941A0,
        0x144394274: 0x1443944F0,
        0x144405291: 0x1444A3410,
        0x1444A3465: 0x141A9BD20,
        0x1444A36B3: 0x141A8F6F0,
        0x1444A3894: 0x144519C40,
        0x1444A41AA: 0x141A9C120,
        0x151AF75AF: 0x141B70800,
        0x151AF75BB: 0x141B70800,
        0x151AF75DC: 0x141A9C400,
        0x144390D7D: 0x144525B70,
        0x141995355: 0x144365BA0,
        0x1419954E5: 0x144365BA0,
        0x144398279: 0x1418FEF20,
        0x144398483: 0x14439D4B0,
        0x14439D55C: 0x1454E8A4C,
        0x14439D586: 0x14557E730,
        0x14439D5E4: 0x14557E730,
        0x14439D5F6: 0x14557E740,
        0x14439D603: 0x14557E740,
        0x14439D63C: 0x1454E8A90,
        0x14439828E: 0x14557E740,
        0x1443982A3: 0x14557E730,
    }
    jumps = {
        0x14456DD90: 0x15A3B60D0,
        0x141AD1B20: 0x151B9B610,
        0x14456E6E0: 0x15A3C1610,
        0x141A9F498: 0x141AA1AD0,
        0x144398966: 0x144398103,
        0x144401F10: 0x15A05ADE0,
        0x141B85C90: 0x151D5DB40,
        0x1444912F0: 0x15A170F40,
        0x141A9C120: 0x151AF7570,
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
        if binding["symbol"] not in {"malloc", "memmove", "memset", "free"}:
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

    check(struct.unpack_from("<I", data, offset(0x1456B08C4))[0] == 0x3E19999A,
          "Record threshold float32 .15")
    check(struct.unpack_from("<Q", data, offset(0x1456B11C8))[0] == 0x14052D5F0,
          "Classification payload virtual10 binding")
    check(data[offset(0x14052D5F0):offset(0x14052D5F0) + 3] == b"\xb0\x01\xc3",
          "Classification payload AL=1 leaf")
    start = offset(0x141A0165E)
    check(data[start:start + 2] == b"\xff\x15", "Second growth free call")
    check(0x141A01664 + struct.unpack_from("<i", data, start + 2)[0] == 0x145D50E90,
          "Second growth CRT free IAT")

    check(data[offset(0x151525812)] == 0x0F, "Post-region opaque branch constant")
    check(struct.unpack_from("<Q", data, offset(0x157D1CD51))[0] == 0x15A171031,
          "Post-region opaque nonzero target")
    check(struct.unpack_from("<Q", data, offset(0x157D1CD59))[0] == 0x158177F24,
          "Post-region opaque zero target")
    query = {a: ins for a, ins in instructions.items() if 0x1443F56D0 <= a < 0x1443F5C3A}
    check({a for a, ins in query.items() if ins.startswith("call ")} ==
          {0x1443F5800, 0x1443F5910, 0x1443F5A1F}, "Post-region query call domain")
    stores = set()
    for ins in query.values():
        match = re.match(r"(?:mov|movss|movd|movdqa) (?:DWORD|XMMWORD) PTR \[rdi\+0x([0-9a-f]+)\],", ins)
        if match:
            stores.add(int(match[1], 16))
    check(stores == {0xDB0, 0xDB4, 0xDC0, 0xDC4, 0xDC8, 0xDCC},
          "Post-region query direct B store domain")

    # TLS模板只证明文件中的初始化输入，不声称运行期槽值一直未变。
    tls_rva, tls_size = struct.unpack_from("<II", data, optional + 112 + 9 * 8)
    check(tls_rva == 0x5D46470 and tls_size == 40, "TLS directory binding")
    tls_start, tls_end, tls_index, _, tls_zero, _ = struct.unpack_from(
        "<QQQQII", data, offset(0x140000000 + tls_rva))
    check((tls_start, tls_end, tls_index, tls_zero) ==
          (0x15CF4B018, 0x15D6197A0, 0x14638EEC0, 0), "TLS template identity")
    check(tls_end - tls_start == 0x6CE788, "TLS initialized extent")
    check(struct.unpack_from("<Q", data, offset(tls_start + 0x6CCC88))[0] ==
          0xFFFFFFFFC3A20F43, "Opaque TLS template slot")
    for address, expected in ((0x153F65EEB, 0x15A171BD8),
                              (0x153F65EF3, 0x15A173003),
                              (0x156FCE5BE, 0x15A995CE0)):
        check(struct.unpack_from("<Q", data, offset(address))[0] == expected,
              f"Opaque event data pointer {address:x}")
    event_word = struct.unpack_from("<H", data, offset(0x15323BF20))[0]
    check(event_word == 0xF461, "Opaque event word input")
    check(((0x04F7 ^ 0x2A06) + event_word) & 0xFFFF == 0x2352,
          "Event low word under equal shared-page reads")
    # 选定 DL=1/C非空分支；不把另一尾部的2352参数套到此路径。
    for address, expected in ((0x1595B942F, 0x15A17140B),
                              (0x1595B9437, 0x1585FC9FD),
                              (0x1482DA874, 0x1437E87BF),
                              (0x149C0FD29, 0x154E5D153)):
        check(struct.unpack_from("<Q", data, offset(address))[0] == expected,
              f"Selected opaque table {address:x}")
    for displacement, fmt, expected in (
        (0x6CC200, "<Q", 0x775E2D6E), (0x6CC768, "<H", 0xEB65),
        (0x6CCA00, "<B", 0x5E), (0x6CCA40, "<B", 0x44),
        (0x6CCBF0, "<B", 0x57), (0x6CCD08, "<Q", 0x1460CE200),
        (0x6CCA18, "<B", 0xE0), (0x6CCB28, "<I", 0x50618C78),
        (0x6CC618, "<I", 0xDD3B196A),
    ):
        check(struct.unpack_from(fmt, data, offset(tls_start + displacement))[0] == expected,
              f"Selected opaque TLS template {displacement:x}")
    for address, expected in ((0x1492949ED, 0x48), (0x14F09880D, 0x35),
                              (0x157B52FA6, 0x6E)):
        check(data[offset(address)] == expected, f"Selected opaque byte input {address:x}")
    check((0xEB65 + 0x385A) & 0xFFFF == 0x23BF, "Selected event word")
    check((0x775E2D6E & 0xB455F79F) - 0x34542506 == 8,
          "Selected opaque stack adjustment under template")
    check(0x1437E87BF + 0x069F394E == 0x14A1DC10D,
          "Selected opaque indirect target")
    check(0x15E638200 - 0x044C6DF2 == 0x15A17140E,
          "Selected opaque return target")
    check(0x154E5D153 - 0x05EF216B + 0x040B9929 == 0x153024911,
          "Selected opaque second indirect target")
    check(0x15536738D + (0xA6EFFE6F & 0x55F0BC4F) == 0x15A172FDC,
          "Selected opaque final return target")
    check(0x23BF - 0x2248 >= 0x31 and 0x23BF - 0x2002 > 0x342,
          "Selected event classifier AL=0")
    check(struct.unpack_from("<I", data, offset(0x14565294C))[0] == 0x3F733333,
          "Goal substep float32 upper cap .95")
    # 仅核对人工浮点界证明用到的常数；不模拟游戏或替代自然下界证明。
    cap = struct.unpack_from("<f", data, offset(0x14565294C))[0]
    check(cap + 1 / 32 < 1, "Goal-time bounded rounding margin")
    check(0x23BF - 0x1F40 == 0x47F and 0x68 + 4 * 0x47F == 0x1264,
          "Second event resource index and time slot")
    check(0xD848 + 0x47F == 0xDCC7 and 0xDCC7 + 0x4C4 == 0xE18B,
          "Second event side flags")
    check(max(1 + 1 // 2, 1 + 0x32) * 8 == 408,
          "Second event vector allocation size")
    start = offset(0x14439834E)
    check(data[start:start + 2] == b"\xff\x15" and
          0x144398354 + struct.unpack_from("<i", data, start + 2)[0] == 0x145D50E90,
          "Second event old vector free IAT")
    check([((r * 30) >> 32) for r in (0, 1 << 31, (1 << 32) - 1)] == [0, 15, 29],
          "Three-variant weighted-selection example")
    # 几何叶函数整个实际范围无调用和内存写入；不替调用者推断足球含义。
    geometry = {a: ins for a, ins in instructions.items() if 0x141A8F6F0 <= a < 0x141A8F766}
    check(geometry.get(0x141A8F765) == "ret", "Geometry leaf complete")
    for address, ins in geometry.items():
        mnemonic, _, operands = ins.partition(" ")
        destination = operands.split(",", 1)[0]
        check(mnemonic != "call", f"Geometry leaf call {address:x}")
        check("[" not in destination or mnemonic in {"cmp", "test", "ucomiss"},
              f"Geometry leaf memory store {address:x}")
    motion_ranges = ((0x144415F90, 0x144416190), (0x144416228, 0x14441626C),
                     (0x1444162EE, 0x144416336), (0x144416640, 0x144416689))
    check(not any(ins.startswith("call ") for address, ins in instructions.items()
                  if any(lo <= address < hi for lo, hi in motion_ranges)),
          "Selected motion-record blocks have no CALL")
    for kind in (3, 6):
        check(struct.unpack_from("<i", data, offset(0x145C4AD10 + (kind - 1) * 4))[0] == 20,
              f"Motion-record kind {kind} extension duration")

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
        0x141ABCB31: "jb 0x141abcc88",
        0x141ABCD23: "jne 0x141abcd70",
        0x141ABCD82: "jne 0x141abcdc9",
        0x141ABCDDF: "jne 0x141abce1a",
        0x141ABCE45: "jne 0x141abce82",
        0x141ABD09B: "jne 0x141abd0d4",
        0x141ABD0A1: "jne 0x141abd0ea",
        0x141A01602: "jmp 0x141a01655",
        0x141ABD180: "je 0x141abd187",
        0x144405163: "je 0x144405185",
        0x141A9B6CB: "je 0x141a9b6d9",
        0x1443F288C: "je 0x1443f29d7",
        0x1443F29EB: "jns 0x1443f2a0c",
        0x141A9B709: "jne 0x141a9b734",
        0x141A9B73C: "je 0x141a9ba8d",
        0x141A9BA8D: "xor edi,edi",
        0x14440518C: "je 0x144405196",
        0x1443F0542: "cmp BYTE PTR [rdi+0xd66],0x0",
        0x1443F0557: "jl 0x1443f0482",
        0x1443F0590: "jle 0x1443f0484",
        0x1443F05B1: "jle 0x1443f0484",
        0x1443F58C8: "jae 0x1443f58d1",
        0x1443F58E3: "jle 0x1443f59a2",
        0x1443F59A8: "jne 0x1443f5b60",
        0x1443F5A15: "jne 0x1443f5a30",
        0x141AA4256: "jne 0x141aa43ec",
        0x141A9BAAD: "je 0x141a9badb",
        0x141B3E6D6: "je 0x141b3ebe0",
        0x15A170F6B: "sub r9,QWORD PTR [rcx+0x560]",
        0x15A170FF0: "add r13b,BYTE PTR [rax-0x3c155e2]",
        0x144415FD5: "mov QWORD PTR [rdx],r13",
        0x144416018: "jle 0x144416228",
        0x144416267: "jmp 0x144415fcc",
        0x144416163: "je 0x144416190",
        0x14441632A: "je 0x144416340",
        0x14441632F: "je 0x14441637c",
        0x144416331: "jmp 0x144416640",
        0x144416684: "jmp 0x144416300",
        0x15A171BAB: "mov rbx,QWORD PTR [rbp+0x73c98725]",
        0x15A171BB2: "lea rbx,[rbx+0x3c5df0bd]",
        0x15A171BBE: "sete bpl",
        0x15A171BCC: "mov rbp,QWORD PTR [r8+rbp*8]",
        0x15A173004: "add rsp,0xb8",
        0x15A172F76: "mov bp,0x4f7",
        0x15A172F7A: "xor bp,0x2a06",
        0x15A1713D2: "js 0x1542c1661",
        0x15A1713FC: "setne r13b",
        0x15857C553: "lea rsp,[rcx-0x34542506]",
        0x15857C6BF: "jmp r10",
        0x15A171869: "cmovge r14,r9",
        0x15A171874: "jmp r14",
        0x14439450D: "ja 0x144394520",
        0x144394520: "xor eax,eax",
        0x1443942A5: "je 0x1443942e8",
        0x1443942EF: "cmp ebp,0xffffffff",
        0x1443943C0: "mov DWORD PTR [rsp+0x38],r13d",
        0x1443952A3: "mov QWORD PTR [r12+0x13a0],rcx",
        0x1443955FE: "jne 0x144397fa7",
        0x1443EB27D: "minss xmm2,xmm1",
        0x1443EB285: "cvtsi2ss xmm9,esi",
        0x1443EB28A: "addss xmm9,xmm2",
        0x1443EBA0B: "cvttss2si eax,xmm9",
        0x1443EBA10: "mov DWORD PTR [r15+0x1030],eax",
        0x1443EBA60: "mov DWORD PTR [r15+0xd24],esi",
        0x1443EBA67: "mov DWORD PTR [r15+0x1030],esi",
        0x1444A3581: "jne 0x1444a35cf",
        0x1444A36DC: "je 0x1444a3727",
        0x1444A372A: "je 0x1444a37c8",
        0x1444A389B: "je 0x1444a3d4f",
        0x144519C53: "je 0x144519e92",
        0x1444A3DA2: "jae 0x1444a3f1b",
        0x1444A3DBA: "jg 0x1444a3dcd",
        0x1444A3DCF: "jne 0x1444a3df3",
        0x1444A3E24: "je 0x1444a3e37",
        0x1444A415A: "je 0x1444a4183",
        0x151AF75C0: "mov QWORD PTR [rsi+0xe348],rdi",
        0x141B3E6BC: "jle 0x141b3ebfb",
        0x1445191DA: "je 0x144519313",
        0x1445191FA: "jg 0x1445193a4",
        0x144519313: "xor edi,edi",
        0x1445193A4: "mov eax,edi",
        0x144405229: "test al,al",
        0x14440522B: "je 0x144405256",
        0x144405264: "jle 0x1444052a5",
        0x1444A3443: "mov DWORD PTR [rsi+0xa7c],eax",
        0x1444A3457: "mov BYTE PTR [rax+0x330],0x0",
        0x1444A346C: "jne 0x1444a387d",
        0x141A9BD44: "je 0x141a9bd80",
        0x141A9BD80: "xor esi,esi",
        0x144390D3C: "cmp DWORD PTR [rbp+0x570],0x4c4",
        0x144390D46: "jne 0x144392926",
        0x144390DB6: "cmp rax,0x4c4",
        0x14199538C: "mov DWORD PTR [rcx+0x10],eax",
        0x144525BCF: "lea rdx,[rsi+0x38]",
        0x14452601B: "lea rdx,[rbx+0x34]",
        0x14452652F: "lea rdx,[r14+0x38]",
        0x1445266D7: "lea rdx,[rdi+0x34]",
        0x144390A70: "cmp DWORD PTR [rax],0x65767473",
        0x1443913D4: "mov rbx,QWORD PTR [rax+rcx*8]",
        0x144391B50: "cmp DWORD PTR [rdx],0x65766172",
        0x1443920A0: "cmp DWORD PTR [rax],0x70726f62",
        0x1443920D2: "mov WORD PTR [r15+0x34],ax",
        0x1443927D3: "movsx ebx,WORD PTR [rbx+0x34]",
        0x1443927D9: "mov DWORD PTR [rsi+0x38],edx",
        0x144395718: "js 0x144395730",
        0x14439573F: "jb 0x144395760",
        0x144395796: "js 0x1443958c0",
        0x1443958C3: "jne 0x144397f8d",
        0x14439591F: "jne 0x144395a10",
        0x1443962E9: "ja 0x144396469",
        0x14439634D: "ja 0x14439675d",
        0x144396878: "jne 0x1443969d4",
        0x144396C15: "jne 0x1443968b9",
        0x144396F13: "jne 0x144396f73",
        0x144396F86: "je 0x144397054",
        0x144397086: "ja 0x144397eba",
        0x144397F1A: "jne 0x144397f51",
        0x144397F5D: "jne 0x144398838",
        0x144397FCD: "jne 0x144397fe7",
        0x144398009: "mov BYTE PTR [rcx+rax*1+0xd848],0x1",
        0x144398040: "jge 0x144398101",
        0x14439804F: "je 0x144398101",
        0x144398070: "jb 0x144398121",
        0x14439814B: "jg 0x144398383",
        0x144398154: "add rsi,0x32",
        0x144398220: "jae 0x144398323",
        0x1443982DA: "je 0x144398345",
        0x144398445: "mov DWORD PTR [rax+0x8],ecx",
        0x14439846E: "jne 0x144398492",
        0x14439854B: "mov DWORD PTR [r12+rcx*4+0x68],eax",
        0x144398550: "inc WORD PTR [r12+0x38]",
        0x1443985BE: "jne 0x144398753",
        0x1443987C7: "ja 0x1443988e0",
        0x1443988EA: "ja 0x1443989da",
        0x1443989E1: "jne 0x144398103",
        0x144395D4A: "ja 0x144395dc0",
        0x144395E03: "ja 0x1443962be",
        0x1443962E9: "ja 0x144396469",
        0x14439634D: "ja 0x14439675d",
        0x144396768: "jne 0x14439737f",
        0x144396A0A: "jne 0x144396b76",
        0x144396C15: "jne 0x1443968b9",
        0x144396F86: "je 0x144397054",
        0x144397086: "ja 0x144397eba",
        0x14439884E: "jne 0x14439896b",
        0x144398972: "jne 0x144398b40",
        0x144398B69: "je 0x144398be2",
        0x144398F7B: "ja 0x144399177",
        0x1443991C8: "jne 0x144397f8d",
        0x144397FCD: "jne 0x144397fe7",
        0x141A9C574: "jb 0x141a9c5a1",
        0x141A9C587: "jne 0x141a9c5c3",
        0x141A9DD13: "mov QWORD PTR [r15+0xd240],rcx",
        0x141A9DD1A: "mov QWORD PTR [r15+0xe360],r9",
        0x141B716E2: "setne al",
        0x141B716FE: "jne 0x141b71712",
        0x141B7171B: "ja 0x141b711b0",
        0x141B711E5: "je 0x141b71230",
        0x141B711F6: "jbe 0x141b71280",
        0x141B71558: "je 0x141b7157d",
        0x141B7155D: "je 0x141b71570",
        0x141B715CC: "je 0x141b70ab0",
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
