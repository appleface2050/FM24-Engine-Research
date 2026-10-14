"""读取 FM24 PE 文件，定位射门调查的字符串与直接调用候选；不执行游戏。"""

import argparse
import bisect
import json
from pathlib import Path
import re
import struct


def scan(path: Path) -> dict:
    """扫描本次 FM24 布局中的 .idata/.sdata；候选须另行核对指令边界。"""
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    sections = {}
    for index in range(count):
        position = optional + optional_size + index * 40
        name = data[position:position + 8].rstrip(b"\0").decode()
        _, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, position + 8)
        sections[name] = (rva, raw_offset, raw_size)

    def offset(rva):
        for start, raw, size in sections.values():
            if start <= rva < start + size:
                return raw + rva - start
        raise ValueError(f"RVA not file-backed: {rva:#x}")

    exception_rva, exception_size = struct.unpack_from("<II", data, optional + 136)
    exception_offset = offset(exception_rva)
    functions = [struct.unpack_from("<III", data, position)
                 for position in range(exception_offset,
                                       exception_offset + exception_size, 12)]
    starts = [row[0] for row in functions]

    def owner(address):
        rva = address - image_base
        index = bisect.bisect_right(starts, rva) - 1
        if index >= 0 and rva < functions[index][1]:
            return {"start": hex(image_base + functions[index][0]),
                    "end_exclusive": hex(image_base + functions[index][1])}
        return None

    rva, raw, size = sections[".idata"]
    strings = {}
    selected_names = {
        "add_goal_to_stats", "assess_area_status", "iterate_path",
        "is_going_out_before", "is_hitting_woodwork_before",
        "set_ball_on_new_trajectory", "get_target_time",
        "is_end_time_greater_than", "is_target_time_greater_than",
    }
    for match in re.finditer(rb"[\x20-\x7e]{6,}", data[raw:raw + size]):
        text = match.group().decode()
        if (text in selected_names or text.startswith("end_shot_") or "MATCH_BALL::" in text
                or "MATCH_PLAYER::add_event()" in text
                or "goal which wasn't a shot" in text
                or "record of where it crossed the goalline" in text):
            strings[image_base + rva + match.start()] = text

    rva, raw, size = sections[".sdata"]
    code = data[raw:raw + size]
    references = []
    for match in re.finditer(
            rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d][\s\S]{4}", code):
        address = image_base + rva + match.start()
        target = address + 7 + struct.unpack_from("<i", match.group(), 3)[0]
        if target in strings:
            references.append({"instruction": hex(address), "target": hex(target),
                               "bytes": match.group().hex(), "owner": owner(address),
                               "text": strings[target]})

    targets = (0x144528BB0, 0x141ABCA90, 0x141ABD270, 0x141A9C400,
               0x141AADD50, 0x1443B5100,
               0x1443F0420, 0x144482710, 0x1444829F0,
               0x1443ECC70, 0x1443F2EF0, 0x144513020, 0x14450A690,
               0x144475C40)
    calls = {hex(target): [] for target in targets}
    for match in re.finditer(rb"\xe8[\s\S]{4}", code):
        address = image_base + rva + match.start()
        target = address + 5 + struct.unpack_from("<i", match.group(), 1)[0]
        if hex(target) in calls:
            calls[hex(target)].append({"instruction": hex(address),
                                      "bytes": match.group().hex(), "owner": owner(address)})
    # 此目标版本中发现的名称表；QWORD 布局与编号不自动代表比赛判定枚举。
    table = []
    for index in range(5):
        address = 0x145A18530 + 24 * index
        pointer, length, value = struct.unpack_from("<QQQ", data, offset(address - image_base))
        position = offset(pointer - image_base)
        name = data[position:data.index(b"\0", position)].decode()
        table.append({"record": hex(address), "string": hex(pointer),
                      "length_field": length, "id": value, "name": name})
    dispatch_base = 0x141AAC4A0
    dispatch_offset = offset(dispatch_base - image_base)
    dispatch = [
        {"area_code": index + 1,
         "destination": hex(dispatch_base + struct.unpack_from(
             "<i", data, dispatch_offset + index * 4)[0])}
        for index in range(6)
    ]
    constants = []
    for address in (0x145A1D404, 0x145A1D408, 0x145A1D410,
                    0x1456B08C4, 0x1455A9800, 0x145A1D550, 0x145A1D51C,
                    0x145A1D534, 0x1458704A0, 0x145A1D45C, 0x145A1D4A4,
                    0x145A1D4D4, 0x145A1D4C8):
        position = offset(address - image_base)
        constants.append({"address": hex(address), "bytes": data[position:position + 4].hex(),
                          "float32": struct.unpack_from("<f", data, position)[0]})
    return {
        "kind": "ordinary-tool static candidates; not REA native dossier",
        "source": path.name, "image_base": hex(image_base), "file_size": len(data),
        "boundary": "ASCII runs >=6 in .idata; raw RIP-relative LEA and E8 in .sdata",
        "limitation": "Raw patterns may begin inside another instruction or data. PE exception ranges are containment hints, not proven complete function bodies. Indirect calls and other addressing forms are not covered.",
        "shot_end_name_table": table,
        "area_dispatch_table": dispatch,
        "constants": constants,
        "string_references": references, "direct_call_candidates": calls,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(f"scan_shot_boundaries input={args.binary} output={args.output}", flush=True)
    result = scan(args.binary)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(f"Done: string references={len(result['string_references'])}, "
          f"direct-call candidates={sum(map(len, result['direct_call_candidates'].values()))}",
          flush=True)
