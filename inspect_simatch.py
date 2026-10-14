"""只读解析本机 FM24 simatch 资源，保留成员位置及未缩放的标量候选。

仅支持本次观测到的 FMF 清单与压缩分块，不执行或修改游戏。
两张 QME 表完整结构解码；其他 JSB 数字保留原始字节和 int32 候选。
这些资源声明不能单独当作运行时公式。
"""

import argparse
import json
import re
import struct
from collections import Counter
from pathlib import Path

import zstandard


def decode_qme_table(data: bytes):
    """解码本机两张 QME 表的树及数值；完整消费成员，不推断抽样公式。"""
    cursor = 0

    def read_value():
        nonlocal cursor
        tag = data[cursor]
        cursor += 1
        kind, compact_size = tag & 0x0F, tag >> 4
        if kind == 0:
            return None
        if kind in (2, 7):
            if compact_size:
                return compact_size - 8 if kind == 2 else float(compact_size - 1)
            format_code = "<i" if kind == 2 else "<d"
            value = struct.unpack_from(format_code, data, cursor)[0]
            cursor += struct.calcsize(format_code)
            return value
        if compact_size:
            size = compact_size - 1
        else:
            size = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
        if kind == 8:
            value = data[cursor:cursor + size].decode("utf-8")
            cursor += size
            return value
        if kind == 9:
            return [read_value() for _ in range(size)]
        if kind == 10:
            value = {}
            for _ in range(size):
                key_size = data[cursor]
                cursor += 1
                key = data[cursor:cursor + key_size].decode("utf-8")
                cursor += key_size
                value[key] = read_value()
            return value
        raise ValueError(f"Unsupported QME table tag: {tag:#x}")

    result = read_value()
    assert cursor == len(data), (cursor, len(data))
    return result


def inspect_archive(source: Path) -> dict:
    """按本机归档清单定位成员，并核对解压长度以排除成员错配。"""
    data = source.read_bytes()
    # 本机文件头 +9 指向嵌套 FMF 头前 9 字节；嵌套头长 13 字节。
    manifest_container = struct.unpack_from("<Q", data, 9)[0]
    assert data[manifest_container + 9:manifest_container + 18] == b"\x02\x01fmf.\x08\x00\x00"
    manifest_start = manifest_container + 18
    compressed_size = struct.unpack_from("<I", data, manifest_start)[0]
    decoder = zstandard.ZstdDecompressor()
    manifest = decoder.decompress(
        data[manifest_start + 4:manifest_start + 4 + compressed_size]
    )
    cursor = 0
    members = []

    def integer() -> int:
        nonlocal cursor
        value = struct.unpack_from("<I", manifest, cursor)[0]
        cursor += 4
        return value

    def string() -> str:
        nonlocal cursor
        size = integer()
        value = manifest[cursor:cursor + size].decode("utf-8")
        cursor += size
        return value

    def directory(path: str) -> None:
        nonlocal cursor
        for _ in range(integer()):
            name, extension = string(), string()
            offset, stored_size, plain_size, _, _ = struct.unpack_from(
                "<QQQQQ", manifest, cursor
            )
            cursor += 40
            members.append({
                "path": f"{path}/{name}{extension}",
                "file_offset": offset + 26,
                "stored_size": stored_size,
                "plain_size": plain_size,
            })
        for _ in range(integer()):
            directory(f"{path}/{string()}")

    directory(string())
    assert cursor == len(manifest), (cursor, len(manifest))
    selected = []
    for member in members:
        path = member["path"]
        if not any(term in path for term in (
            "expected_goals/", "physics/", "qme_", "systems.cfg"
        )):
            continue
        start = member["file_offset"]
        end = start + member["stored_size"]
        decoded = bytearray()
        chunks = 0
        while start < end:
            size = struct.unpack_from("<I", data, start)[0]
            start += 4
            decoded.extend(decoder.decompress(data[start:start + size]))
            start += size
            chunks += 1
        assert start == end and len(decoded) == member["plain_size"], path
        record = {**member, "chunks": chunks}
        if path.endswith((".xml", ".cfg")):
            record["text"] = decoded.decode("utf-8-sig")
        elif path.endswith("/qme_stat_relevant_attribute_data.jsb"):
            record["attribute_links"] = decode_qme_table(decoded)["values"]
        elif path.endswith("/qme_distribution_data.jsb"):
            rows = decode_qme_table(decoded)
            record["distribution_summary"] = {
                "record_count": len(rows),
                "distribution_counts": dict(Counter(
                    row["distribution_type"] for row in rows
                )),
                "ability_windows": sorted({
                    tuple(row["ability_window"]) for row in rows
                }),
                "position_count": len({row["position"] for row in rows}),
                "stat_type_count": len({row["stat_type"] for row in rows}),
                "binned_widths": sorted({
                    len(row["mean"]) for row in rows
                    if row["distribution_type"] == "binned"
                }),
                "sample_record": rows[0],
            }
        elif path.endswith(".jsb") and len(decoded) < 10_000:
            # 定位明确长度前缀的键；不宣称恢复了整个 JSB 类型系统。
            values = []
            for match in re.finditer(rb"[a-z][a-z0-9_]{3,}", decoded):
                key = match.group()
                before, after = match.start() - 1, match.end()
                if before < 0 or decoded[before] != len(key):
                    continue
                tag = decoded[after]
                value = {"key": key.decode(), "decoded_offset": match.start(),
                         "tag_hex": hex(tag)}
                if tag == 2:
                    raw = decoded[after + 1:after + 5]
                    value.update(raw_hex=raw.hex(),
                                 signed_le_i32_candidate=struct.unpack("<i", raw)[0])
                values.append(value)
            record["scalar_candidates"] = values
        else:
            record["leading_bytes_hex"] = decoded[:128].hex()
        selected.append(record)
    return {
        "evidence_type": "ordinary-shell-static-observation-not-REA",
        "source": str(source), "source_size": len(data),
        "manifest_offset": manifest_start, "manifest_size": len(manifest),
        "member_count": len(members), "members": selected,
        "limitations": [
            "No target execution, native consumer tracing, numeric scale or units established.",
            "Multiple model versions present; active selection unknown.",
            "Both QME tables are structurally decoded, including compact integers and floats; other JSB members retain raw scalar candidates.",
        ],
    }


def main() -> None:
    """输出可复核观察，显式提供输入与输出路径。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = inspect_archive(args.source)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(f"Input: {args.source}\nOutput: {args.output}\n"
          f"Members: {result['member_count']}; selected: {len(result['members'])}")


if __name__ == "__main__":
    main()
