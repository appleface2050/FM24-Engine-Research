"""只读本机FM24数据库的普通CLUB记录前缀；不执行游戏，不解析派生CLUB。

仅适用于已观测的2430 client_db容器和普通记录布局。输出用于核对静态
输入来源，不代表记录已进入同一自然比赛，也不把序列化引用值当稳定ID。
"""

import argparse
import json
import struct
from pathlib import Path

import zstandard


def read_table(source: Path, member_path: str) -> tuple[dict, bytes]:
    """按当前容器布局解出一个表；复用同一清单解析，保留原始位置。"""
    data = source.read_bytes()
    if data[:8] != bytes.fromhex("03017461642ef10d"):
        raise ValueError("Unsupported outer database header")
    archive_header = bytes.fromhex("0201666d662e080000")
    if data[8:17] != archive_header or data[33] != 3:
        raise ValueError("Unsupported database archive framing")
    container = 8 + struct.unpack_from("<Q", data, 17)[0]
    if data[container + 9:container + 18] != archive_header:
        raise ValueError("Manifest header does not match the observed container")
    manifest_start = container + 18
    decoder = zstandard.ZstdDecompressor().decompressobj()
    manifest = decoder.decompress(data[manifest_start:])
    if not decoder.eof or decoder.unused_data:
        raise ValueError("Manifest frame does not end at the source boundary")
    position = 0

    def integer() -> int:
        """读取清单u32并移动游标。"""
        nonlocal position
        value = struct.unpack_from("<I", manifest, position)[0]
        position += 4
        return value

    def text() -> str:
        """读取清单中按字节计长的UTF8字符串。"""
        nonlocal position
        length = integer()
        value = manifest[position:position + length].decode("utf-8")
        position += length
        return value

    members = []

    def directory(path: str) -> None:
        """读取该观测版本的目录/成员清单，不解释后两个不透明QWORD。"""
        nonlocal position
        for _ in range(integer()):
            name, extension = text(), text()
            offset, stored, plain, _, _ = struct.unpack_from("<5Q", manifest, position)
            position += 40
            members.append({"path": path + "/" + name + extension,
                            "offset": offset, "stored_size": stored, "plain_size": plain})
        for _ in range(integer()):
            directory(path + "/" + text())

    directory(text())
    if position != len(manifest):
        raise ValueError("Manifest has unconsumed bytes")
    member = next(item for item in members if item["path"] == member_path)
    start = 34 + member["offset"]
    stop = start + member["stored_size"]
    decoder = zstandard.ZstdDecompressor().decompressobj()
    table = decoder.decompress(data[start:stop])
    if not decoder.eof or decoder.unused_data or len(table) != member["plain_size"]:
        raise ValueError("Selected member frame or plain size differs")
    if table[:8] != data[:8]:
        raise ValueError("Unsupported table header")
    metadata = {
        "source": str(source.resolve()), "source_size": len(data),
        "source_header_hex": data[:34].hex(),
        "manifest_range": [manifest_start, len(data)],
        "manifest_plain_size": len(manifest), "manifest_members": len(members),
        "member": member, "member_compressed_range": [start, stop],
    }
    return metadata, table


def read_nation_slot(source: Path, slot: int) -> dict:
    """按原生client模式布局读取国家表记录；尾部保留为不透明字节。"""
    metadata, table = read_table(source, "client_db/table_10.dat")
    count = struct.unpack_from("<I", table, 8)[0]
    position, selected = 13, None
    for row in range(count):
        start = position
        tag = table[position]
        position += 1
        if tag != 0:
            raise ValueError(f"Unsupported NATION tag at row {row}")
        # 1cb、f0/f8/e8/100、1cc/1d0、1b4、1cd。
        position += 1 + 4 * 4 + 1 + 1 + 4 + 1
        languages = struct.unpack_from("<b", table, position)[0]
        position += 1
        if languages < 0:
            raise ValueError(f"Unsupported NATION language count at row {row}")
        position += languages * 5  # 14260c8b0: int32引用值+byte。
        arrays = []
        for wire_size in (28, 28, 12):
            size = struct.unpack_from("<i", table, position)[0]
            position += 4
            if size < 0:
                raise ValueError(f"Unsupported NATION array count at row {row}")
            arrays.append(size)
            position += size * wire_size
        identity_start = position
        identity = struct.unpack_from("<3i", table, position)
        position += 12
        if row == slot:
            selected = {"record_index": row, "record_tag": tag,
                        "record_range": [start, position],
                        "language_count": languages, "array_counts": arrays,
                        "identity_block_range": [identity_start, position],
                        "serialized_identity_fields": dict(zip(["R+8", "R+c", "R+10"], identity))}
    if selected is None:
        raise ValueError("Requested nation slot is outside this table")
    return {**metadata, "declared_record_count": count, "records_parsed": count,
            "selected": selected, "opaque_tail_range": [position, len(table)],
            "opaque_tail_hex": table[position:].hex(),
            "limitation": "Table10 record candidate only; runtime table identity/mapping phase is not inferred"}


def read_candidate(source: Path, target_id: int) -> dict:
    """从普通CLUB记录首项读至指定C+c，并核对相同引用值的国家槽候选。"""
    metadata, table = read_table(source, "client_db/table_3.dat")
    count = struct.unpack_from("<I", table, 8)[0]
    position = 13  # table头8字节、记录数4字节、表flags1字节。

    def record_integer() -> int:
        """读取普通记录中的有符号32位字段。"""
        nonlocal position
        value = struct.unpack_from("<i", table, position)[0]
        position += 4
        return value

    def record_text() -> str:
        """读取本前缀实际观测到的非负长度UTF8名称。"""
        nonlocal position
        length = record_integer()
        if length < 0 or position + length > len(table):
            raise ValueError(f"Unsupported record string at {position - 4:#x}")
        value = table[position:position + length].decode("utf-8")
        position += length
        return value

    for row in range(count):
        record_start = position
        tag = table[position]
        position += 1
        if tag != 0:
            raise ValueError(f"Unsupported derived record tag {tag:#x} at row {row}; "
                             "prefix parsing stopped without guessing its layout")
        references = [record_integer() for _ in range(5)]
        own_scalars = table[position:position + 6].hex()
        position += 6
        names = [record_text(), record_text()]
        base_scalars = table[position:position + 3].hex()
        position += 3
        id_offset = position
        identity = [record_integer() for _ in range(3)]
        if identity[1] == target_id:
            result = {
                **metadata,
                "declared_record_count": count, "table_flags": table[12],
                "prefix_records_parsed": row + 1, "record_index": row,
                "record_range": [record_start, position], "record_tag": tag,
                "serialized_reference_values": dict(zip(
                    ["C+d8", "C+e0", "C+e8", "C+f0", "C+f8"], references)),
                "own_scalar_bytes_C160": own_scalars, "names": names,
                "base_scalar_bytes": base_scalars,
                "identity_block_range": [id_offset, id_offset + 12],
                "serialized_identity_fields": dict(zip(["C+8", "C+c", "C+10"], identity)),
                "remaining_table_bytes_unparsed": len(table) - position,
                "limitations": [
                    "Only the ordinary tag0 prefix through this candidate is parsed",
                    "Serialized reference values are not assumed to be stable IDs or runtime pointers",
                    "Native stream mode/format branches and reference fixup require separate evidence",
                    "No same-match identity, preservation or final-score closure is established",
                ],
            }
            if references[0] >= 0 and references[0] == references[2]:
                result["nation_slot_candidate"] = read_nation_slot(source, references[0])
            return result
    raise ValueError("Target C+c was not found in the supported prefix")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="本机2430_fm/client_db.dat，只读")
    parser.add_argument("--id", type=lambda value: int(value, 0), default=0x214EB,
                        help="目标C+c，默认0x214eb")
    parser.add_argument("--output", type=Path, help="可选：写最小候选记录JSON，不导出原数据表")
    args = parser.parse_args()
    result = read_candidate(args.source, args.id)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
