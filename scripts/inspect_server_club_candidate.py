"""只读解析FM24 2430完整数据库的CLUB、NATION及TEAM候选记录。

按原生mode=1布局推进；只支持前缀中已恢复的简化财务类型0。
输出是资源记录证据，不证明运行时注册、引用保持或比赛采用。
"""

import argparse
from collections import Counter
import json
import struct
from pathlib import Path

from inspect_client_club_candidate import read_table


class Cursor:
    """保留当前表偏移，按已恢复字段宽度读取；不搜索或猜测下一条记录。"""

    def __init__(self, data: bytes):
        self.data = data
        self.position = 13

    def take(self, size: int) -> bytes:
        """读取完整字段；越界立即停止，避免负长度或截断被误认成成功。"""
        if size < 0 or self.position + size > len(self.data):
            raise ValueError(f"Unsupported field extent at {self.position}: {size}")
        start = self.position
        self.position += size
        return self.data[start:self.position]

    def integer(self, fmt: str = "i") -> int:
        """读取明确有符号性的一个字段。"""
        return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))[0]

    def count(self, fmt: str = "i") -> int:
        """当前资源的非负计数合同；不模拟负计数的异常/分配路径。"""
        offset = self.position
        value = self.integer(fmt)
        if value < 0:
            raise ValueError(f"Unsupported negative count at {offset}: {value}")
        return value

    def text(self) -> str:
        """读取长度32+UTF8字节，与已恢复字符串读者的线性消费对应。"""
        return self.take(self.count()).decode("utf-8")


def read_nation_slot(source: Path, slot: int) -> dict:
    """读取mode1国家表；保留选中槽与完整消费边界，不赋运行时指针。"""
    metadata, table = read_table(source, "server_db/table_10.dat")
    cursor = Cursor(table)
    total = struct.unpack_from("<I", table, 8)[0]
    selected = None
    versions = Counter()
    for row in range(total):
        start = cursor.position
        tag = cursor.integer("B")
        if tag != 0:
            raise ValueError(f"Unsupported NATION tag {tag} at row {row}")
        cursor.take(4)  # R118。
        cursor.take(cursor.count("h") * 4)  # R128引用列表。
        cursor.take(cursor.count() * 4)  # R158四字节列表。
        for _ in range(cursor.count("h")):  # R170，1448d1c10重定位读者。
            cursor.take(1)
            for _ in range(4):
                cursor.text()
            cursor.take(4 + 4 * 4)  # 日期与4个DWORD，混淆长度常量实值为4。
        cursor.take(6 * 4)  # R184..198。
        for _ in range(cursor.count()):  # R60，142638430按条目版本分流。
            version = cursor.integer("B")
            versions[version] += 1
            cursor.take(22 + (2 if version > 1 else 0))
        cursor.take(cursor.count("I") * 12)  # Rd8：DWORD及两个4字节日期。
        size = cursor.count("I")  # R78，1425f5830的重定位体。
        if size >= 0x8000000:
            raise ValueError("Nation R78 count enters native failure branch")
        cursor.take(size * 14)  # 1字节版本、两个DWORD、5个BYTE。
        cursor.take(24)  # 与client共有的固定字段。
        languages = cursor.count("b")
        cursor.take(languages * 5)
        arrays = []
        for width in (28, 28, 12):
            count = cursor.count()
            arrays.append(count)
            cursor.take(count * width)
        cursor.take(10 * 4 + 2 + 1)  # server尾部标量。
        identity_start = cursor.position
        identity = [cursor.integer() for _ in range(3)]
        if identity[0] != row:
            raise ValueError(f"NATION serialized row identity differs at row {row}: {identity}")
        if row == slot:
            selected = {"record_index": row, "record_tag": tag,
                        "record_range": [start, cursor.position],
                        "language_count": languages, "array_counts": arrays,
                        "identity_block_range": [identity_start, cursor.position],
                        "serialized_identity_fields": dict(zip(["R+8", "R+c", "R+10"], identity))}
    if selected is None:
        raise ValueError("Requested nation slot is outside this table")
    return {**metadata, "table_flags": table[12], "declared_record_count": total,
            "records_parsed": total, "all_serialized_row_indices_match": True,
            "R60_item_versions": {str(key): value for key, value in sorted(versions.items())}, "selected": selected,
            "opaque_tail_range": [cursor.position, len(table)],
            "opaque_tail_hex": table[cursor.position:].hex()}


def read_team_slot(source: Path, slot: int) -> dict:
    """按NATIONAL_TEAM/TEAM完整读取链顺序定位球队槽，不用ID搜索定位。"""
    metadata, table = read_table(source, "server_db/table_24.dat")
    cursor = Cursor(table)
    total = struct.unpack_from("<I", table, 8)[0]
    tags = Counter()
    national_items = 0
    for row in range(total):
        start = cursor.position
        tag = cursor.integer("B")
        tags[tag] += 1
        if tag == 0x0B:
            cursor.take(48)  # NATIONAL_TEAM的10个DWORD和8个BYTE。
            items = cursor.count("b")
            national_items += items
            cursor.take(items * 10)  # 1425fc750：版本BYTE、两个DWORD、BYTE。
        elif tag != 0x0A:
            raise ValueError(f"Unsupported TEAM record tag {tag:#x} at row {row}")
        cursor.take(1 + 1 + 2 + 6 * 4 + 1 + 4)
        roster_count = cursor.count("H")
        cursor.take(roster_count * 4)
        cursor.take(8 + 5 + 4 + 1)
        base_start = cursor.position
        scalar_fields = dict(zip(["T+28", "T+2f", "T+29", "T+2c", "T+2d", "T+2e"],
                                 cursor.take(6)))
        parent_start = cursor.position
        parent = cursor.integer()
        name = cursor.text()
        scalar_fields["T+2a"] = cursor.integer("B")
        short_name = cursor.text()
        scalar_fields["T+2b"] = cursor.integer("B")
        identity_start = cursor.position
        identity = [cursor.integer() for _ in range(3)]
        if identity[0] != row:
            raise ValueError(f"TEAM serialized row identity differs at row {row}: {identity}")
        if row == slot:
            return {**metadata, "table_flags": table[12], "declared_record_count": total,
                    "prefix_records_parsed": row + 1, "record_index": row, "record_tag": tag,
                    "record_range": [start, cursor.position], "base_start": base_start,
                    "prefix_tag_counts": {hex(key): value for key, value in sorted(tags.items())},
                    "prefix_national_item_count": national_items,
                    "roster_count": roster_count, "base_scalar_fields": scalar_fields,
                    "serialized_parent_range": [parent_start, parent_start + 4],
                    "serialized_parent_value_T30": parent, "names": [name, short_name],
                    "identity_block_range": [identity_start, cursor.position],
                    "serialized_identity_fields": dict(zip(["T+8", "T+c", "T+10"], identity)),
                    "all_serialized_row_indices_match": True,
                    "remaining_table_bytes_unparsed": len(table) - cursor.position,
                    "limitations": ["Source prefix in mode1 TEAM/NATIONAL_TEAM schemas only",
                                    "Serialized T30 is a CLUB slot value, not a runtime pointer",
                                    "No uninterrupted preservation to CLUB fixup or match adoption"]}
    raise ValueError("Requested TEAM slot is outside the supported prefix")


def read_candidate(source: Path, target_id: int = 0x214EB) -> dict:
    """从首条连续推进至指定普通CLUB；任何未恢复布局立即拒绝。"""
    metadata, table = read_table(source, "server_db/table_3.dat")
    cursor = Cursor(table)
    total = struct.unpack_from("<I", table, 8)[0]
    for row in range(total):
        start = cursor.position
        tag = cursor.integer("B")
        if tag != 0:
            raise ValueError(f"Unsupported derived CLUB tag {tag:#x} at row {row}")
        references = [cursor.integer() for _ in range(5)]
        own_scalars = cursor.take(6).hex()
        names = [cursor.text(), cursor.text()]
        scalar_start = cursor.position
        server_scalars = dict(zip(["C+16a", "C+166", "C+148", "C+16b"],
                                  struct.unpack("<BhiB", cursor.take(8))))
        people = cursor.count("b")
        cursor.take(people * 4)
        finance_selector_offset = cursor.position
        finance = cursor.integer("B")
        if finance != 0:
            raise ValueError(f"Unsupported CLUB finance kind {finance} at row {row}, "
                             f"offset {finance_selector_offset}; no record boundary guessed")
        finance_start = cursor.position
        cursor.take(4 + 1 + 3 + 13 + 4 + 20)  # virtual20 -> 142291ef0：45字节。
        periods = cursor.count("b")
        cursor.take(periods * 24)
        extra = cursor.count("b")
        cursor.take(extra * 12)
        server_tail = dict(zip(["C+168", "C+140"], struct.unpack("<hi", cursor.take(6))))
        base_start = cursor.position
        base_scalars = cursor.take(3).hex()
        reference_counts, reference_values = [], []
        for field in range(5):  # C18/C30无符号计数，C60/C78/C90有符号计数。
            size = cursor.count("B" if field < 2 else "b")
            reference_counts.append(size)
            reference_values.append([cursor.integer() for _ in range(size)])
        group_count = cursor.count("B")
        cursor.take(group_count * 16)
        history_count = cursor.count("h")
        cursor.take(history_count * 28)
        identity_start = cursor.position
        identity = [cursor.integer() for _ in range(3)]
        if identity[0] != row:
            raise ValueError(f"CLUB serialized row identity differs at row {row}: {identity}")
        if identity[1] != target_id:
            continue
        if references[0] < 0 or references[2] != references[0]:
            raise ValueError("Selected source is outside the equal nonnegative nation-reference contract")
        return {**metadata, "declared_record_count": total, "table_flags": table[12],
                "prefix_records_parsed": row + 1, "all_serialized_row_indices_match": True,
                "all_prefix_finance_selectors": [0],
                "record_index": row, "record_tag": tag, "record_range": [start, cursor.position],
                "names": names, "own_scalar_bytes_C160": own_scalars,
                "serialized_reference_values": dict(zip(
                    ["C+d8", "C+e0", "C+e8", "C+f0", "C+f8"], references)),
                "server_scalar_start": scalar_start, "server_scalar_fields": server_scalars,
                "server_tail_fields": server_tail, "finance_selector_offset": finance_selector_offset,
                "finance_payload_range": [finance_start, finance_start + 45],
                "own_array_counts": [people, periods, extra], "base_start": base_start,
                "base_scalar_bytes": base_scalars, "base_reference_counts": reference_counts,
                "base_reference_values": dict(zip(["C+18", "C+30", "C+60", "C+78", "C+90"],
                                                  reference_values)),
                "base_group_count": group_count, "base_history_count": history_count,
                "identity_block_range": [identity_start, cursor.position],
                "serialized_identity_fields": dict(zip(["C+8", "C+c", "C+10"], identity)),
                "remaining_table_bytes_unparsed": len(table) - cursor.position,
                "nation_slot_candidate": read_nation_slot(source, references[0]),
                "limitations": ["Only ordinary tag0 prefix and finance kind0 are supported",
                                "Source record boundaries only; runtime mapping and retention are unproved",
                                "No same-match materializer adoption or natural-score closure"]}
    raise ValueError("Selected CLUB stable ID is not present in the supported prefix")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--club-id", type=lambda value: int(value, 0), default=0x214EB)
    parser.add_argument("--team-slot", type=int, help="按完整TEAM表布局定位指定槽，替代CLUB候选输出")
    args = parser.parse_args()
    result = (read_team_slot(args.source, args.team_slot) if args.team_slot is not None
              else read_candidate(args.source, args.club_id))
    print(json.dumps(result, ensure_ascii=False, indent=2))
