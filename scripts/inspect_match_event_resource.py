"""只读提取 FM24 比赛事件资源中的两个记录；不执行游戏。"""

import argparse
import struct
import xml.etree.ElementTree as ET
from pathlib import Path

import zstandard


def find_member(data: bytes, wanted: str) -> tuple[int, int, int]:
    """从本机 FMF 清单取得目标成员位置；消费完整清单以避免截断错配。"""
    container = struct.unpack_from('<Q', data, 9)[0]
    if data[container + 9:container + 18] != b'\x02\x01fmf.\x08\x00\x00':
        raise ValueError('unexpected manifest header')
    start = container + 18
    size = struct.unpack_from('<I', data, start)[0]
    manifest = zstandard.ZstdDecompressor().decompress(data[start + 4:start + 4 + size])
    cursor = 0
    matches = []

    def integer():
        nonlocal cursor
        value = struct.unpack_from('<I', manifest, cursor)[0]
        cursor += 4
        return value

    def string():
        nonlocal cursor
        length = integer()
        value = manifest[cursor:cursor + length].decode('utf-8')
        cursor += length
        return value

    def directory(path):
        nonlocal cursor
        for _ in range(integer()):
            name, extension = string(), string()
            position, stored, plain, _, _ = struct.unpack_from('<QQQQQ', manifest, cursor)
            cursor += 40
            if f'{path}/{name}{extension}' == wanted:
                matches.append((position + 26, stored, plain))
        for _ in range(integer()):
            directory(f'{path}/{string()}')

    directory(string())
    if cursor != len(manifest) or len(matches) != 1:
        raise ValueError('manifest incomplete or event member ambiguous')
    return matches[0]


def inspect(source: Path):
    """读取事件110和1151的变体数与权重，不推断运行时实际加载。"""
    data = source.read_bytes()
    start, stored, plain = find_member(data, 'simatch/events/match_events.xml')
    end = start + stored
    decoder = zstandard.ZstdDecompressor()
    result = bytearray()
    while start < end:
        size = struct.unpack_from('<I', data, start)[0]
        start += 4
        result.extend(decoder.decompress(data[start:start + size]))
        start += size
    if start != end or len(result) != plain:
        raise ValueError('event member size mismatch')
    root = ET.fromstring(result)
    events = root.find("list[@id='evts']")
    if events is None:
        raise ValueError('missing evts')
    ids = [int(event.find("integer[@id='id']").get('value')) for event in events]
    print(f'events={len(ids)} unique={len(set(ids))} min={min(ids)} max={max(ids)} '
          f'ordered_contiguous={ids == list(range(len(ids)))}')
    for event_id in (110, 1151):
        records = [event for event in events
                   if event.find("integer[@id='id']") is not None
                   and event.find("integer[@id='id']").get('value') == str(event_id)]
        if len(records) != 1:
            raise ValueError(f'event {event_id} missing or ambiguous')
        variants = records[0].find("list[@id='evar']")
        if variants is None:
            raise ValueError(f'event {event_id} missing variants')
        weights = [int(row.find("integer[@id='prob']").get('value')) for row in variants]
        delays = [int(row.find("integer[@id='dely']").get('value')) for row in variants]
        print(f'id={event_id} variants={len(weights)} prob={weights} delay={delays}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    inspect(args.archive)
