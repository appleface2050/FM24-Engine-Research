"""复核进球生命周期的局部分支转写；不是 FM24 模拟器或最终比分模型。"""

import argparse
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def timing_gate(tick, ball_time, match_times, context_time, d840=0, e28c=0):
    """转写141aa4820：球推进循环完成后的冻结输入，True会阻断后续分派。"""
    if d840 != 0 or e28c != 0:
        return False
    return tick not in (ball_time, *match_times, context_time)


def choose_dispatch(tick, deadline, region, blocked=False, special=(0, 0, 0)):
    """转写局部分派：tick/deadline是int32，region是字节，special为返回/b/c。"""
    # 前置1445191c0必须返回0；中间调用视为已到达指定检查点的外部条件。
    if tick < deadline:
        return "deferred", False
    rollback_called = tick == deadline
    if rollback_called:
        # 回退函数的返回值不控制这两个局部字节的赋值。
        b, c = 1, 0
    else:
        handled, b, c = special
        if handled:
            return "special_handled", False
    if blocked:
        return "timing_blocked", rollback_called
    if c:
        return "alternate_event", rollback_called
    if b:
        return "event_dispatch", rollback_called
    if 1 <= region <= 7:
        return "ordinary_region", rollback_called
    return "other_region", rollback_called


def reverse_pending(count, pending):
    """仅转写保存引用的回退门槛与计数字节；后续包装器正常完成是前提。"""
    if not pending:
        return count, False, False
    return (count - 1) & 0xFF, False, True


def reset_flags(old, mask, state_byte):
    """转写151b00860的直接标志/状态字节，不模拟它的其他调用。"""
    writes_marker = bool(mask & 0x200 and old & 1)
    if writes_marker and state_byte < 4:
        state_byte += 6
    return ((old & 0xFDFF00FE) | mask | 0x100) & 0xFFFFFFFF, state_byte, writes_marker


def delay_from_draw(draw):
    """转写151af7570窗口外等待量；draw为上游PRNG给出的uint32，不生成随机数。"""
    return 12 + (((draw * 3) >> 30) & 12)


def fixture_record_offset(native_type, side):
    """仅覆盖已绑定的两种原生类型及有效side=0/1，不推断其他工厂对象。"""
    return {"FIXTURE": 0x4C, "FIXTURE_RESULT": 0x64}[native_type] + 4 * side


def adjust_fixture_record(record, flags, mode, delta):
    """转写四字节增减；mode=2时冻结两次查询返回同一记录，不赋正式比分名。"""
    result = list(record)
    index = 1 if flags & 0x10 else 0
    result[index] = (result[index] + delta) & 0xFF
    if mode == 2:
        result[3] = (result[3] + delta) & 0xFF
    return result


def examples():
    """用手算期望验证相等时刻、回退门槛、位操作和延迟边界。"""
    n = 0

    def check(label, actual, expected):
        nonlocal n
        if actual != expected:
            raise AssertionError(f"{label}: actual={actual!r} expected={expected!r}")
        n += 1

    check("deadline-1", choose_dispatch(199, 200, 5), ("deferred", False))
    check("deadline", choose_dispatch(200, 200, 5), ("event_dispatch", True))
    check("deadline+1", choose_dispatch(201, 200, 5), ("ordinary_region", False))
    check("deadline-empty-ref-still-event",
          (choose_dispatch(200, 200, 5)[0], reverse_pending(2, False)[2]),
          ("event_dispatch", False))
    check("special-return-1", choose_dispatch(201, 200, 5, special=(1, 0, 0)), ("special_handled", False))
    check("special-b", choose_dispatch(201, 200, 5, special=(0, 1, 0)), ("event_dispatch", False))
    check("special-c-priority", choose_dispatch(201, 200, 5, special=(0, 1, 1)), ("alternate_event", False))
    check("timing-blocks-deadline-event", choose_dispatch(200, 200, 5, blocked=True), ("timing_blocked", True))
    check("unknown-region", choose_dispatch(201, 200, 0), ("other_region", False))
    check("no-trigger-time", timing_gate(100, 90, (91, 92, 93, 94, 95), 96), True)
    check("ball-trigger", timing_gate(100, 100, (91, 92, 93, 94, 95), 96), False)
    check("context-trigger", timing_gate(100, 90, (91, 92, 93, 94, 95), 100), False)
    check("d840-bypasses-time-comparisons", timing_gate(100, 90, (91, 92, 93, 94, 95), 96, d840=1), False)
    check("e28c-bypasses-time-comparisons", timing_gate(100, 90, (91, 92, 93, 94, 95), 96, e28c=1), False)
    first = reverse_pending(2, True)
    check("one-reversal", first, (1, False, True))
    check("second-reversal-no-new-reference", reverse_pending(first[0], first[1]), (1, False, False))
    check("clear-before-reversal", reverse_pending(2, False), (2, False, False))
    check("reset-old-state-3", reset_flags(1, 0x200, 3), (0x300, 9, True))
    check("reset-old-state-4", reset_flags(1, 0x200, 4), (0x300, 4, True))
    check("reset-different-mask", reset_flags(1, 0x400, 2), (0x500, 2, False))
    for draw, expected in [(0, 12), (0x55555555, 12), (0x55555556, 16),
                           (0xAAAAAAAA, 16), (0xAAAAAAAB, 20), (0xFFFFFFFF, 20)]:
        check(f"delay-{draw:08x}", delay_from_draw(draw), expected)
    for native_type, side, offset in [("FIXTURE", 0, 0x4C), ("FIXTURE", 1, 0x50),
                                      ("FIXTURE_RESULT", 0, 0x64), ("FIXTURE_RESULT", 1, 0x68)]:
        check(f"layout-{native_type}-{side}", fixture_record_offset(native_type, side), offset)
    record = [1, 2, 3, 4]
    check("record-byte0", adjust_fixture_record(record, 0, 0, 1), [2, 2, 3, 4])
    check("record-byte1", adjust_fixture_record(record, 0x10, 0, 1), [1, 3, 3, 4])
    check("record-byte0-and3", adjust_fixture_record(record, 0, 2, 1), [2, 2, 3, 5])
    check("record-byte1-and3-reversal", adjust_fixture_record(record, 0x10, 2, -1), [1, 1, 3, 3])
    incremented = adjust_fixture_record(record, 0, 0, 1)
    check("same-input-reversal", adjust_fixture_record(incremented, 0, 0, -1), record)
    check("different-mode-is-not-inverse", adjust_fixture_record(incremented, 0x10, 0, -1), [2, 1, 3, 4])
    print(f"Local worked examples passed: {n}. No game functions executed.", flush=True)


def verify_original(exe):
    """只读原PE并复核证据中的指令字节；不加载或执行目标程序。"""
    data = exe.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    evidences = [json.loads((ROOT / name).read_text()) for name in (
        "20261017_goal_lifecycle_observations.json",
        "20261017_fixture_result_binding_observations.json",
    )]
    for evidence in evidences:
        if image_base != int(evidence["image_base"], 16):
            raise ValueError("PE image base differs from the selected research target")
    sections = []
    for i in range(section_count):
        _, rva, size, raw = struct.unpack_from("<IIII", data, optional + optional_size + i * 40 + 8)
        sections.append((rva, size, raw))
    native = [item for evidence in evidences for item in evidence["native_assertions"]]
    static_data = [item for evidence in evidences for item in evidence.get("data_assertions", [])]
    for item in native + static_data:
        va = int(item["va"], 16)
        expected = bytes.fromhex(item["hex"])
        rva = va - image_base
        for start, size, raw in sections:
            if start <= rva and rva + len(expected) <= start + size:
                offset = raw + rva - start
                if data[offset:offset + len(expected)] != expected:
                    raise AssertionError(f"Original bytes differ at {item['va']}; stop using this evidence")
                break
        else:
            raise ValueError(f"Unmapped instruction {item['va']}")
    print(f"Original PE assertions passed: {len(native)} instruction/leaf, {len(static_data)} data.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, help="可选：核对原始fm.exe字节；不会执行游戏")
    args = parser.parse_args()
    examples()
    if args.exe:
        verify_original(args.exe)
    print("Coverage: local frozen branches only; final valid-goal/score lifecycle remains open.", flush=True)
