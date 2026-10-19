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


def write_fixture_record_fragment(records, buffer, position):
    """仅转写8次成功的单字节输出；缓冲区容量充足，不模拟完整对象/失败路径。"""
    result = bytearray(buffer)
    for value in records:
        result[position] = value
        position += 1
    return bytes(result), position


def query_fixture_byte(record, prefer_byte1=False, prefer_byte3=False):
    """转写1419c0150的低8位返回值；None代表虚查询返回空，非整寄存器语义。"""
    if record is None:
        return 0xFF
    if prefer_byte3 and record[3] != 0xFF:
        return record[3]
    if prefer_byte1 and record[1] != 0xFF:
        return record[1]
    return record[0]


def fixture_comparison_status(first, second):
    """转写141e44aa0：按signed byte比较，输出两侧6c/6d原始状态码。"""
    for index, code in [(2, 3), (3, 7), (1, 2), (0, 1)]:
        left = first[index] if first[index] < 128 else first[index] - 256
        right = second[index] if second[index] < 128 else second[index] - 256
        if left > right:
            return code, 10
        if left < right:
            return 10, code
    return 9, 9


def handoff_gate(flags):
    """转写1434f4798调用条件；必须已到该检查点，不代表整个函数入口条件。"""
    return bool(flags & 4)


def snapshot_fixture_records(records):
    """仅转写成功克隆时两个四字节的值复制，不模拟其他字段或生命周期。"""
    return bytes(records)


def iteration_exit_choice(tick, entry_tick, mode, limit, flags, phase_tick=0):
    """转写141a98930已通过初始化门槛后的局部检查顺序；所有时刻为int32输入。"""
    if flags & 4:
        return "already_complete"
    if limit != -1 and tick >= limit:
        return "pause"
    if mode == 2:
        if phase_tick >= 0x5461 and flags & 0x10010:
            return "pause"
    elif mode == 0 and tick > entry_tick:
        return "pause"
    return "clock_cap_overwrite" if tick >= 48001 else "dispatch_state"


def state3_completion_choice(tick, deadline, flags):
    """转写144406f55已到比较点的状态；输出在后续helper副作用之前。"""
    if tick >= deadline:
        return flags | 4, "finalizer"
    return flags, "advance_helper"


def clock_cap_record_writes(first, second, pending=False):
    """仅覆盖已绑定FIXTURE_RESULT、有效W/I和正常虚调用的超限直接写入。"""
    first, second = list(first), list(second)
    first[0], second[0] = 2, 1
    return first, second, 4, (1, 10), pending


def state2_next_state(substate_after_helpers):
    """转写144405868返回低字节；输入是所有前序helper之后重新读取的e218。"""
    return 2 | int(substate_after_helpers == 4)


def end_entry_reset_block():
    """转写141ac9db5的104字节源块，不模拟该函数前后的其他副作用。"""
    return bytes(88) + bytes([0xFF] * 16)


def remaining_opportunity_winner(first, first_remaining, second, second_remaining):
    """转写1444061bf..20b：输入为四个原始字节，在实际比较点冻结。"""
    a, u, b, v = [value if value < 128 else value - 256
                  for value in (first, first_remaining, second, second_remaining)]
    if a > b + v:
        return 0
    if b > a + u:
        return 1
    return None


def increment_phase_record(record):
    """仅转写1444060ab在查询非空时对记录第2字节的递增。"""
    result = list(record)
    result[2] = (result[2] + 1) & 0xFF
    return result


def event_suffix_gates(primary):
    """转写1443d573d和5afa的门槛；不执行通用插入或跳表分支体。"""
    signed = primary if primary < 128 else primary - 256
    unsigned = signed & 0xFFFFFFFF
    masked_group = unsigned <= 0x15 and bool(0x203008 & (1 << unsigned))
    jump_table = ((unsigned - 8) & 0xFFFFFFFF) <= 0xF
    return masked_group, jump_table


def unlinked_revision_candidates(subtype):
    """冻结记录无关联；只计算结果7候选及原始9/10门槛，不模拟上下文/调用。"""
    return subtype == 7, ((subtype - 9) & 0xFF) <= 1


def reserve_service_serial(counter):
    """转写142d74481..490的检查点；编号分配发生在下游成功与否已知之前。"""
    serial = counter & 0xFFFFFFFF
    return (serial + 1) & 0xFFFFFFFF, serial


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
    check("stream-record-order",
          write_fixture_record_fragment([1, 2, 3, 4, 5, 6, 7, 8], bytes(8), 0),
          (bytes([1, 2, 3, 4, 5, 6, 7, 8]), 8))
    check("stream-current-position-not-always-append",
          write_fixture_record_fragment([1, 2, 3, 4, 5, 6, 7, 8], bytes([9] * 10), 1),
          (bytes([9, 1, 2, 3, 4, 5, 6, 7, 8, 9]), 9))
    check("query-base-only", query_fixture_byte([2, 3, 4, 5]), 2)
    check("query-byte1", query_fixture_byte([2, 3, 4, 5], True), 3)
    check("query-byte3-priority", query_fixture_byte([2, 3, 4, 5], True, True), 5)
    check("query-byte3-fallback-byte1", query_fixture_byte([2, 3, 4, 255], True, True), 3)
    check("query-both-sentinels", query_fixture_byte([2, 255, 4, 255], True, True), 2)
    check("query-disabled-byte1", query_fixture_byte([2, 3, 4, 255], False, True), 2)
    check("query-zero-is-present", query_fixture_byte([2, 3, 4, 0], True, True), 0)
    check("query-empty-low-byte", query_fixture_byte(None), 255)
    check("query-does-not-select-byte2", query_fixture_byte([255, 255, 4, 255], True, True), 255)
    check("status-byte2-priority", fixture_comparison_status([9, 9, 0, 9], [0, 0, 1, 0]), (10, 3))
    check("status-byte3-next", fixture_comparison_status([0, 0, 0, 1], [9, 9, 0, 0]), (7, 10))
    check("status-byte1-next", fixture_comparison_status([9, 0, 0, 0], [0, 1, 0, 0]), (10, 2))
    check("status-byte0-last", fixture_comparison_status([1, 0, 0, 0], [0, 0, 0, 0]), (1, 10))
    check("status-all-equal", fixture_comparison_status([1, 2, 3, 4], [1, 2, 3, 4]), (9, 9))
    check("status-ff-is-signed-negative", fixture_comparison_status([0, 0, 255, 0], [0, 0, 0, 0]), (10, 3))
    check("status-ff-not-validity-check", fixture_comparison_status([255]*4, [255]*4), (9, 9))
    check("handoff-bit4-clear", handoff_gate(0), False)
    check("handoff-bit4-set", handoff_gate(4), True)
    check("handoff-bit10-alone", handoff_gate(0x10), False)
    check("handoff-bit4-with-other-bits", handoff_gate(0x14), True)
    source = bytearray([1, 2, 3, 4, 5, 6, 7, 8])
    snapshot = snapshot_fixture_records(source)
    check("snapshot-preserves-two-records", snapshot, bytes([1, 2, 3, 4, 5, 6, 7, 8]))
    source[0] = 9
    check("snapshot-not-source-alias", snapshot, bytes([1, 2, 3, 4, 5, 6, 7, 8]))
    check("snapshot-does-not-validate", snapshot_fixture_records([255] * 8), bytes([255] * 8))
    check("cap-clock-48000", iteration_exit_choice(48000, 48000, 1, -1, 0), "dispatch_state")
    check("cap-clock-48001", iteration_exit_choice(48001, 48001, 1, -1, 0), "clock_cap_overwrite")
    check("cap-explicit-limit-first", iteration_exit_choice(48001, 48000, 1, 48001, 0), "pause")
    check("cap-mode0-progress-first", iteration_exit_choice(48001, 48000, 0, -1, 0), "pause")
    check("cap-mode0-no-progress", iteration_exit_choice(48001, 48001, 0, -1, 0), "clock_cap_overwrite")
    check("cap-mode2-phase-and-mask", iteration_exit_choice(48001, 48000, 2, -1, 0x10, 21601), "pause")
    check("cap-mode2-phase-below", iteration_exit_choice(48001, 48000, 2, -1, 0x10, 21600), "clock_cap_overwrite")
    check("cap-mode2-mask-clear", iteration_exit_choice(48001, 48000, 2, -1, 0, 21601), "clock_cap_overwrite")
    check("cap-already-complete-first", iteration_exit_choice(48001, 48000, 1, -1, 4), "already_complete")
    check("state3-before-deadline", state3_completion_choice(199, 200, 0x10), (0x10, "advance_helper"))
    check("state3-at-deadline", state3_completion_choice(200, 200, 0x10), (0x14, "finalizer"))
    check("state3-after-deadline", state3_completion_choice(201, 200, 0x10), (0x14, "finalizer"))
    check("cap-replaces-base-only", clock_cap_record_writes([5, 3, 2, 1], [4, 8, 7, 6], pending=True),
          ([2, 3, 2, 1], [1, 8, 7, 6], 4, (1, 10), True))
    check("cap-does-not-initialize-all-fields", clock_cap_record_writes([255]*4, [255]*4),
          ([2, 255, 255, 255], [1, 255, 255, 255], 4, (1, 10), False))
    for substate, expected in [(0, 2), (3, 2), (4, 3), (5, 2)]:
        check(f"state2-next-{substate}", state2_next_state(substate), expected)
    cleared = end_entry_reset_block()
    check("entry-block-length", len(cleared), 104)
    check("entry-pending-reference-zero", struct.unpack_from("<Q", cleared)[0], 0)
    check("entry-last-zero-qword", struct.unpack_from("<Q", cleared, 80)[0], 0)
    check("entry-tail-sentinels", struct.unpack_from("<qq", cleared, 88), (-1, -1))
    check("entry-clear-blocks-listed-reversal",
          reverse_pending(2, bool(struct.unpack_from("<Q", cleared)[0])), (2, False, False))
    check("entry-flags-not-complete-yet", handoff_gate(0x1800000), False)
    check("entry-delay-current-tick", state3_completion_choice(100, 100 + 2, 0x1800000),
          (0x1800000, "advance_helper"))
    check("entry-delay-next-tick", state3_completion_choice(101, 100 + 2, 0x1800000),
          (0x1800000, "advance_helper"))
    check("entry-delay-deadline", state3_completion_choice(102, 100 + 2, 0x1800000),
          (0x1800004, "finalizer"))
    check("rollback-deadline-delays-finish",
          state3_completion_choice(100, max(100 + 1, 103), 0x1800000),
          (0x1800000, "advance_helper"))
    check("remaining-side0-equality-continues", remaining_opportunity_winner(3, 2, 1, 2), None)
    check("remaining-side0-strictly-exceeds", remaining_opportunity_winner(3, 2, 1, 1), 0)
    check("remaining-side1-strictly-exceeds", remaining_opportunity_winner(1, 1, 3, 2), 1)
    check("remaining-side1-equality-continues", remaining_opportunity_winner(1, 2, 3, 2), None)
    check("remaining-no-attempts-tie", remaining_opportunity_winner(2, 0, 2, 0), None)
    check("remaining-no-attempts-different", remaining_opportunity_winner(3, 0, 2, 0), 0)
    check("phase-byte2-independent", increment_phase_record([2, 3, 0, 5]), [2, 3, 1, 5])
    check("phase-byte2-wrap-not-initialization-proof", increment_phase_record([2, 3, 255, 5]), [2, 3, 0, 5])
    check("constructor-delay-before-deadline", state3_completion_choice(119, 100 + 20, 0x1800000),
          (0x1800000, "advance_helper"))
    check("constructor-delay-at-deadline", state3_completion_choice(120, 100 + 20, 0x1800000),
          (0x1800004, "finalizer"))
    check("post-clear-primary-ff-bypasses-both", event_suffix_gates(0xFF), (False, False))
    check("primary-11-is-distinct-from-ff", event_suffix_gates(0x11), (False, True))
    check("primary-3-enters-mask-only", event_suffix_gates(3), (True, False))
    check("primary-15-enters-both", event_suffix_gates(0x15), (True, True))
    check("primary-18-above-switch-range", event_suffix_gates(0x18), (False, False))
    check("unlinked-ending-marker-no-revision-candidate", unlinked_revision_candidates(0x11), (False, False))
    check("unlinked-subtype9-normalization-candidate", unlinked_revision_candidates(9), (False, True))
    check("unlinked-subtype10-normalization-candidate", unlinked_revision_candidates(10), (False, True))
    check("unlinked-subtype7-context-still-required", unlinked_revision_candidates(7), (True, False))
    check("service-serial-reserved-before-acceptance", reserve_service_serial(7), (8, 7))
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
        "20261017_fixture_stream_direction_observations.json",
        "20261017_fixture_scoreline_consumers_observations.json",
        "20261017_match_result_handoff_observations.json",
        "20261017_match_completion_conditions_observations.json",
        "20261017_state3_entry_cleanup_observations.json",
        "20261019_remaining_opportunity_end_observations.json",
        "20261019_post_clear_dispatch_observations.json",
        "20261019_event_queue_result_service_observations.json",
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
