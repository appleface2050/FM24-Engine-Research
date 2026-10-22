"""复核进球生命周期的局部分支转写；不是 FM24 模拟器或最终比分模型。"""

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from urllib.parse import unquote


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


def initialize_fixture_record_heads(records, mode, prior_offsets):
    """转写141a9275c窗口：已绑定两侧查询成功，只清R0；mode2另存R3。"""
    result = [list(record) for record in records]
    for record in result:
        record[0] = 0
    offsets = [record[3] for record in result] if mode == 2 else list(prior_offsets)
    return result, offsets


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


def archive_span_checkpoint(previous, position, limit, maximum):
    """转写142d794a1..4ed；输入为最终比较点的int32值，不执行序列化或重试。"""
    if previous > 0 and previous == position and limit != -1:
        return "retry", 0, maximum, None
    span = (previous, (position - previous) & 0xFFFFFFFF)
    return "record", position, max(maximum, position), span


def precopy_entry_eligible(entry_tick, match_tick, side, kind, team_flags):
    """转写141a98050的条目资格；输入为原生int32/byte值，不执行或模拟回调。"""
    if entry_tick != match_tick or side > 1 or kind == 0x0E:
        return False
    return bool(team_flags & 0x1001) or (kind < 20 and bool((0x82322 >> kind) & 1))


def loaded_date_bucket_slot(packed_day):
    """仅转写141e6be60同年/已加载分支的槽位检查；类别与年份已在检查点固定。"""
    slot = ((packed_day & 0x1FF) - 1) & 0xFFFF
    return slot if slot < 366 else None


def competition_dispatch_after_index_copy(index_result, provider, reference, lookup, competition):
    """转写1445eb65e..6cb门槛；index_result是前序返回值，原调用者不检查它。"""
    return bool(provider and reference and lookup and competition)


def league_entry_accumulation(first, second, counters):
    """转写141f6e0dd..12f检查点；冻结查询对象/记录，未模拟整段阶段处理。"""
    values = [query_fixture_byte(record, prefer_byte1=True) for record in (first, second)]
    own, opponent = [value if value < 128 else value - 256 for value in values]
    total_own, total_opponent, byte_e, byte_f = counters
    return ((total_own + own) & 0xFFFF, (total_opponent + opponent) & 0xFFFF,
            (byte_e + 1) & 0xFF, (byte_f + 1) & 0xFF)


def result_admission_fallback(load_ok, output_flag=True):
    """仅转写140205c81..e32的回调返回/输出标记，不模拟加载或正式接受。"""
    return True, output_flag if load_ok else False


def player_stats_record_checks(first, second):
    """转写144c5c09f..191的冻结记录读取；返回局部比较，不模拟外围资格/调用。"""
    left = query_fixture_byte(first, prefer_byte1=True, prefer_byte3=True)
    right = query_fixture_byte(second, prefer_byte1=True, prefer_byte3=True)
    left = left if left < 128 else left - 256
    right = right if right < 128 else right - 256
    magnitude_byte = abs(left - right) & 0xFF
    signed_magnitude = magnitude_byte if magnitude_byte < 128 else magnitude_byte - 256
    both_byte2_nonnegative = all(record is not None and record[2] < 128
                                 for record in (first, second))
    return left, right, signed_magnitude <= 1, both_byte2_nonnegative


def form_latest_slot(count, head, capacity):
    """转写两种已绑定表现对象+40：仅用于非空、数量/头下标有效的环形记录。"""
    slot = count + head - 1
    return slot if slot < capacity else slot - capacity


def form_date_skips_append(count, current_date, latest_date):
    """转写14273371f..74c；已找到现有表现对象，日期为原始uint32打包值。"""
    return bool(count and latest_date is not None
                and ((current_date ^ latest_date) & 0x1FF) == 0
                and current_date >> 16 == latest_date >> 16)


def stage_row_compare_fragment(first, second, rules=(0, 1)):
    """限定mode0/普通主键；行=(+8,+a,+c)，None表示进入未建模的后续平局处理。"""
    def signed_word(value):
        value &= 0xFFFF
        return value if value < 0x8000 else value - 0x10000

    delta = signed_word(second[2]) - signed_word(first[2])
    if delta:
        return delta
    for rule in rules:  # 仅覆盖原生规则0、1；其他规则不在该局部模型范围内。
        if rule not in (0, 1):
            return None
        left = signed_word(first[0] - first[1]) if rule == 0 else signed_word(first[0])
        right = signed_word(second[0] - second[1]) if rule == 0 else signed_word(second[0])
        if right != left:
            return right - left
    return None


def payload_control_reference_cycle(initial, copies, source_releases):
    """有效引用计数的冻结算例：构建增加、外部释放、清理副本；不执行虚调用。"""
    after_build = (initial + copies) & 0xFFFFFFFF
    before_cleanup = (after_build - source_releases) & 0xFFFFFFFF
    count = before_cleanup
    virtual_calls = 0
    for _ in range(copies):
        count = (count - 1) & 0xFFFFFFFF
        virtual_calls += int(count == 0)
    return after_build, before_cleanup, count, virtual_calls


def payload_element_without_child(header, reference, reference_count):
    """144361db0源+10为空的新目标路径；只列字段和共享引用计数变化。"""
    return (header, reference, 0), (reference_count + int(bool(reference))) & 0xFFFFFFFF


def payload_group_release_actions(owns_first, slots):
    """列出条件动作；控制计数冻结于第二遍递减前，不建模第一遍析构的副作用。"""
    actions = []
    if owns_first:
        actions.extend(("destroy_element", element) for element, _ in slots if element)
    for _, control in slots:
        if control is not None:
            pointer, count = control
            actions.append(("decrement_control", pointer))
            if count == 1:
                actions.append(("virtual_destroy", pointer))
    return actions


def payload_move_into_empty(source):
    """15114cee0的不同对象/空目标路径；元组为(+0,+8,+10,+18,+1c)。"""
    root, reference, auxiliary, mode, flag = source
    return (root, reference, auxiliary, mode, flag), (0, 0, 0, mode, flag)


def payload_transfer_reference_fields(destination, source):
    """仅15114cfcc..d00b字段结果；不建模旧引用释放副作用。"""
    return (destination, source) if destination == source else (source, 0)


def payload_reference_variant(first, second, third):
    """141a615a6..601：32位和按signed解释，再两次向零取余；仅返回低字节的有符号值。"""
    total = (first + second + third) & 0xFFFFFFFF
    total = total if total < 0x80000000 else total - 0x100000000
    remainder = (abs(total) % 10) * (-1 if total < 0 else 1)
    return (abs(remainder) % 3) * (-1 if remainder < 0 else 1)


def payload_resource_key(code, variant):
    """仅已核对的38/3a分派；其他代码不在本局部模型范围内。"""
    base = {0x38: 0x4B74F, 0x3A: 0x4B752}[code]
    low = variant & 0xFF
    return base + (0 if low == 0 else 1 if low == 1 else 2)


def payload_player_read(raw_byte):
    """仅ID3f/41/42、mask800000000的只读路径；无属性足球名称推断。"""
    value = raw_byte if raw_byte < 128 else raw_byte - 256
    numerator = value + 3
    quotient = abs(numerator) // 5 * (-1 if numerator < 0 else 1)
    return max(1, quotient)


def payload_annotation_duplicate(mapped_code, candidate, history):
    """匹配6字节历史记录的WORD0及字节2/3/4；忽略其字节5。"""
    key = (mapped_code, candidate[8], candidate[9], candidate[10])
    return any((int.from_bytes(entry[:2], "little"), *entry[2:5]) == key
               for entry in history)


def payload_growth_capacity(count):
    """141a76b0c..b56的正常小规模容量计算；不建模溢出极限分支。"""
    return max(count + 1, count + count // 2)


def project_payload_event(record):
    """1443cc280的字节0..8映射；不建模未写入的字节9或上层分配器。"""
    code, value = struct.unpack_from("<HH", record)
    preserves_value = (code not in (0xE, 0x264) and
                       (400 <= code <= 407 or 300 <= code <= 317 or
                        601 <= code <= 620 or 350 <= code <= 357 or
                        113 <= code <= 120 or 4 <= code <= 9))
    return struct.pack("<HHHBBB", code, value if preserves_value else 1,
                       value, record[5], record[6], record[7])


def payload_header_matches(header, code, field4, side, flag):
    """141a44bb8..bd5只比较DWORD0及字节4/5/6；不读取字节7。"""
    return (struct.unpack_from("<I", header)[0] == code
            and header[4] == field4 and header[5] == side and header[6] == flag)


def team_payload_forwards_match(has_primary, flags):
    """只描述14513c65d门槛；False不证明此前容器复制帮助函数保分。"""
    return bool(has_primary and flags & 1)


def empty_team_payload_fields(flags, old_reference, secondary_reference=None):
    """Q+138为空的整段无CALL路径；只列输出三标志和+18引用字段。"""
    return ((flags >> 5) & 1, (flags >> 4) & 1, (flags >> 6) & 1,
            old_reference if secondary_reference is None else secondary_reference)


def selected_full_selector(active_byte, mode_byte, flag_28d, first_object_flags):
    """仅低字节：args2/3=0且引用合格、首侧2f=0及关联对象非空的早分支。"""
    if not active_byte or mode_byte == 2 or not flag_28d:
        return 1
    return 0 if first_object_flags & 1 else None  # None为未覆盖后续分支，不代表返回值。


def scheduled_task_type(force_full, selector, alternate):
    """1434ef590的分流片段；selector为1434eecf0冻结返回，不推断其足球含义。"""
    return "OTHER" if not force_full and (selector or alternate) else "FULL"


def full_task_collection(marker):
    """FULL+30仅依据X+58；假定已返回推进调用并到达集合选择点。"""
    return "append" if marker else "destroy"


def fixture_result_status(record):
    """FIXTURE_RESULT+f0：仅side0默认记录低字节的符号位，不代表正式接受。"""
    return not bool(query_fixture_byte(record) & 0x80)


def submitted_summary_scores(records, side):
    """141e47150比分片段；None表示门槛阻断写入；辅助调用副作用不在本模型内。"""
    if not fixture_result_status(records[0]):
        return None
    own, opponent = records[side], records[1 - side]
    selected = 1 if own[1] < 0x80 else 0
    return own[selected], opponent[selected]


def redirect_registered_result_slots(slots, values, old, replacement):
    """仅转写已进入141e5af90的槽间接改写；不模拟查找、释放或整次提交。"""
    result = dict(values)
    for slot in slots:
        if result[slot] == old:
            result[slot] = replacement
    return result


def unregister_result_slot(slots, slot):
    """仅转写已满足*slot非空的141e58023末段：按地址移除，非按结果值。"""
    return [item for item in slots if item != slot]


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
    check("archive-span-advances", archive_span_checkpoint(8, 12, 100, 9),
          ("record", 12, 12, (8, 4)))
    check("archive-span-same-positive-retries", archive_span_checkpoint(8, 8, 100, 12),
          ("retry", 0, 12, None))
    check("archive-span-unlimited-allows-zero", archive_span_checkpoint(8, 8, -1, 12),
          ("record", 8, 12, (8, 0)))
    check("archive-span-initial-zero-does-not-retry", archive_span_checkpoint(0, 0, 100, 0),
          ("record", 0, 0, (0, 0)))
    check("precopy-type9-mask-with-zero-team-flags", precopy_entry_eligible(100, 100, 0, 9, 0), True)
    check("precopy-type6-after-type9-writes-zero", precopy_entry_eligible(100, 100, 0, 6, 0), False)
    check("precopy-type6-after-type9-writes-one", precopy_entry_eligible(100, 100, 0, 6, 1), True)
    check("precopy-team-flag-bit1000-allows-type6", precopy_entry_eligible(100, 100, 0, 6, 0x1000), True)
    check("precopy-team-flag-bit100-is-insufficient", precopy_entry_eligible(100, 100, 0, 6, 0x100), False)
    check("precopy-kind14-excluded-before-team-flags", precopy_entry_eligible(100, 100, 0, 14, 0x1001), False)
    check("precopy-side2-excluded", precopy_entry_eligible(100, 100, 2, 9, 0x1001), False)
    check("precopy-tick-mismatch-excluded", precopy_entry_eligible(99, 100, 0, 9, 0x1001), False)
    check("precopy-fixed-mask-types", tuple(k for k in range(20) if precopy_entry_eligible(100, 100, 0, k, 0)),
          (1, 5, 8, 9, 13, 19))
    check("admission-load-fails-but-callback-returns-one",
          result_admission_fallback(False), (True, False))
    check("admission-load-success-leaves-output-flag",
          result_admission_fallback(True), (True, True))
    check("admission-load-success-does-not-set-output-flag",
          result_admission_fallback(True, False), (True, False))
    earlier = snapshot_fixture_records([2, 255, 0, 255, 1, 255, 0, 255])
    refreshed = snapshot_fixture_records([3, 255, 0, 255, 1, 255, 0, 255])
    check("admission-refresh-replaces-earlier-value-copy", (earlier[0], refreshed[0]), (2, 3))
    check("league-entry-prefers-non-ff-byte1",
          league_entry_accumulation([2, 3, 0, 255], [1, 255, 0, 255], (10, 7, 4, 4)),
          (13, 8, 5, 5))
    check("league-entry-zero-byte1-is-used",
          league_entry_accumulation([2, 0, 0, 255], [1, 255, 0, 255], (10, 7, 4, 4)),
          (10, 8, 5, 5))
    check("league-entry-ff-values-sign-extend-at-checkpoint",
          league_entry_accumulation([255] * 4, [255] * 4, (0, 0, 0, 0)),
          (65535, 65535, 1, 1))
    check("league-entry-word-and-byte-wrap",
          league_entry_accumulation([1, 255, 0, 255], [0, 255, 0, 255], (65535, 0, 255, 255)),
          (0, 0, 0, 0))
    check("date-bucket-first-day", loaded_date_bucket_slot(1), 0)
    check("date-bucket-last-slot", loaded_date_bucket_slot(366), 365)
    check("date-bucket-zero-rejected", loaded_date_bucket_slot(0), None)
    check("date-bucket-367-rejected", loaded_date_bucket_slot(367), None)
    check("date-bucket-packed-high-bits-masked", loaded_date_bucket_slot(0xA001), 0)
    check("index-copy-false-does-not-block-competition",
          competition_dispatch_after_index_copy(False, True, True, True, True), True)
    check("index-copy-true-same-competition-choice",
          competition_dispatch_after_index_copy(True, True, True, True, True), True)
    check("index-copy-true-does-not-bypass-missing-competition",
          competition_dispatch_after_index_copy(True, True, True, True, False), False)
    check("player-stats-byte3-precedes-byte1",
          player_stats_record_checks([9, 5, 0, 1], [7, 4, 0, 1]), (1, 1, True, True))
    check("player-stats-byte1-fallback-and-byte2-marker",
          player_stats_record_checks([1, 3, 255, 255], [9, 2, 255, 255]), (3, 2, True, False))
    check("player-stats-byte0-fallback-margin-two",
          player_stats_record_checks([3, 255, 0, 255], [1, 255, 0, 255]), (3, 1, False, True))
    check("player-stats-ff-is-not-result-validity",
          player_stats_record_checks([255] * 4, [255] * 4), (-1, -1, True, False))
    check("form-date-ignores-nonday-flags",
          form_date_skips_append(3, 0x07EA0064, 0x07EA8064), True)
    check("form-date-different-year-continues",
          form_date_skips_append(3, 0x07EA0064, 0x07E90064), False)
    check("form-date-different-day-continues",
          form_date_skips_append(3, 0x07EA0064, 0x07EA0063), False)
    check("form-empty-has-no-date-skip", form_date_skips_append(0, 0x07EA0064, None), False)
    check("form20-latest-wrap", form_latest_slot(20, 19, 20), 18)
    check("form60-latest-wrap", form_latest_slot(2, 59, 60), 0)
    check("stage-primary-precedes-difference",
          stage_row_compare_fragment((100, 0, 6), (1, 0, 9)), 3)
    check("stage-rule0-difference",
          stage_row_compare_fragment((10, 7, 6), (9, 7, 6)), -1)
    check("stage-rule1-after-equal-difference",
          stage_row_compare_fragment((8, 5, 6), (9, 6, 6)), 1)
    check("stage-rule-order-difference-first",
          stage_row_compare_fragment((8, 0, 6), (9, 7, 6), (0, 1)), -6)
    check("stage-rule-order-field8-first",
          stage_row_compare_fragment((8, 0, 6), (9, 7, 6), (1, 0)), 1)
    check("stage-negative-difference-sign-extension",
          stage_row_compare_fragment((0, 1, 6), (0, 0, 6)), 1)
    check("stage-full-tie-is-outside-fragment",
          stage_row_compare_fragment((8, 5, 6), (8, 5, 6)), None)
    changed = league_entry_accumulation([3, 255, 0, 255], [1, 255, 0, 255], (5, 4, 0, 0))
    check("stage-frozen-accumulation-changes-comparison",
          (stage_row_compare_fragment((5, 4, 6), (9, 7, 6)),
           stage_row_compare_fragment((*changed[:2], 6), (9, 7, 6))), (1, -1))
    check("registered-slot-replacement-is-indirect",
          redirect_registered_result_slots([0x1000], {0x1000: 0x2000}, 0x2000, 0x3000),
          {0x1000: 0x3000})
    check("registered-slot-no-longer-old-is-preserved",
          redirect_registered_result_slots([0x1000], {0x1000: 0x4000}, 0x2000, 0x3000),
          {0x1000: 0x4000})
    check("unregister-compares-slot-address-not-pointee",
          unregister_result_slot([0x1000, 0x1008, 0x1000], 0x1000), [0x1008])
    check("unregistered-alias-is-not-redirected",
          redirect_registered_result_slots([], {0x1000: 0x2000}, 0x2000, 0x3000),
          {0x1000: 0x2000})
    check("result-status-zero-is-available", fixture_result_status([0, 255, 0, 255]), True)
    check("result-status-127", fixture_result_status([127, 255, 0, 255]), True)
    check("result-status-128", fixture_result_status([128, 0, 0, 255]), False)
    check("result-status-byte1-cannot-rescue-byte0",
          fixture_result_status([255, 3, 0, 255]), False)
    ordinary_records = ([2, 255, 0, 255], [1, 255, 0, 255])
    check("summary-team-perspectives",
          (submitted_summary_scores(ordinary_records, 0), submitted_summary_scores(ordinary_records, 1)),
          ((2, 1), (1, 2)))
    asymmetric_records = ([2, 3, 0, 255], [1, 255, 0, 255])
    check("summary-own-byte1-selects-both-fields",
          (submitted_summary_scores(asymmetric_records, 0), submitted_summary_scores(asymmetric_records, 1)),
          ((3, 255), (1, 2)))
    check("summary-unavailable-leaves-score-fields-unwritten",
          submitted_summary_scores(([255, 3, 0, 255], [1, 2, 0, 255]), 1), None)
    check("query-status-exclusion-is-optional-and-one-sided",
          (bool(True and fixture_result_status([0, 255, 0, 255])),
           bool(False and fixture_result_status([0, 255, 0, 255]))), (True, False))
    check("actual-scheduler-excludes-populated-first-record",
          (not fixture_result_status([255, 255, 0, 255]),
           not fixture_result_status([0, 255, 0, 255])), (True, False))
    check("actual-scheduler-selected-full-branch", scheduled_task_type(False, False, False), "FULL")
    check("task-selector-can-choose-other", scheduled_task_type(False, True, False), "OTHER")
    check("force-full-bypasses-selector", scheduled_task_type(True, True, True), "FULL")
    check("collection-marker-empty-does-not-append", full_task_collection(0), "destroy")
    check("collection-marker-present-appends", full_task_collection(0x1000), "append")
    check("full-selector-active-first-object-bit", selected_full_selector(1, 1, 1, 1), 0)
    check("full-selector-inactive-prefix-returns-one", selected_full_selector(0, 1, 1, 1), 1)
    check("full-selector-mode-two-returns-one", selected_full_selector(1, 2, 1, 1), 1)
    check("full-selector-flag28d-zero-returns-one", selected_full_selector(1, 1, 0, 1), 1)
    check("full-selector-uncovered-tail-is-unknown", selected_full_selector(1, 1, 1, 0), None)
    check("team-payload-no-primary-skips-match-forward", team_payload_forwards_match(False, 1), False)
    check("team-payload-bit-clear-skips-match-forward", team_payload_forwards_match(True, 0), False)
    check("team-payload-bit-set-forwards-match", team_payload_forwards_match(True, 1), True)
    check("empty-team-payload-keeps-optional-reference",
          empty_team_payload_fields(0x50, 0x1234), (0, 1, 1, 0x1234))
    check("empty-team-payload-copies-optional-reference",
          empty_team_payload_fields(0x20, 0x1234, 0x5678), (1, 0, 0, 0x5678))
    fresh_header = bytes.fromhex("0500000000ff0000")
    check("fresh-payload-side0-forces-rebuild", payload_header_matches(fresh_header, 5, 42, 0, 1), False)
    check("fresh-payload-side1-forces-rebuild", payload_header_matches(fresh_header, 5, 0, 1, 1), False)
    check("cache-equality-ignores-byte7",
          payload_header_matches(bytes.fromhex("050000002a0001ff"), 5, 42, 0, 1), True)
    for code, expected_count in ((4, 7), (9, 7), (10, 1), (14, 1),
                                 (111, 1), (113, 7), (120, 7), (121, 1),
                                 (611, 7), (612, 1), (620, 7), (621, 1)):
        source = struct.pack("<HHBBBBBB", code, 7, 99, 1, 2, 3, 88, 77)
        projected = project_payload_event(source)
        check(f"event-projection-code-{code}", projected,
              struct.pack("<HHHBBB", code, expected_count, 7, 1, 2, 3))
    for count, expected in ((0, 1), (1, 2), (2, 3), (3, 4), (4, 6)):
        check(f"payload-growth-capacity-{count}", payload_growth_capacity(count), expected)
    for raw, expected in ((0, 1), (6, 1), (7, 2), (96, 19), (97, 20),
                          (100, 20), (127, 26), (128, 1), (255, 1)):
        check(f"payload-player-fixed-mask-{raw}", payload_player_read(raw), expected)
    candidate = bytes.fromhex("3a000000ffffffff0001ffff00000000")
    historical = bytes.fromhex("f3030001ff42")
    check("annotation-history-hit", payload_annotation_duplicate(0x3F3, candidate, [historical]), True)
    check("annotation-history-empty", payload_annotation_duplicate(0x3F3, candidate, []), False)
    changed = bytearray(candidate)
    changed[10] = 0
    check("annotation-third-key-mismatch", payload_annotation_duplicate(0x3F3, changed, [historical]), False)
    changed = bytearray(candidate)
    changed[11] = 0
    check("annotation-ignored-byte11", payload_annotation_duplicate(0x3F3, changed, [historical]), True)
    for total, expected in ((0, 0), (1, 1), (2, 2), (9, 0), (10, 0),
                            (-1, -1), (-9, 0), (-10, 0)):
        check(f"payload-reference-variant-{total}", payload_reference_variant(total, 0, 0), expected)
    check("payload-reference-sum-wraps-signed32",
          payload_reference_variant(0x7FFFFFFF, 1, 0), -2)
    for code, base in ((0x38, 0x4B74F), (0x3A, 0x4B752)):
        for variant, delta in ((0, 0), (1, 1), (2, 2), (-1, 2)):
            check(f"payload-resource-key-{code}-{variant}", payload_resource_key(code, variant), base + delta)
    populated = (0x1000, 0x2000, 0x3000, 0x4B752, 0xFF)
    moved, emptied = payload_move_into_empty(populated)
    check("descriptor-empty-target-receives-fields", moved, populated)
    check("descriptor-source-retains-only-metadata", emptied, (0, 0, 0, 0x4B752, 0xFF))
    check("descriptor-source-all-cleanup-pointers-null", emptied[:3], (0, 0, 0))
    check("descriptor-transfer-null-source-reference",
          payload_move_into_empty((0x1000, 0, 0x3000, -1, 0)),
          ((0x1000, 0, 0x3000, -1, 0), (0, 0, 0, -1, 0)))
    check("descriptor-equal-reference-keeps-both", payload_transfer_reference_fields(7, 7), (7, 7))
    check("descriptor-distinct-reference-transfers", payload_transfer_reference_fields(0, 7), (7, 0))
    check("element-null-child-shares-reference",
          payload_element_without_child(0x1000, 0x2000, 1), ((0x1000, 0x2000, 0), 2))
    check("element-null-reference-does-not-increment",
          payload_element_without_child(0x1000, 0, 0), ((0x1000, 0, 0), 0))
    slots = [(0x1000, (0x2000, 1)), (0, None)]
    check("group-borrowed-still-destroys-last-control",
          payload_group_release_actions(False, slots),
          [("decrement_control", 0x2000), ("virtual_destroy", 0x2000)])
    check("group-owned-destroys-first-before-control",
          payload_group_release_actions(True, slots),
          [("destroy_element", 0x1000), ("decrement_control", 0x2000), ("virtual_destroy", 0x2000)])
    check("group-shared-control-does-not-destroy",
          payload_group_release_actions(False, [(0x1000, (0x2000, 2))]),
          [("decrement_control", 0x2000)])
    check("control-source-owner-retained",
          payload_control_reference_cycle(1, 1, 0), (2, 2, 1, 0))
    check("control-source-owner-released",
          payload_control_reference_cycle(1, 1, 1), (2, 1, 0, 1))
    check("control-aliased-occurrences-owner-retained",
          payload_control_reference_cycle(1, 3, 0), (4, 4, 1, 0))
    check("control-aliased-occurrences-owner-released",
          payload_control_reference_cycle(1, 3, 1), (4, 3, 0, 1))
    check("initialization sets only record heads",
          initialize_fixture_record_heads([[255]*4, [255]*4], 0, [0, 0]),
          ([[0, 255, 255, 255], [0, 255, 255, 255]], [0, 0]))
    check("mode2 reads existing fourth byte into offsets",
          initialize_fixture_record_heads([[7, 8, 9, 3], [6, 5, 4, 2]], 2, [0, 0]),
          ([[0, 8, 9, 3], [0, 5, 4, 2]], [3, 2]))
    initialized, _ = initialize_fixture_record_heads([[255]*4, [255]*4], 0, [0, 0])
    check("ordinary increment after reached zero write",
          adjust_fixture_record(initialized[0], 0, 0, 1), [1, 255, 255, 255])
    team = bytearray([255] * 0x250)
    team[0x118:0x120] = (0x0A0A006400000000).to_bytes(8, "little")
    team[0x138:0x249] = bytes(0x111)
    check("team constructor offset and count start at zero",
          (team[0x11B], team[0x248], team[0x249]), (0, 0, 255))
    print(f"Local worked examples passed: {n}. No game functions executed.", flush=True)


def verify_index() -> None:
    """检查当前机制引用、关键连接证据及四个入口文档的本地链接。"""
    index = json.loads((ROOT / "EVIDENCE_INDEX.json").read_text())
    if not (ROOT / index["target_identity"]).is_file():
        raise ValueError("Missing recorded target identity")
    mechanisms = index["mechanisms"]
    ids = {item["id"] for item in mechanisms}
    if len(ids) != len(mechanisms):
        raise ValueError("Duplicate mechanism ID")
    for item in mechanisms:
        for direction in ("upstream", "downstream"):
            for reference in item[direction]:
                if reference not in ids:
                    raise ValueError(f"Unknown mechanism: {item['id']} -> {reference}")
        paths = [path for paths in item["evidence"].values() for path in paths]
        for connection in item.get("connections", []):
            paths.append(connection["evidence"])
            evidence = json.loads((ROOT / connection["evidence"]).read_text())
            addresses = {entry["va"] for entry in evidence["native_assertions"]}
            if connection["callsite"] not in addresses:
                raise ValueError(f"Connection callsite has no byte assertion: {connection['callsite']}")
        for path in paths:
            if not (ROOT / path).is_file():
                raise ValueError(f"Missing evidence file: {path}")
    for name in ("README.md", "RESEARCH_MAP.md", "OPEN_QUESTIONS.md",
                 "20261017_有效进球与比分状态生命周期.md"):
        for target in re.findall(r"\]\(([^)]+)\)", (ROOT / name).read_text()):
            if "://" in target or target.startswith("#"):
                continue
            path = unquote(target.split("#")[0])
            if not (ROOT / path).exists():
                raise ValueError(f"Missing local document link: {name} -> {target}")
    print(f"Index references and local document links passed: {len(mechanisms)} mechanisms.", flush=True)


def verify_target_identity(data: bytes, expected: dict) -> None:
    """先核对完整输入，再核对PE身份；不匹配时不得继续套用地址证据。"""
    if len(data) != expected["file_size"]:
        raise ValueError("Target file size differs; do not apply this evidence")
    if hashlib.sha256(data).hexdigest() != expected["sha256"]:
        raise ValueError("Target SHA-256 differs; do not apply this evidence")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    actual = {
        "machine": hex(struct.unpack_from("<H", data, pe + 4)[0]),
        "time_date_stamp": hex(struct.unpack_from("<I", data, pe + 8)[0]),
        "section_count": struct.unpack_from("<H", data, pe + 6)[0],
        "optional_magic": hex(struct.unpack_from("<H", data, optional)[0]),
        "image_base": hex(struct.unpack_from("<Q", data, optional + 24)[0]),
        "entry_point_rva": hex(struct.unpack_from("<I", data, optional + 16)[0]),
        "size_of_image": struct.unpack_from("<I", data, optional + 56)[0],
    }
    if actual != expected["pe"]:
        raise ValueError("Target PE identity differs from the recorded input")


def verify_original(exe):
    """只读原PE并复核证据中的指令字节；不加载或执行目标程序。"""
    print(f"Checking target identity and original bytes: {exe}", flush=True)
    data = exe.read_bytes()
    index = json.loads((ROOT / "EVIDENCE_INDEX.json").read_text())
    identity = json.loads((ROOT / index["target_identity"]).read_text())
    verify_target_identity(data, identity)
    print("Whole-file target identity passed; this does not verify the reported semantics.", flush=True)
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
        "20261019_archived_result_stream_observations.json",
        "20261019_result_list_precopy_observations.json",
        "20261019_precopy_tactic_callback_observations.json",
        "20261019_result_owner_cursor_observations.json",
        "20261019_result_batch_admission_observations.json",
        "20261019_actual_comp_stage_consumer_observations.json",
        "20261019_result_index_query_bridge_observations.json",
        "20261019_delegate_registration_observations.json",
        "20261019_player_stats_result_consumer_observations.json",
        "20261019_form_history_question_boundary_observations.json",
        "20261019_stage_aggregate_order_observations.json",
        "20261020_fixture_pointer_registration_observations.json",
        "20261020_result_summary_status_observations.json",
        "20261020_schedule_task_collection_observations.json",
        "20261020_full_output_order_observations.json",
        "20261020_team_payload_match_gate_observations.json",
        "20261020_payload_cache_cold_path_observations.json",
        "20261020_payload_event_aggregation_observations.json",
        "20261020_payload_allocator_boundary_observations.json",
        "20261020_payload_player_read_dedup_observations.json",
        "20261020_payload_label_dispatch_observations.json",
        "20261020_payload_descriptor_transfer_observations.json",
        "20261020_payload_nested_ownership_observations.json",
        "20261020_payload_release_retention_observations.json",
        "20261020_fixture_score_initialization_observations.json",
        "20261020_payload_null_slot_isolation_observations.json",
        "20261020_stage_dirty_acceptance_observations.json",
        "20261020_finalize_helper_preservation_observations.json",
        "20261021_current_league_result_observations.json",
        "20261021_finalize_event_storage_observations.json",
        "20261021_nonzero_player_condition_observations.json",
        "20261021_player_state_queue_observations.json",
        "20261021_candidate_nonempty_observations.json",
        "20261021_position_stream_observations.json",
        "20261021_full_builder_position_observations.json",
        "20261021_database_position_establishment_observations.json",
        "20261021_database_position_tail_observations.json",
        "20261021_database_outer_fields_observations.json",
        "20261021_database_recalculation_boundary_observations.json",
        "20261022_position_weight_roundtrip_observations.json",
        "20261022_player_service_same_day_observations.json",
    )]
    for evidence in evidences:
        if image_base != int(evidence["image_base"], 16):
            raise ValueError("PE image base differs from the selected research target")
    sections = []
    for i in range(section_count):
        _, rva, size, raw = struct.unpack_from("<IIII", data, optional + optional_size + i * 40 + 8)
        sections.append((rva, size, raw))

    def mapped_bytes(va, length):
        """按原PE区段映射读取地址，不依赖Ghidra指令文本。"""
        rva = va - image_base
        for start, size, raw in sections:
            if start <= rva and rva + length <= start + size:
                offset = raw + rva - start
                return data[offset:offset + length]
        raise ValueError(f"Unmapped original address {va:#x}")

    native = [item for evidence in evidences for item in evidence["native_assertions"]]
    static_data = [item for evidence in evidences for item in evidence.get("data_assertions", [])]
    for item in native + static_data:
        va = int(item["va"], 16)
        expected = bytes.fromhex(item["hex"])
        if mapped_bytes(va, len(expected)) != expected:
            raise AssertionError(f"Original bytes differ at {item['va']}; stop using this evidence")
    print(f"Original PE assertions passed: {len(native)} instruction/leaf, {len(static_data)} data.", flush=True)
    # 从原PE而非手写行为模型检查事件提交switch的完整目标集合。
    event_table = 0x141A73C98
    displacements = struct.unpack("<358i", mapped_bytes(event_table, 358 * 4))
    event_targets = {event_table + displacement for displacement in displacements}
    covered_targets = {
        0x141A737BD, 0x141A737EF, 0x141A737FD, 0x141A73808, 0x141A73813,
        0x141A7381E, 0x141A73829, 0x141A73834, 0x141A73875, 0x141A7387E,
    }
    if event_targets != covered_targets:
        raise AssertionError("Event submission switch reaches an uncovered target; reopen its call/write coverage")
    print("Event submission switch passed: 358 entries, 10 covered code targets; no game execution.", flush=True)

    # 刷新函数尾部为22项数据表，不能当作可执行间接跳转。
    refresh_table = 0x141B3AFD0
    refresh_displacements = struct.unpack("<22i", mapped_bytes(refresh_table, 22 * 4))
    refresh_targets = {refresh_table + displacement for displacement in refresh_displacements}
    if refresh_targets != {
        0x141B391F0, 0x141B3920E, 0x141B39376,
        0x141B39387, 0x141B39398, 0x141B393F6,
    }:
        raise AssertionError("Player refresh switch reaches an uncovered target; reopen its call/write coverage")
    print("Player refresh switch passed: 22 entries, 6 covered code targets; no game execution.", flush=True)

    adjustment_table = 0x141C3A770
    adjustment_displacements = struct.unpack("<31i", mapped_bytes(adjustment_table, 31 * 4))
    adjustment_targets = {adjustment_table + displacement for displacement in adjustment_displacements}
    if adjustment_targets != {
        0x141C3A2B2, 0x141C3A363, 0x141C3A40F,
        0x141C3A4BB, 0x141C3A502, 0x141C3A594,
    }:
        raise AssertionError("Player adjustment switch reaches an uncovered target; reopen its call/write coverage")
    print("Player adjustment switch passed: 31 entries, 6 covered code targets; no game execution.", flush=True)

    condition_evidence = json.loads((ROOT / "20261021_nonzero_player_condition_observations.json").read_text())
    for table in condition_evidence["classifier_switches"]:
        start = int(table["table"], 16)
        count = table["entries"]
        offsets = struct.unpack(f"<{count}i", mapped_bytes(start, count * 4))
        targets = {start + offset for offset in offsets}
        if targets != {int(address, 16) for address in table["destinations"]}:
            raise AssertionError("Nonzero condition classifier has an uncovered switch target")
        if not all(int(table["entry"], 16) <= target < int(table["code_end"], 16) for target in targets):
            raise AssertionError("Nonzero condition classifier leaves its covered code range")
    mode_table = 0x1419CE2CC
    modes = struct.unpack("<4i", mapped_bytes(mode_table, 16))
    if mode_table + modes[3] != 0x1419CD085:
        raise AssertionError("Actual nonzero condition mode3 reaches an uncovered branch")
    print("Nonzero condition branches passed: 7 classifier tables / 345 entries and actual mode3; no game execution.", flush=True)

    queue_evidence = json.loads((ROOT / "20261021_player_state_queue_observations.json").read_text())
    for link in queue_evidence["tail_connections"]:
        site = int(link["site"], 16)
        raw = mapped_bytes(site, 5)
        if raw[0] != 0xE9 or site + 5 + struct.unpack_from("<i", raw, 1)[0] != int(link["target"], 16):
            raise AssertionError(f"State queue tail target differs at {site:#x}; reopen its preservation boundary")
    print(f"State queue E9 checks passed: {len(queue_evidence['tail_connections'])}; kind1/message exclusion remains conditional.", flush=True)

    candidate_evidence = json.loads((ROOT / "20261021_candidate_nonempty_observations.json").read_text())

    def native_literal(spec):
        """读取证据中标明的原生立即数，不使用另行手填的掩码数值。"""
        return int.from_bytes(mapped_bytes(int(spec["va"], 16) + spec["offset"], spec["size"]), "little")

    threshold_bits = 0
    for spec in candidate_evidence["zero_threshold_masks"]:
        threshold_bits |= native_literal(spec)
    witnesses = candidate_evidence["nonempty_witnesses"]
    admitted = set(range(15)) - {1}
    if {w["outer_index"] for w in witnesses} != admitted or len(witnesses) != 14:
        raise AssertionError("Nonempty certificate does not cover every admitted position")
    if {w["attribute_index"] for w in witnesses} != admitted:
        raise AssertionError("Position-to-attribute coverage differs; reopen the nonempty condition")
    for witness in witnesses:
        i = witness["outer_index"]
        leaf = int(witness["attribute_leaf"], 16)
        if i <= 6:
            table = 0x1419C98EC
            target = table + struct.unpack("<i", mapped_bytes(table + ((1 << i) - 1) * 4, 4))[0]
            if target != leaf:
                raise AssertionError(f"Attribute index switch changed for position {i}")
        raw = mapped_bytes(leaf, 3)
        attribute = 0 if raw == b"\x31\xc0\xc3" else raw[1] if raw[0] == 0xB0 and raw[2] == 0xC3 else None
        if attribute != witness["attribute_index"]:
            raise AssertionError(f"Attribute index leaf differs for position {i}")
        j, k = witness["category_index"], witness["variant_index"]
        position_mask = native_literal(witness["position_mask_literal"])
        role_mask = native_literal(witness["role_mask_literal"])
        if not (0 <= j <= 52 and 0 <= k <= 52 and position_mask & (1 << j)
                and role_mask & (1 << k) and not threshold_bits & (1 << j)):
            raise AssertionError(f"No zero-threshold candidate witness for position {i}")
    for site, expected in ((0x141B2B98F, 0x2000), (0x141B2BA76, 0x4000)):
        raw = mapped_bytes(site, 5)
        mask = struct.unpack_from("<I", raw, 1)[0]
        if raw[0] != 0xA9 or mask != expected or mask & (0x200000000 | 0x400000000):
            raise AssertionError("Selected direct flag consumer no longer projects only the proven low bits")
    print("Candidate certificate passed: 14 original-constant zero-threshold witnesses; 2 low-bit consumers. Natural input establishment remains separate.", flush=True)

    position_evidence = json.loads((ROOT / "20261021_position_stream_observations.json").read_text())
    clamps = position_evidence["position_clamps"]
    if len(clamps) != 15 or {c["index"] for c in clamps} != set(range(15)):
        raise AssertionError("Position clamp coverage differs; reopen predicate preservation")
    for clamp in clamps:
        i = clamp["index"]
        compare = int(clamp["compare"], 16)
        store = int(clamp["store"], 16)
        if i == 0:
            comparison = b"\x80\x3e\x15"
            assignment = b"\xc6\x06\x14"
        else:
            displacement = struct.pack("<I", 0x108 + i)
            comparison = b"\x41\x80\xbd" + displacement + b"\x15"
            assignment = b"\x41\xc6\x85" + displacement + b"\x14"
        branch = mapped_bytes(compare + len(comparison), 2)
        if (mapped_bytes(compare, len(comparison)) != comparison
                or mapped_bytes(store, len(assignment)) != assignment
                or not (branch in (b"\x0f\x8c", b"\x0f\x8d") or branch[0] in (0x7C, 0x7D))):
            raise AssertionError(f"Signed upper clamp differs at position {i}")
    callbacks = struct.unpack("<QQ", mapped_bytes(0x145A1A060, 16))
    if callbacks != (0x141B3C6F0, 0x141B3C940):
        raise AssertionError("MATCH_PLAYER stream callback binding differs")
    raw = mapped_bytes(0x141B3C940, 5)
    if raw[0] != 0xE9 or 0x141B3C945 + struct.unpack_from("<i", raw, 1)[0] != 0x151C63300:
        raise AssertionError("MATCH_PLAYER virtual+20 thunk target differs")
    print("Position stream checks passed: 69-byte transfer assertions, 15 signed clamps and callback binding; input direction/provenance remain unbound.", flush=True)

    # 核对实际构建器、源getter与目标偏移，避免把流接口或相同偏移的其他对象混用。
    for slot, target in ((0x145B10218, 0x14519E490),
                         (0x145A4EC78, 0x142178F30),
                         (0x145C7EAB8, 0x142178F30),
                         (0x145A4F500, 0x1421D5200),
                         (0x145C7F340, 0x14499B080)):
        if struct.unpack("<Q", mapped_bytes(slot, 8))[0] != target:
            raise AssertionError("FULL builder or database-player virtual binding differs")
    if (mapped_bytes(0x142178F30, 8) != bytes.fromhex("488d8108020000c3")
            or mapped_bytes(0x1451A9AFA, 7) != bytes.fromhex("4881c680020000")
            or mapped_bytes(0x14519F794, 8) != bytes.fromhex("498d8c2408010000")
            or mapped_bytes(0x14519F79C, 6) != bytes.fromhex("41b845000000")):
        raise AssertionError("FULL position source/destination/length operands differ")
    print("FULL position source passed: actual slot -> P280 -> 69-byte copy; two conditional database getter bindings. Source predicate at copy time remains unproved.", flush=True)

    # 从限定原生操作数核对建立段，不以构造零值或输入记录存在代替位置门槛。
    base = struct.unpack_from("<I", mapped_bytes(0x14217B677, 7), 3)[0]
    even = mapped_bytes(0x14217B8C4, 8)
    odd = mapped_bytes(0x14217B8D8, 8)
    bound = mapped_bytes(0x14217B8D2, 4)[3]
    stride = mapped_bytes(0x14217B8C0, 4)[3]
    fallback = mapped_bytes(0x14217B8EC, 7)
    if (base != 0x208 or even[:3] != bytes.fromhex("80bc0f")
            or odd[:3] != bytes.fromhex("80bc0f") or even[7] != odd[7]
            or mapped_bytes(0x14217B8AE, 7) != bytes.fromhex("807d000f0f9dc0")
            or mapped_bytes(0x14217B8CC, 2) != bytes.fromhex("7c04")
            or mapped_bytes(0x14217B8E0, 2) != bytes.fromhex("7cde")
            or (bound, stride) != (12, 2) or fallback[:2] != bytes.fromhex("c687")):
        raise AssertionError("Database position establishment signed scan differs")
    even_offset = struct.unpack_from("<I", even, 3)[0] - base
    odd_offset = struct.unpack_from("<I", odd, 3)[0] - base
    indices = ({0} | {even_offset + i for i in range(0, bound + 1, stride)}
               | {odd_offset + i for i in range(0, bound, stride)})
    fallback_index = struct.unpack_from("<I", fallback, 2)[0] - base
    masks = struct.unpack("<15I", mapped_bytes(0x145A508E0, 60))
    if (indices != {0, *range(2, 15)} or fallback_index not in indices
            or not all(masks[i] for i in indices)
            or not fallback[6] >= even[7] == 15 >= 10):
        raise AssertionError("Database position establishment no longer implies candidate input predicate")
    print("Database position establishment passed: 14 signed >=15 tests and in-set fallback=20; establishment checkpoint; conditional return preservation checked next.", flush=True)

    # 只复核已绑定类型的有限虚调用，不把无直接位置写入等同于整次调用只读。
    tail_evidence = json.loads((ROOT / "20261021_database_position_tail_observations.json").read_text())
    bindings = tail_evidence["virtual_bindings"]
    if len(bindings) != 19 or len(tail_evidence["contract_types"]) != 7:
        raise AssertionError("Database tail virtual-binding coverage differs")
    for binding in bindings:
        slot = int(binding["slot"], 16)
        if struct.unpack("<Q", mapped_bytes(slot, 8))[0] != int(binding["target"], 16):
            raise AssertionError(f"Database tail virtual target differs at {slot:#x}")
    for site, raw in ((0x14217E34C, "49897608"),
                      (0x14217E3D9, "41808fbe01000040"),
                      (0x14217B90B, "888764020000"),
                      (0x14217BA02, "c3")):
        expected = bytes.fromhex(raw)
        if mapped_bytes(site, len(expected)) != expected:
            raise AssertionError("Database tail non-position write/return differs")
    date_write = mapped_bytes(0x141E9E6B1, 9)
    if (date_write[:3] != bytes.fromhex("66c705")
            or 0x141E9E6BA + struct.unpack_from("<i", date_write, 3)[0] != 0x14631FAF0):
        raise AssertionError("Date helper global write target differs")
    vbtable = struct.unpack("<iii", mapped_bytes(0x145A4E944, 12))
    if vbtable != (-8, 0x270, 0x298) or vbtable[1] + 8 != 0x278:
        raise AssertionError("Database player successful return interface layout differs")
    print("Database position tail passed: 19 virtual slots / 7 contract types, non-position writes and personnel return layout. Preservation to generator return remains conditional on stated ownership/type contracts.", flush=True)

    # 外层实际调用：检查虚基调整、全部局部分布调用及两个有限跳表。
    outer = json.loads((ROOT / "20261021_database_outer_fields_observations.json").read_text())
    if len(outer["virtual_bindings"]) != 9:
        raise AssertionError("Outer field-processing virtual coverage differs")
    for binding in outer["virtual_bindings"]:
        if struct.unpack("<Q", mapped_bytes(int(binding["slot"], 16), 8))[0] != int(binding["target"], 16):
            raise AssertionError("Outer field-processing virtual target differs")
    if struct.unpack("<ii", mapped_bytes(0x145A4E93C, 8)) != (-8, -0x30):
        raise AssertionError("Outer context-to-personnel virtual-base adjustment differs")
    profiles = outer["distribution_profiles"]
    if len(profiles) != 14:
        raise AssertionError("Outer distribution call coverage differs")
    for profile in profiles:
        site = int(profile["callsite"], 16)
        raw = mapped_bytes(site, 5)
        if (raw[0] != 0xE8 or site + 5 + struct.unpack_from("<i", raw, 1)[0] != 0x14499C260
                or profile["n"] != 8
                or mapped_bytes(int(profile["config_store"], 16), 8) != bytes.fromhex("c744243008000000")):
            raise AssertionError("Actual outer distribution profile no longer has n=8")
    outer_addresses = {int(row["va"], 16) for row in outer["native_assertions"]}
    if len(outer["switch_tables"]) != 2:
        raise AssertionError("Outer field-processing switch coverage differs")
    for table in outer["switch_tables"]:
        base = int(table["base"], 16)
        targets = [base + offset for offset in struct.unpack("<10i", mapped_bytes(base, 40))]
        if targets != [int(target, 16) for target in table["targets"]] or not set(targets) <= outer_addresses:
            raise AssertionError("Outer field-processing switch destination lacks native evidence")
    # 此处允许属性区后部写入；不能把“位置保持”升级成69字节全部保持。
    for site, raw in ((0x1426BE652, "88884a020000"),
                      (0x1426BE81C, "888846020000"),
                      (0x14499C2CA, "83f818"),
                      (0x1426BEAAF, "c3")):
        expected = bytes.fromhex(raw)
        if mapped_bytes(site, len(expected)) != expected:
            raise AssertionError("Outer field write, actual distribution branch or return differs")
    print("Database outer fields passed: ACTUAL_PLAYER 9 virtual slots, 14 n=8 distribution sites, 20 switch entries; writes at attributes62/66. First15 preservation is conditional on documented storage/runtime contracts, not a factory-to-match proof.", flush=True)

    # 重算边界只核对真实写点，不将“存在写回”自动解释为H变化或保持。
    if struct.unpack("<Q", mapped_bytes(0x145A4F530, 8))[0] != 0x1421D5280:
        raise AssertionError("Following helper personnel virtual+6b8 differs")
    for site, raw in ((0x142435499, "42884c2e5c"),
                      (0x14243552A, "884c2e59"),
                      (0x1424355B3, "888e4a020000"),
                      (0x1419D2DA1, "660fd627"),
                      (0x1419D2DDA, "660fd65f08"),
                      (0x14274B525, "41002c14"),
                      (0x14274B53E, "41882c14")):
        expected = bytes.fromhex(raw)
        if mapped_bytes(site, len(expected)) != expected:
            raise AssertionError("Following helper or attribute recalculation write differs")
    for site, raw in ((0x14216B690, "48c7868f01000000000000"),
                      (0x14216B69B, "48c7868701000000000000")):
        expected = bytes.fromhex(raw)
        if mapped_bytes(site, len(expected)) != expected:
            raise AssertionError("Constructor modifier-pointer zeroing differs")
    print("Database recalculation boundary passed: next helper non-position writes, first16 attribute writeback and modifier-tail writes. No whole-factory preservation or natural-input counterexample proved.", flush=True)

    weights = json.loads((ROOT / "20261022_position_weight_roundtrip_observations.json").read_text())
    table = weights["selected_position_switch"]
    base = int(table["base"], 16)
    targets = [base + offset for offset in struct.unpack("<15i", mapped_bytes(base, 60))]
    addresses = {int(row["va"], 16) for row in weights["native_assertions"]}
    if targets != [int(target, 16) for target in table["targets"]] or not set(targets) <= addresses:
        raise AssertionError("Selected-position counter switch lacks native targets")
    for site, raw in ((0x1419CF39C, "83020a"),
                      (0x1419CF6A2, "41b83c030000"),
                      (0x1419CFA11, "83f80a"),
                      (0x1419D23B4, "48c744242000000000"),
                      (0x1419D2500, "480f45da"),
                      (0x1419D2C88, "0f2ec3"),
                      (0x1419D2C8D, "7be1"),
                      (0x1419D2C69, "6689146b")):
        expected = bytes.fromhex(raw)
        if mapped_bytes(site, len(expected)) != expected:
            raise AssertionError("Position zero-weight/short-update branch differs")
    print("Position recalculation passed: selected counter switch15, actual count/clear/param5 and zero-weight skip anchors. Modifier roundtrip still requires documented snapshot, range and stability conditions; no natural score closure.", flush=True)

    service = json.loads((ROOT / "20261022_player_service_same_day_observations.json").read_text())
    for binding in service["virtual_bindings"]:
        if struct.unpack("<Q", mapped_bytes(int(binding["slot"], 16), 8))[0] != int(binding["target"], 16):
            raise AssertionError("Player service factory/virtual target differs")
    jump = mapped_bytes(0x1431D98F0, 5)
    if jump[0] != 0xE9 or 0x1431D98F5 + struct.unpack_from("<i", jump, 1)[0] != 0x1566F1340:
        raise AssertionError("Player service factory relocated body differs")
    for site, raw in ((0x1438F1D52, "6641b80100"),
                      (0x144B62C67, "41f6c501"),
                      (0x144B62C6D, "85f6"),
                      (0x144B65741, "c3"),
                      (0x14216B63D, "898650010000")):
        expected = bytes.fromhex(raw)
        if mapped_bytes(site, len(expected)) != expected:
            raise AssertionError("Actual player service mask/date/return anchor differs")
    branch = mapped_bytes(0x144B62C6F, 6)
    if branch[:2] != bytes.fromhex("0f84") or 0x144B62C75 + struct.unpack_from("<i", branch, 2)[0] != 0x144B656D6:
        raise AssertionError("Same-day player service branch no longer reaches covered epilogue")
    print("Player service same-day boundary passed: factory/primary service slots, relocated constructor, actual mask1 and date-zero return. Registry selection and constructor-to-call date continuity remain conditional.", flush=True)

    connections = [connection for item in index["mechanisms"]
                   for connection in item.get("connections", [])]
    for connection in connections:
        callsite = int(connection["callsite"], 16)
        raw = mapped_bytes(callsite, 5)
        if raw[0] != 0xE8:
            raise AssertionError(f"Not a direct E8 call at {callsite:#x}")
        callee = callsite + 5 + struct.unpack_from("<i", raw, 1)[0]
        if callee != int(connection["callee"], 16):
            raise AssertionError(f"Direct call target differs at {callsite:#x}")
    print(f"Direct-call displacement checks passed: {len(connections)}. Object-flow semantics remain conditional.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, help="可选：核对完整目标身份、字节和关键调用目标；不会执行游戏")
    args = parser.parse_args()
    verify_index()
    examples()
    if args.exe:
        verify_original(args.exe)
    print("Coverage: local frozen branches only; final valid-goal/score lifecycle remains open.", flush=True)
