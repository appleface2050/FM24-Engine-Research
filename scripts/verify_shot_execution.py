"""复核射门研究的原 PE 转录、直接调用与局部条件；不执行游戏或证明整场行为。"""

import argparse
import json
import math
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
    "20261028_goal_origin_and_substep_static.txt",
    "20261028_goal_contact_broadphase_static.txt",
    "20261028_goal_frame_child_bounds_static.txt",
    "20261028_goal_gravity_force_static.txt",
    "20261028_goal_physics_parameter_init_static.txt",
    "20261028_goal_physics_header_handoff_static.txt",
    "20261028_goal_environment_override_static.txt",
    "20261028_goal_environment_constructor_static.txt",
    "20261028_goal_environment_match_update_static.txt",
    "20261028_goal_environment_full_entry_static.txt",
    "20261028_goal_environment_player_shared_input_static.txt",
    "20261028_goal_constructed_quad_static.txt",
    "20261028_goal_constructed_quad_intersection_static.txt",
    "20261028_goal_quad_scan_selection_static.txt",
    "20261028_goal_crossing_time_handoff_static.txt",
    "20261028_goal_time_after_crossing_static.txt",
    "20261028_goal_angle_metadata_origin_static.txt",
    "20261028_goal_direction_table_witness_static.txt",
    "20261028_goal_reference_geometry_copy_static.txt",
    "20261028_goal_metadata_record_write_static.txt",
    "20261029_goal_shape_extent_initializer_static.txt",
    "20261029_goal_frame_position_source_static.txt",
    "20261029_goal_field_dimension_sentinel_static.txt",
    "20261029_goal_dimension_initialization_static.txt",
    "20261029_goal_dimension_reference_source_static.txt",
    "20261029_goal_fixture_dimension_pointer_copy_static.txt",
    "20261029_goal_fixture_clone_pointer_return_static.txt",
    "20261029_goal_pitch_clone_builder_intervening_calls_static.txt",
    "20261029_goal_builder_team_early_return_static.txt",
    "20261029_goal_full_selection_service_state_static.txt",
    "20261029_goal_pitch_data_helper_branch_static.txt",
    "20261029_goal_fixture_competition_callback_static.txt",
    "20261029_goal_league_stage_fixture_callback_static.txt",
    "20261029_goal_shot_origin_boundary_compatibility_static.txt",
    "20261029_goal_shot_origin_submission_argument_static.txt",
    "20261029_goal_shot_direction_lookup_static.txt",
    "20261029_goal_shot_target_field_origin_static.txt",
    "20261029_goal_shot_target_center_rng_static.txt",
    "20261029_goal_shot_target_post_generation_static.txt",
    "20261029_goal_shot_direction_helper_preservation_static.txt",
    "20261029_goal_shot_finishing_and_direction_static.txt",
    "20261029_goal_shot_solver_input_static.txt",
    "20261029_goal_shot_solver_selection_static.txt",
    "20261029_goal_shot_solver_spin_incompatibility_static.txt",
    "20261029_goal_shot_trial_ground_branch_static.txt",
    "20261029_goal_shot_trial_contact_response_static.txt",
    "20261029_goal_shot_ground_normal_initializer_static.txt",
    "20261029_goal_shot_ground_material_init_static.txt",
    "20261029_goal_shot_ground_first_shape_binding_static.txt",
    "20261029_goal_shot_trial_post_contact_step_static.txt",
    "20261029_goal_shot_trial_constraint_clear_static.txt",
    "20261029_goal_shot_zero_perturbation_static.txt",
    "20261029_goal_context_perturbation_initialization_static.txt",
    "20261029_goal_shot_candidate_priority_flag_static.txt",
    "20261029_goal_shot_candidate_post_creation_static.txt",
    "20261029_goal_shot_candidate_first_multiplier_static.txt",
    "20261029_goal_shot_candidate_second_multiplier_static.txt",
    "20261029_goal_shot_scoring_state_writes_static.txt",
    "20261029_goal_shot_scoring_update_order_static.txt",
    "20261029_goal_shot_scoring_intermediate_helpers_static.txt",
    "20261029_goal_shot_action_before_state_update_static.txt",
    "20261029_goal_shot_match_flag_clear_static.txt",
    "20261029_goal_shot_reference_dispatch_compatibility_static.txt",
    "20261029_goal_shot_candidate_context_init_static.txt",
    "20261029_goal_shot_direction_equal_case_static.txt",
    "20261029_goal_shot_post_candidate_short_returns_static.txt",
    "20261029_goal_shot_post_candidate_first_return_static.txt",
    "20261029_goal_shot_candidate_flag_conflict_static.txt",
    "20261029_goal_shot_near_candidate_initialization_static.txt",
    "20261029_goal_shot_model_empty_subject_static.txt",
    "20261030_goal_preparation_cache_return_static.txt",
    "20261030_goal_cache_ball_query_static.txt",
    "20261030_goal_cache_pair_geometry_writes_static.txt",
    "20261030_goal_cache_candidate_query_writes_static.txt",
    "20261030_goal_cache_position_query_static.txt",
    "20261030_goal_cache_bracketing_query_static.txt",
    "20261030_goal_cache_reset_state_gates_static.txt",
    "20261030_goal_reset_to_position_update_static.txt",
    "20261030_goal_cache_complete_preservation_static.txt",
    "20261030_goal_preparation_return_preservation_static.txt",
    "20261030_goal_candidate_context_entry_geometry_static.txt",
    "20261030_goal_candidate_roster_query_static.txt",
    "20261030_goal_candidate_context_speed_preservation_static.txt",
    "20261030_goal_candidate_attribute_gate_static.txt",
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
    check(struct.unpack_from("<Q", data, offset(0x145D2FCF8 + 8))[0]
          == 0x1453899F0, "Frame child transform slot")
    check(struct.unpack_from("<f", data, offset(0x145A1D4D4))[0] == 2.0,
          "Shot candidate second multiplier")
    check(0x144439894 + struct.unpack_from("<i", data, offset(0x144439898))[0]
          == 0x1444339FB, "Shot candidate scoring switch")
    check(struct.unpack_from("<f", data, offset(0x145A1D4B0))[0] == 1.0,
          "Shot candidate first multiplier")
    check(struct.unpack_from("<f", data, offset(0x145A1D524))[0] == 20.0,
          "Alternate shot candidate threshold")
    check(struct.unpack_from("<f", data, offset(0x145816548))[0] == -240.0
          and struct.unpack_from("<f", data, offset(0x1456B0CD8))[0] == 240.0,
          "Bracketing query fallback time offsets")
    for address, value in ((0x145A1D454, -1000.0), (0x145A1D594, 999999.0),
                           (0x145A1D4A0, 0.25),
                           (0x145A1D404, 3.6600000858306885),
                           (0x145A1D4C8, 0.10000000149011612),
                           (0x145A1D4D0, 0.05000000074505806), (0x145A1D570, 100.0)):
        check(struct.unpack_from("<f", data, offset(address))[0] == value,
              f"Reset/position scalar constant {address:x}")
    check(struct.unpack_from("<f", data, offset(0x145A1D53C))[0] == 30.0,
          "Team geometry comparison constant")
    check(struct.unpack_from("<f", data, offset(0x145A1D4EC))[0] == 5.0,
          "Team geometry distance offset")
    for address, value in ((0x14558DD60, 0.25), (0x145A1D4F0, 6.0),
                           (0x145A1D50C, 12.0),
                           (0x145C40604, 10000000000.0),
                           (0x145A1D41C, 0.1111999973654747),
                           (0x145C405E4, 3.1415927410125732),
                           (0x1455829FC, 0.5)):
        check(struct.unpack_from("<f", data, offset(address))[0] == value,
              f"Geometry constant {address:x}")

    check(struct.unpack_from("<Q", data, offset(0x145B10178 + 0x30))[0]
          == 0x145183700, "FULL builder dimension provider slot")
    for address, value in ((0x145A19010, 100.6500015258789),
                           (0x145A19014, 68.625), (0x14559C24C, 10.0),
                           (0x1456B1D58, 90.0), (0x1456006D0, 120.0),
                           (0x1458704A8, 55.0)):
        check(struct.unpack_from("<f", data, offset(address))[0] == value,
              f"Dimension source constant {address:x}")

    check(data[offset(0x1456848A0):offset(0x1456848A0) + 16]
          == bytes.fromhex("00000080" * 4), "Coordinate sign-bit mask")

    check(struct.unpack_from("<Q", data, offset(0x145608078 + 0x110))[0]
          == 0x141E435F0, "FIXTURE_RESULT clone slot")

    for slot, target in ((0x10, 0x140269550), (0x18, 0x140269560),
                         (0x28, 0x140269570), (0x30, 0x140269580),
                         (0x58, 0x141E446C0), (0x90, 0x140269610)):
        check(struct.unpack_from("<Q", data, offset(0x145608078 + slot))[0]
              == target, f"FIXTURE_RESULT copy callback {slot:x}")

    check(struct.unpack_from("<Q", data, offset(0x145A20E08 + 0xD0))[0]
          == 0x141DF8D10, "ACTUAL_COMP fixture preparation callback")

    check(struct.unpack_from("<Q", data, offset(0x145A41AE8 + 0x2D8))[0]
          == 0x141E14C40, "LEAGUE_STAGE fixture callback")

    for address, value in ((0x145A1D404, 3.6600000858306885),
                           (0x145A1D410, 2.440000057220459)):
        check(struct.unpack_from("<f", data, offset(address))[0] == value,
              f"Shot origin geometry threshold {address:x}")

    check(struct.unpack_from("<f", data, offset(0x145A1D504))[0] == 10.0,
          "Shot target lookup coordinate scale")

    check(struct.unpack_from("<f", data, offset(0x1455A9880))[0]
          == 0.10000000149011612, "Direction table coordinate scale")

    check(struct.unpack_from("<f", data, offset(0x145A1D500))[0] == 9.0,
          "Shot target height branch threshold")

    for address, value in ((0x145A1D4E4, 4.0),
                           (0x145A1D460, 0.10000000149011612)):
        check(struct.unpack_from("<f", data, offset(address))[0] == value,
              f"Shot target blend threshold {address:x}")

    def f32(value):
        """将算例每一步舍入为单精度，模拟选定的标量运算顺序。"""
        return struct.unpack("<f", struct.pack("<f", value))[0]

    # 验证角度取整的调用确实指向 PE 中的 CRT floorf 导入槽。
    thunk = offset(0x14557EA20)
    check(data[thunk:thunk + 2] == b"\xff\x25", "floorf thunk opcode")
    check(0x14557EA26 + struct.unpack_from("<i", data, thunk + 2)[0]
          == 0x145D50F40, "floorf import slot")
    descriptor = offset(0x15CF4A2A8)
    lookup, _, _, module, iat = struct.unpack_from("<IIIII", data, descriptor)
    check(iat == 0x5D50EB0, "math import table")
    check(data[offset(0x140000000 + module):offset(0x140000000 + module) + 31] ==
          b"api-ms-win-crt-math-l1-1-0.dll\0", "math import module")
    item = lookup + ((0x5D50F40 - iat) // 8) * 8
    name = struct.unpack_from("<Q", data, offset(0x140000000 + item))[0]
    check(data[offset(0x140000000 + name + 2):offset(0x140000000 + name + 2) + 7]
          == b"floorf\0",
          "floorf import name")
    thunk = offset(0x14557E9B0)
    check(data[thunk:thunk + 2] == b"\xff\x25"
          and 0x14557E9B6 + struct.unpack_from("<i", data, thunk + 2)[0] == 0x145D50F08,
          "Cache ceilf import slot")
    item = lookup + ((0x5D50F08 - iat) // 8) * 8
    name = struct.unpack_from("<Q", data, offset(0x140000000 + item))[0]
    check(data[offset(0x140000000 + name + 2):offset(0x140000000 + name + 2) + 6]
          == b"ceilf\0", "Cache ceilf import name")
    check(math.floor(f32(f32(1.5 * f32(0.2)) + 0.5)) == 0,
          "Zero angle witness distance correction")

    # 固定随机见证：目标居中、两轴旋转为零、射门抽样为1。
    state = 0x9610158181B549B1
    expected = (0x802C3081, 0x93E7D808, 0xC417FFD1, 0x17C2A8CB, 0x12215DAE)
    draws = []
    for value in expected:
        x = ((state >> 45) ^ (state >> 27)) & 0xFFFFFFFF
        rotation = state >> 59
        result = ((x >> rotation) | (x << ((-rotation) & 31))) & 0xFFFFFFFF
        check(result == value, "Shot zero-spin witness PRNG output")
        draws.append(result)
        state = (state * 0x5851F42D4C957F2D + 1) & 0xFFFFFFFFFFFFFFFF
    check(state == 0x1E9DD04DA2048F0A, "Shot zero-spin witness final state")
    check((664 * draws[0] >> 32) - 332 == 0, "Centered target")
    check((6 * draws[1] >> 32) - 3 == 0, "Vertical spin input")
    check(-2 + (3 * draws[2] >> 32) == 0, "Lateral spin input")
    check(20 * draws[3] >> 32 == 1, "Finishing sample")
    check(10 * draws[4] >> 32 == 0, "Solver angle sample")

    # 零角度试算器多项式，以及中心目标/选定记录的条件性方向算例。
    for address, bits in ((0x145831614, 0x3FC90FDB),
                          (0x145A0A9FC, 0x3FA2F983),
                          (0x145A13508, 0xBECF817B),
                          (0x145A0AA04, 0x3E666666)):
        check(struct.unpack_from("<I", data, offset(address))[0] == bits,
              f"Shot direction polynomial constant {address:x}")
    bits_float = lambda bits: struct.unpack("<f", struct.pack("<I", bits))[0]
    angle = bits_float(0x3FC90FDB)
    factor = f32(f32(angle * bits_float(0x3FA2F983))
                 + f32(f32(bits_float(0xBECF817B) * angle) * abs(angle)))
    factor = f32(factor + f32(f32(f32(abs(factor) * factor) - factor)
                              * bits_float(0x3E666666)))
    check(struct.pack("<f", f32(35 * factor)).hex() == "ffff0b42",
          "Zero angle solver speed factor")
    # t=(0,1)，选中的有限记录q=(0,2)：镜像方向为(0,1)。
    qx, qy = f32(0), f32(2)
    qlength = f32(math.sqrt(f32(f32(qx * qx) + f32(qy * qy))))
    ux, uy = f32(qx / qlength), f32(qy / qlength)
    vx = f32(f32(35 * factor) * f32(-ux))
    vy = f32(f32(35 * factor) * uy)
    check(vx == 0.0 and struct.pack("<f", vy).hex() == "ffff0b42",
          "Shot reflection conditional output")

    # 试算记录扫描使用严格大于，等于目标距离不会被选中。
    target_distance_squared = f32(f32(1.5 * 1.5))
    records = ((0.0, 0.0), (0.0, 1.5), (0.0, 2.0))
    chosen = next((x, y) for x, y in records
                  if f32(f32(x * x) + f32(y * y)) > target_distance_squared)
    check(chosen == (0.0, 2.0), "Shot trial first strictly beyond target")

    # 指定零高度和向下加速度时，试算分支将负的平面相交比例截到0。
    step = f32(1 / 12)
    dz = f32(f32(f32(f32(step * step) * f32(-9.8)) * f32(0.5)))
    fraction = f32(f32(0.1112) / dz)
    check(dz < 0 and fraction < 0, "Trial ground witness branch")
    check(max(fraction, 0.0) == 0.0, "Trial ground intersection clamp")

    # 环境构造器的六个材料项，由指令立即数和只读向量组装。
    material_bytes = (struct.pack("<Q", 0x402000003F000000)
                      + data[offset(0x145A1A420):offset(0x145A1A420) + 16]
                      + data[offset(0x145A1A430):offset(0x145A1A430) + 16]
                      + data[offset(0x145A1A440):offset(0x145A1A440) + 16]
                      + data[offset(0x145A1A420):offset(0x145A1A420) + 16])
    check(len(material_bytes) == 72, "Constructed material table size")
    for index in range(6):
        check(struct.unpack_from("<fff", material_bytes, index * 12)
              == (0.5, 2.5, 0.5), f"Constructed material entry {index}")

    # 构造器后续调用在 E+d0=2 时重写六项；不是上面的暂存表。
    updated = bytearray(material_bytes)
    struct.pack_into("<Q", updated, 0, 0x402000003F333333)
    struct.pack_into("<I", updated, 8, 0x3F000000)
    struct.pack_into("<III", updated, 12, 0x3F19999A, 0x40000000, 0x3F000000)
    updated[24:40] = data[offset(0x145C4BF50):offset(0x145C4BF50) + 16]
    struct.pack_into("<Q", updated, 40, 0x3F4CCCCD40400000)
    struct.pack_into("<Q", updated, 48, 0x3FC000003F000000)
    struct.pack_into("<I", updated, 56, 0x3E99999A)
    struct.pack_into("<Q", updated, 60, 0x402000003F000000)
    struct.pack_into("<I", updated, 68, 0x3F000000)
    expected_bits = ((0x3F333333, 0x40200000, 0x3F000000),
                     (0x3F19999A, 0x40000000, 0x3F000000),
                     (0x3F000000, 0x40000000, 0x3F000000),
                     (0x3DCCCCCD, 0x40400000, 0x3F4CCCCD),
                     (0x3F000000, 0x3FC00000, 0x3E99999A),
                     (0x3F000000, 0x40200000, 0x3F000000))
    for index, expected in enumerate(expected_bits):
        check(struct.unpack_from("<III", updated, index * 12) == expected,
              f"Updated material entry {index}")

    # 条件性地面接触算例：切向变化和旋转的量级。
    remaining, gravity, mass, mu, radius, inertia = map(f32, (0.1, 10, 1, 0.1, 0.1, 1))
    normal_impulse = f32(f32(remaining * gravity) * mass)
    tangential_impulse = f32(-f32(normal_impulse * mu))
    vy = f32(f32(10) + tangential_impulse)
    wx = f32(f32(radius * tangential_impulse) / inertia)
    check(0 < vy < 10 and wx < 0, "Ground response changes speed and spin")
    check(f32(vy + f32(radius * wx)) > 0, "Ground example avoids reversal")

    # 将已定位的球参数及索引0材料用于限定地面响应，保持原生float32步骤。
    radius, mass, h, gravity, coefficient = map(f32, (0.1112, 0.43, 1 / 12, -9.8, 0.5))
    inertia = f32(f32(radius * radius) * f32(2 / 3))
    speed = struct.unpack("<f", bytes.fromhex("ffff0b42"))[0]
    impulse = f32(f32(-f32(h * gravity)) * mass)
    impulse_y = f32(-f32(impulse * coefficient))
    after_y = f32(speed + impulse_y)
    after_wx = f32(f32(radius * impulse_y) / inertia)
    check(struct.pack("<f", after_y).hex() == "334c0b42",
          "Constructed-parameter ground tangential speed")
    check(struct.pack("<f", after_wx).hex() == "309517c0",
          "Constructed-parameter ground generated spin")
    check(f32(after_y + f32(radius * after_wx)) > 0,
          "Constructed-parameter ground no reversal")

    # 限定接触后下一步：速度超高阈值，旋转力只在Z方向。
    density = struct.unpack("<f", bytes.fromhex("19cc9c3f"))[0]
    pi = struct.unpack("<f", struct.pack("<I", 0x40490FDB))[0]
    area = f32(f32(f32(pi * radius) * radius) * f32(0.5))
    drag_scale = f32(f32(f32(density * area) * f32(0.24)) * after_y)
    acceleration_y = f32(f32(drag_scale * f32(-after_y)) / mass)
    dy = f32(f32(h * after_y) + f32(f32(f32(h * h) * acceleration_y) * f32(0.5)))
    check(struct.pack("<f", dy).hex() == "b9263640" and dy > 1.5,
          "Trial post-contact horizontal threshold")
    check(f32(dy / f32(math.sqrt(f32(dy * dy)))) == 1.0,
          "Trial selected direction normalization")

    # 相同归一化时间的零时长接触会复写记录，水平坐标保持。
    time = f32(h / f32(0.25))
    last = (f32(0), dy, time)
    contact = (last[0], last[1], f32(f32(h + 0.0) / f32(0.25)))
    check(contact[2] == last[2] and contact[:2] == last[:2],
          "Zero-duration contact replaces same-time position record")

    # 对称地面试算：三个子步、两次重复接触与记录筛选。
    trial_y, trial_v, trial_w, elapsed = f32(0), speed, f32(0), f32(0)
    duration, max_step = f32(0.25), f32(1 / 12)
    trial_records = [f32(0)]
    for _ in range(3):
        trial_h = min(max_step, f32(duration - elapsed))
        j = f32(f32(-f32(trial_h * gravity)) * mass)
        if trial_w != 0:
            spin_length = f32(math.sqrt(f32(trial_w * trial_w)))
            spin_damping = min(f32(f32(2.5) * j), spin_length)
            trial_w = f32(trial_w - f32(spin_damping * f32(trial_w / spin_length)))
        friction = f32(-f32(j * coefficient))
        trial_v = f32(trial_v + friction)
        trial_w = f32(trial_w + f32(f32(radius * friction) / inertia))
        check(f32(trial_v + f32(radius * trial_w)) > 0,
              "Trial contact avoids tangential reversal")
        check(trial_v > 21, "Trial remains in high-speed drag branch")
        scale = f32(f32(f32(density * area) * f32(0.24)) * trial_v)
        acceleration = f32(f32(scale * f32(-trial_v)) / mass)
        delta = f32(f32(trial_h * trial_v)
                    + f32(f32(f32(trial_h * trial_h) * acceleration) * f32(0.5)))
        trial_y = f32(trial_y + delta)
        trial_v = f32(trial_v + f32(trial_h * acceleration))
        elapsed = f32(elapsed + trial_h)
        trial_records.append(trial_y)
    check(trial_records == [0.0, 2.846113443374634, 5.570520401000977,
                            8.182209014892578], "Three trial positions")
    check(elapsed == duration, "Trial completes time interval")
    check(next(y for y in trial_records if f32(y * y) > f32(1.5 * 1.5))
          == trial_records[1], "First beyond-target record")

    # K=0 时，修正幅度在普通有限值下不会进入正数扰动分支。
    for control in (-100, 0, 100):
        amplitude = f32(f32(f32(0) * f32(0.01)) * f32(40))
        threshold = f32(f32(control) * f32(0.2))
        if amplitude > threshold:
            amplitude = f32(amplitude + f32(f32(threshold - amplitude) * f32(0.75)))
        check(amplitude <= 0.0, "Zero parameter avoids positive perturbation")

    # 环境构造器：第二参数0、第三参数15，expf(0)=1；按原生float32次序。
    def float_bits(value):
        """解码原指令的 float32 常量位模式。"""
        return struct.unpack("<f", struct.pack("<I", value))[0]

    a490, a498, a49c, a4a0 = map(float_bits, (
        0x43889333, 0x3CED46C0, 0x41050807, 0x47C5E680))
    density = f32(f32(f32(1.0 * a4a0) * a498)
                  / f32(f32(f32(15) + a490) * a49c))
    density = max(density, float_bits(0x3F733333))
    check(struct.pack("<f", density).hex() == "19cc9c3f",
          "Environment constructor coefficient arithmetic")

    check(struct.unpack_from("<f", data, offset(0x145A1D5A8))[0]
          == float_bits(0x3E9C0EBF), "Environment input scale")
    updated_density = f32(f32(f32(1.0 * a4a0) * a498)
                          / f32(f32(f32(20) + a490) * a49c))
    check(struct.pack("<f", updated_density).hex() == "771f9a3f",
          "Environment match update comparison")

    for temperature_like, expected in ((30, "f309953f"), (31, "818c943f")):
        value = f32(f32(f32(1.0 * a4a0) * a498)
                    / f32(f32(f32(temperature_like) + a490) * a49c))
        check(struct.pack("<f", value).hex() == expected,
              "Shared match input coefficient comparison")
    check((100 * 9) // 10 == 90, "Work-rate internal threshold example")

    check(struct.unpack_from("<Q", data, offset(0x145D2FBD8 + 8))[0]
          == 0x145388B10, "Ground shape virtual transform target")
    check(data[offset(0x145388B10)] == 0xC3, "Ground shape transform is RET")

    check(struct.unpack_from("<Q", data, offset(0x145D4BE30))[0] == 0x1418F88D0,
          "Ground normal initializer pointer")

    check(struct.unpack_from("<Q", data, offset(0x145D4BE58))[0] == 0x1418FDF30,
          "Shape extent initializer pointer")
    check(f32(f32(0.06) * f32(1)) == f32(0.06), "Shape extent example")

    check(struct.unpack_from("<f", data, offset(0x145A1D418))[0]
          == float_bits(0x3CA3D70A), "Frame position offset constant")
    frame_y = f32(f32(f32(105) * f32(0.5)) - float_bits(0x3CA3D70A))
    check(struct.pack("<f", frame_y).hex() == "85eb5142", "Frame position example")

    # 场地对象的四个尺寸槽在构造时均为float32 -1。
    check(struct.unpack_from("<4I", data, offset(0x14565D780))
          == (0xBF800000,) * 4, "Match dimension initial vector")
    check(f32(f32(-1) * f32(0.5)) != f32(-1),
          "Constructor sentinel is not a half-length relation")

    radius = f32(0.1112)
    area = f32(f32(f32(math.pi) * radius) * radius)
    check(struct.pack("<f", area).hex() == "371e1f3d"
          and struct.pack("<f", f32(area * 0.5)).hex() == "371e9f3c",
          "Ball parameter initialization arithmetic")

    elapsed, total, limit = 0.0, f32(0.25), f32(1 / 12)
    fractions, positions, heights, y = [], [], [], f32(51.0)
    z, vz, gravity = f32(1.125), f32(0), f32(-9.8)
    while elapsed < total:
        step = min(limit, f32(total - elapsed))
        elapsed = f32(elapsed + step)
        fractions.append(struct.pack("<f", f32(elapsed / total)).hex())
        y = f32(y + f32(f32(12.0) * step))
        positions.append(y)
        gravity_displacement = f32(f32(f32(step * step) * gravity) * 0.5)
        z = f32(z + f32(f32(step * vz) + gravity_displacement))
        vz = f32(vz + f32(step * gravity))
        heights.append(struct.pack("<f", z).hex())
    check(fractions == ["abaaaa3e", "abaa2a3f", "0000803f"],
          "Default-parameter substep example")
    check(positions == [52.0, 53.0, 54.0]
          and positions[0] < 52.625 < positions[1],
          "Worked trajectory crosses plane in second substep")
    check(heights == ["faa48b3f", "d2277d3f", "9999513f"],
          "Gravity trajectory substep example")

    # 固定非零阻力算例；逐次执行原指令对应的 float32 算术。
    elapsed, y, z, vy, vz = 0.0, f32(51), f32(1.125), f32(12), f32(0)
    drag_positions = []
    while elapsed < total:
        step = min(limit, f32(total - elapsed))
        speed = f32(math.sqrt(f32(f32(vy * vy) + f32(vz * vz))))
        magnitude = f32(f32(f32(f32(1) * f32(0.01)) * f32(0.5)) * speed)
        ay = f32(f32(f32(magnitude * -vy) / f32(0.45)) + f32(0))
        az = f32(f32(f32(magnitude * -vz) / f32(0.45)) + gravity)
        h2 = f32(step * step)
        y = f32(y + f32(f32(step * vy) + f32(f32(h2 * ay) * f32(0.5))))
        z = f32(z + f32(f32(step * vz) + f32(f32(h2 * az) * f32(0.5))))
        vy, vz = f32(vy + f32(step * ay)), f32(vz + f32(step * az))
        elapsed = f32(elapsed + step)
        drag_positions.append((struct.pack("<f", y).hex(), struct.pack("<f", z).hex()))
    check(drag_positions == [("50fa4f42", "faa48b3f"),
                             ("5ce95342", "61407d3f"),
                             ("56cd5742", "f013523f")],
          "Nonzero drag trajectory example")

    # 比较人为指定u=1和构造条件下的环境系数；轨迹仍为冻结输入。
    trajectory_cases = (
        (f32(1), [("68f74f42", "c7e0893f"),
                  ("d3dd5342", "99c4793f"),
                  ("a3b35742", "1fca4e3f")]),
        (density, [("79f54f42", "c7e0893f"),
                   ("32d65342", "e1cc793f"),
                   ("bfa25742", "f6f24e3f")]),
    )
    for environment, expected in trajectory_cases:
        elapsed, y, z, vy, vz = 0.0, f32(51), f32(1 + radius), f32(12), f32(0)
        initialized_positions = []
        for _ in range(3):
            step = min(limit, f32(total - elapsed))
            speed = f32(math.sqrt(f32(f32(vy * vy) + f32(vz * vz))))
            check(8 < speed < 21, "Initialized-parameter interpolation branch")
            t = f32(f32(speed - f32(8)) / f32(f32(21) - f32(8)))
            smooth = f32(f32(t * t) * f32(f32(3) - f32(t + t)))
            coefficient = f32(f32(f32(f32(0.24) - f32(0.41)) * smooth) + f32(0.41))
            magnitude = f32(f32(f32(environment * f32(area * 0.5)) * coefficient) * speed)
            ay = f32(f32(f32(magnitude * -vy) / f32(0.43)) + f32(0))
            az = f32(f32(f32(magnitude * -vz) / f32(0.43)) + gravity)
            h2 = f32(step * step)
            y = f32(y + f32(f32(step * vy) + f32(f32(h2 * ay) * f32(0.5))))
            z = f32(z + f32(f32(step * vz) + f32(f32(h2 * az) * f32(0.5))))
            vy, vz = f32(vy + f32(step * ay)), f32(vz + f32(step * az))
            elapsed = f32(elapsed + step)
            initialized_positions.append((y, z))
        check(elapsed == total, "Initialized-parameter substeps reach total")
        check([(struct.pack("<f", yy).hex(), struct.pack("<f", zz).hex())
               for yy, zz in initialized_positions] == expected,
              "Initialized-parameter trajectory example")
        plane = f32(f32(52.5) + radius)
        check(initialized_positions[0][0] < plane < initialized_positions[1][0],
              "Frozen plane crossed in second substep")
        check(all(zz - radius > 0 for _, zz in initialized_positions),
              "Frozen trajectory stays above ground")

    # 根据1443e8310的float32近似旋转构造正侧门口，而非假设轴对齐。
    geometry_constants = {
        0x145C405F8: 0x3C8EFA35, 0x1455A7BEC: 0x43340000,
        0x145830658: 0xC0490FDB, 0x1457ED450: 0x40C90FDB,
        0x1456D56D4: 0x40490FDB, 0x145831614: 0x3FC90FDB,
        0x14583065C: 0xC0C90FDB, 0x145A0A9FC: 0x3FA2F983,
        0x145A0AA00: 0x3ECF817B, 0x145A0AA04: 0x3E666666,
        0x145A1D404: 0x406A3D71, 0x145A1D410: 0x401C28F6,
        0x1456D56F8: 0x00000000,
    }
    for address, bits in geometry_constants.items():
        check(struct.unpack_from("<I", data, offset(address))[0] == bits,
              f"Goal geometry constant {address:x}")
    check(struct.unpack_from("<4I", data, offset(0x1457ED810))
          == (0x3F800000, 0x3F800000, 0x3F800000, 0),
          "Goal geometry vector constant")
    angle = f32(float_bits(0x43340000) * float_bits(0x3C8EFA35))
    shifted = f32(angle + float_bits(0x3FC90FDB))
    if shifted > float_bits(0x40490FDB):
        shifted = f32(shifted + float_bits(0xC0C90FDB))

    def approximate_sine(x):
        """复现此构造路径使用的逐次 float32 近似三角运算。"""
        base = f32(f32(x * float_bits(0x3FA2F983))
                   - f32(f32(x * float_bits(0x3ECF817B)) * abs(x)))
        return f32(f32(f32(f32(abs(base) * base) - base)
                       * float_bits(0x3E666666)) + base)

    sine, cosine = approximate_sine(angle), approximate_sine(shifted)
    width, height = float_bits(0x406A3D71), float_bits(0x401C28F6)
    vertices = []
    for x, z in ((-width, 0), (width, 0), (width, height), (-width, height)):
        rotated_x = f32(f32(x * cosine) - f32(-radius * sine))
        rotated_y = f32(f32(f32(x * sine) + f32(-radius * cosine)) + f32(52.5))
        vertices.append((rotated_x, rotated_y, z))
    check([[struct.pack("<f", value).hex() for value in vertex] for vertex in vertices]
          == [["733d6a40", "df715242", "00000000"],
              ["733d6ac0", "de715242", "00000000"],
              ["733d6ac0", "de715242", "f6281c40"],
              ["733d6a40", "df715242", "f6281c40"]],
          "Constructed positive-side goal vertices")
    center_plane = (vertices[0][1] + vertices[1][1]) / 2
    first, second = initialized_positions[:2]
    intersection_z = (first[1] - radius
                      + (center_plane - first[0]) / (second[0] - first[0])
                      * (second[1] - first[1]))
    check(first[0] < center_plane < second[0] and 0 < intersection_z < height,
          "Frozen path crosses constructed goal center plane")

    # 对冻结的第二段按门线交点分支的float32次序计算，不执行原生代码。
    def vector_sub(a, b):
        """逐分量执行单精度减法。"""
        return [f32(x - y) for x, y in zip(a, b)]

    def dot3(a, b):
        """模拟x乘积、y乘积相加，再加z乘积的顺序。"""
        return f32(f32(f32(a[0] * b[0]) + f32(a[1] * b[1]))
                   + f32(a[2] * b[2]))

    e0 = vector_sub(vertices[0], vertices[1])
    e1 = vector_sub(vertices[0], vertices[2])
    cross = [f32(f32(e0[1] * e1[2]) - f32(e0[2] * e1[1])),
             f32(f32(e0[2] * e1[0]) - f32(e0[0] * e1[2])),
             f32(f32(e0[0] * e1[1]) - f32(e0[1] * e1[0]))]
    epsilon = struct.unpack_from("<f", data, offset(0x145C40600))[0]
    check(epsilon == float_bits(0x348637BE), "Goal normal epsilon")
    length = f32(math.sqrt(f32(dot3(cross, cross) + epsilon)))
    normal = [f32(value / length) for value in cross]
    # 将求解器的受限35速输出接到已恢复的高速度阻力与首段门口几何。
    shot_speed = f32(34.999996185302734)
    high_coefficient = f32(0.24)
    step = f32(1 / 12)
    high_magnitude = f32(f32(f32(density * f32(area * 0.5))
                             * high_coefficient) * shot_speed)
    high_ay = f32(f32(high_magnitude * -shot_speed) / f32(0.43))
    high_y = f32(f32(51) + f32(f32(step * shot_speed)
                     + f32(f32(f32(step * step) * high_ay) * f32(0.5))))
    high_z = f32(f32(f32(1) + radius)
                 + f32(f32(f32(step * step) * gravity) * f32(0.5)))
    check(shot_speed > 21 and high_z > radius, "Shot first substep inputs")
    high_start = [f32(0), f32(51), f32(f32(1) + radius)]
    high_end = [f32(0), high_y, f32(high_z - radius)]
    high_ref = dot3(vertices[0], normal)
    high_a = f32(dot3(high_start, normal) - high_ref)
    high_b = f32(dot3(high_end, normal) - high_ref)
    check(high_a < 0 <= high_b, "Shot first segment crosses goal plane")
    high_fraction = f32(f32(-high_a) / f32(high_b - high_a))
    high_hit = [f32(high_start[i] + f32(high_fraction * f32(high_end[i] - high_start[i])))
                for i in range(3)]
    high_edge0 = vector_sub(vertices[1], vertices[0])
    high_edge1 = vector_sub(vertices[2], vertices[0])
    high_delta = vector_sub(high_hit, vertices[0])
    h00, h01, h11 = (dot3(high_edge0, high_edge0), dot3(high_edge0, high_edge1),
                     dot3(high_edge1, high_edge1))
    h20, h21 = dot3(high_edge0, high_delta), dot3(high_edge1, high_delta)
    hden = f32(f32(h00 * h11) - f32(h01 * h01))
    hw1 = f32(f32(f32(h11 * h20) - f32(h01 * h21)) / hden)
    hw2 = f32(f32(f32(h21 * h00) - f32(h20 * h01)) / hden)
    hw0 = f32(f32(f32(1) - hw1) - hw2)
    check(hw0 >= 0 and hw1 >= 0 and f32(hw0 + hw1) <= 1,
          "Shot first segment enters goal triangle")
    check([struct.pack("<f", value).hex() for value in high_hit]
          == ["00000000", "de715242", "0fc3833f"],
          "Shot first segment intersection bits")

    # 首条记录成功时，扫描偏移为0；前一记录被设为当前记录。
    current_fraction = f32(1 / 3)
    previous_fraction = current_fraction
    previous_point = [f32(0), high_y, high_z]
    current_point = [f32(0), high_y, high_z]
    zero_segment = vector_sub(current_point, previous_point)
    check(dot3(zero_segment, zero_segment) == 0,
          "First goal record uses zero interpolation segment")
    interpolation = f32(0)
    first_subtime = f32(f32(f32(current_fraction - previous_fraction)
                            * interpolation) + previous_fraction)
    first_time = f32(f32(110) + min(f32(0.95), first_subtime))
    check(struct.pack("<f", first_subtime).hex() == "abaaaa3e"
          and struct.pack("<f", first_time).hex() == "abaadc42",
          "First goal record fallback time")

    start = [f32(0), first[0], f32(first[1] - radius)]
    end = [f32(0), second[0], f32(second[1] - radius)]
    reference = dot3(vertices[0], normal)
    # 三条记录时，G+3*0x50-0x1c是最后记录位置的y分量。
    check(initialized_positions[2][0] > 0, "Positive goal side selected")
    first_start = [f32(0), f32(51), f32(f32(1) + radius)]
    first_end = [f32(0), first[0], f32(first[1] - radius)]
    first_a = f32(dot3(first_start, normal) - reference)
    first_b = f32(dot3(first_end, normal) - reference)
    check(first_a < 0 and first_b < 0, "First segment leaves crossing state clear")
    side_start = f32(dot3(start, normal) - reference)
    side_end = f32(dot3(end, normal) - reference)
    check(side_start < 0 <= side_end, "Goal forward-side crossing")
    fraction = f32(f32(-side_start) / f32(side_end - side_start))
    hit = [f32(start[i] + f32(fraction * f32(end[i] - start[i])))
           for i in range(3)]
    edge0 = vector_sub(vertices[1], vertices[0])
    edge1 = vector_sub(vertices[2], vertices[0])
    delta = vector_sub(hit, vertices[0])
    d00, d01, d11 = dot3(edge0, edge0), dot3(edge0, edge1), dot3(edge1, edge1)
    d20, d21 = dot3(edge0, delta), dot3(edge1, delta)
    denominator = f32(f32(d00 * d11) - f32(d01 * d01))
    weight1 = f32(f32(f32(d11 * d20) - f32(d01 * d21)) / denominator)
    weight2 = f32(f32(f32(d21 * d00) - f32(d20 * d01)) / denominator)
    weight0 = f32(f32(f32(1) - weight1) - weight2)
    check(weight0 >= 0 and weight1 >= 0 and f32(weight0 + weight1) <= 1,
          "Goal first triangle accepts frozen intersection")
    check([struct.pack("<f", value).hex() for value in hit]
          == ["00000000", "de715242", "52a6663f"], "Goal intersection bits")
    check(side_end > -1, "Goal crossing replaces initial side value")

    # 成功段时刻使用原始物理位置与已保存交点的投影和三维段长。
    raw_start = [f32(0), first[0], first[1]]
    raw_end = [f32(0), second[0], second[1]]
    distance = dot3(vector_sub(raw_end, hit), normal)
    segment = vector_sub(raw_end, raw_start)
    segment_length = f32(math.sqrt(dot3(segment, segment)))
    check(distance > 0 and segment_length > 0, "Crossing time interpolation branch")
    factor = f32(f32(1) - f32(distance / segment_length))
    previous_fraction, current_fraction = f32(1 / 3), f32(2 / 3)
    subtime = f32(f32(f32(current_fraction - previous_fraction) * factor)
                  + previous_fraction)
    check(struct.unpack_from("<f", data, offset(0x14565294C))[0] == f32(0.95),
          "Crossing time cap")
    subtime = min(f32(0.95), subtime)
    actual_time = f32(f32(110) + subtime)
    check(struct.pack("<f", subtime).hex() == "08340c3f"
          and struct.pack("<f", actual_time).hex() == "6818dd42"
          and int(actual_time) == 110, "Crossing time example")

    # 三次表读取为0，与轨迹组元数据180的最小环绕差均为180。
    angular_differences = [min(abs(180 - value), 360 - abs(180 - value))
                           for value in (0, 0, 0)]
    check(all(value >= 91 for value in angular_differences)
          and initialized_positions[2][0] > f32(f32(52.5) + radius),
          "Crossing continuation to candidate time under fixed table inputs")

    # 三次顺序追加仅触及G+10+n*50到G+54+n*50及G+0计数。
    for index in (0, 1, 2):
        check(0x54 + index * 0x50 < 0x334, "Record writes preserve metadata")

    # 新组+32e的8字节清零覆盖组+334的16位角度元数据。
    cleared_group = bytearray([0xff] * 0x336)
    cleared_group[0x32e:0x336] = bytes(8)
    check(struct.unpack_from("<h", cleared_group, 0x334)[0] == 0,
          "New trajectory group angle metadata")
    # 假设参考点(0,52.5)，最后物理位置向该点的量化位移。
    dx = int(f32(f32(0 - f32(0)) * f32(10)))
    dy = int(f32(f32(f32(52.5) - initialized_positions[2][0]) * f32(10)))
    check((dx, dy) == (0, -14), "Frozen direction-table index")

    # 正侧参考点限定为(0,52.5)时，重建三个方向表格点及角差。
    angle_constants = {
        0x145A1D408: 0x40EA3D71, 0x145A1D504: 0x41200000,
        0x1455A9880: 0x3DCCCCCD, 0x14584C5D4: 0x2EDBE6FF,
        0x145A1350C: 0xBE4902DE, 0x145A13510: 0x3F7B50B1,
        0x145A13514: 0x4016CBE4, 0x145870800: 0x3F490FDB,
    }
    for address, bits in angle_constants.items():
        check(struct.unpack_from("<I", data, offset(address))[0] == bits,
              f"Direction table constant {address:x}")
    goal_x = (f32(0), f32(-width), f32(f32(-width) + float_bits(0x40EA3D71)))
    grid = [(int(f32(x * f32(10))), dy) for x in goal_x]
    check(grid == [(0, -14), (-36, -14), (36, -14)], "Goal direction grid")

    def table_direction(x_index, y_index):
        """按初始化器和方向生成器重建所需的有限格点。"""
        x = f32(f32(x_index) * float_bits(0x3DCCCCCD))
        y = f32(f32(y_index) * float_bits(0x3DCCCCCD))
        if x == 0:
            return 180 if y < 0 else 0
        magnitude = f32(abs(x) + float_bits(0x2EDBE6FF))
        ratio = f32(f32(magnitude - abs(y)) / f32(magnitude + abs(y)))
        polynomial = f32(f32(f32(float_bits(0xBE4902DE) * ratio) * ratio)
                         + float_bits(0x3F7B50B1))
        polynomial = f32(polynomial * ratio)
        theta = f32(float_bits(0x4016CBE4) - polynomial) if y < 0 else f32(
            polynomial + float_bits(0x3F490FDB))
        if x < 0:
            theta = f32(-theta)
        degrees = f32(f32(theta * f32(180)) / f32(math.pi))
        rounded = math.floor(f32(degrees + f32(0.5))) if degrees >= 0 else math.ceil(
            f32(degrees - f32(0.5)))
        return rounded % 360

    # 相同35速在限定无接触下推进三步；方向表消费末条而非交点。
    hy, hz, hvy, hvz = f32(51), f32(f32(1) + radius), shot_speed, f32(0)
    high_records = []
    for _ in range(3):
        hs = f32(math.sqrt(f32(f32(hvy * hvy) + f32(hvz * hvz))))
        check(hs > 21, "Shot high-speed drag branch")
        hm = f32(f32(f32(density * f32(area * 0.5)) * f32(0.24)) * hs)
        hay = f32(f32(f32(hm * -hvy) / f32(0.43)) + f32(0))
        haz = f32(f32(f32(hm * -hvz) / f32(0.43)) + gravity)
        h2 = f32(step * step)
        hy = f32(hy + f32(f32(step * hvy) + f32(f32(h2 * hay) * f32(0.5))))
        hz = f32(hz + f32(f32(step * hvz) + f32(f32(h2 * haz) * f32(0.5))))
        hvy = f32(hvy + f32(step * hay))
        hvz = f32(hvz + f32(step * haz))
        high_records.append((hy, hz))
    check([(struct.pack("<f", yy).hex(), struct.pack("<f", zz).hex())
           for yy, zz in high_records]
          == [("d3705742", "c7e0893f"), ("58726242", "7af2793f"),
              ("cc0c6d42", "76a74f3f")], "Shot high-speed trajectory records")
    check(all(zz > radius for _, zz in high_records), "Shot records above ground")
    # 同一三步末速度进入已恢复的二维门线预筛选。
    prefilter_sy = f32(abs(f32(f32(0.25) * hvy)))
    prefilter_lo = f32(f32(6) - f32(52.5))
    prefilter_hi = f32(f32(52.5) - f32(6))
    y_ends = (f32(f32(51) - prefilter_sy), f32(f32(51) + prefilter_sy))
    check(not all(prefilter_lo <= y <= prefilter_hi for y in y_ends),
          "Shot prefilter leaves central longitudinal zone")
    check(-12 <= f32(0) <= 12, "Shot prefilter lateral endpoint")
    check(0xCF30 == 255 * 0xD0, "Candidate context initial capacity")
    check((0x810 & 0x04C0) == 0 and ((0x810 >> 8) & 1) == 0,
          "Prepared player flag selects direction calculation")
    check((0x700 & 0xFDFF00FF) == 0 and (0x500 & 0xFDFF00FF) == 0,
          "Shot preparation can clear earlier match flag examples")
    check(((0x500 >> 8) & 3) == 1 and ((0x700 >> 8) & 3) == 3,
          "Prior match flag examples conflict with prefilter gate")
    high_dy = int(f32(f32(f32(52.5) - high_records[-1][0]) * f32(10)))
    high_grid = [(int(f32(x * f32(10))), high_dy) for x in goal_x]
    check(high_grid == [(0, -67), (-36, -67), (36, -67)], "Shot direction grid")
    high_angles = [table_direction(x, y) for x, y in high_grid]
    check(high_angles == [180, 208, 152], "Shot direction angles")
    high_differences = [min(a, 360 - a) for a in high_angles]
    check(high_differences == [180, 152, 152], "Shot zero-metadata angle gates")

    for address, value in ((0x145A1D4DC, 3.0), (0x145A1D570, 100.0)):
        check(struct.unpack_from("<f", data, offset(address))[0] == value,
              f"Shot target range constant {address:x}")

    # 中路目标：两侧参考角相同，冻结 PRNG 状态使对称整数区间选到0。
    side_angles = (table_direction(36, 15), table_direction(-36, 15))
    check(side_angles == (67, 293), "Shot target side direction angles")
    side_differences = [min(a, 360 - a) for a in side_angles]
    check(side_differences == [67, 67], "Shot target symmetric angles")
    check(abs(side_differences[0] - side_differences[1])
          < max(side_differences) // 2, "Shot target symmetric random branch")
    half_width = f32(float_bits(0x406A3D71)
                     - f32(float_bits(0x3DE3BCD3) * f32(3.0)))
    bound = int(f32(half_width * f32(100)))
    check(bound == 332, "Shot target quantized half width")
    state = 0xE9803E5CF5592829
    output = ((state >> 45) ^ (state >> 27)) & 0xFFFFFFFF
    rotation = state >> 59
    output = ((output >> rotation) | (output << ((-rotation) & 31))) & 0xFFFFFFFF
    check(output == 0x80043CF9 and ((2 * bound * output) >> 32) - bound == 0,
          "Shot target center from frozen PRNG state")

    angles = [table_direction(x, y) for x, y in grid]
    differences = [min(abs(value), 360 - abs(value)) for value in angles]
    check(angles == [180, 249, 111] and differences == [180, 111, 111],
          "Constructed direction values and zero-metadata angle differences")
    check(differences[2] >= 91 and differences[0] >= 91 and differences[1] > 90,
          "Zero-metadata branch reaches candidate time")

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

    check(struct.unpack_from("<Q", data, offset(0x145A1A048 + 0x38))[0]
          == 0x141B62DC0, "MATCH_PLAYER context speed getter slot")
    for address, expected in ((0x145A1D4FC, 8.0), (0x145A4E8C0, 2000.0),
                              (0x145A1D488, 0.75)):
        check(struct.unpack_from("<f", data, offset(address))[0] == expected,
              f"Context speed/boolean constant {address:x}")
    # 可手算局部语义；不把Python例子称为执行原生函数。
    db4, db1, match_e3bb, tick = 0, 0, 0, 110
    for timestamp, expected in ((110, 1), (111, 0)):
        cleared = (db4 == 0 and db1 == 0 and match_e3bb == 0 and timestamp > tick)
        check((0 if cleared else 1) == expected, "C610 signed timestamp worked example")
    speed_adjustment = f32(min(1.0, f32(f32(1000.0) / f32(2000.0))))
    speed = f32(f32(f32(f32(40.0) / f32(20.0)) + f32(5.0))
                - speed_adjustment)
    speed = max(3.0, f32(speed + f32(0.25)))
    check(speed == 6.75, "Uncached speed with bound virtual getter worked example")

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

    # 复用既有公共属性分类器证据，避免复制四份表或仅抽核几个编号。
    common = json.loads((ROOT / "20261020_finalize_helper_preservation_observations.json").read_text())
    classifiers = (0x14274E900, 0x14274ED20, 0x14274F140, 0x1443CB7B0)
    for row in common["native_assertions"]:
        address = int(row["va"], 16)
        if (0x1419C9CE0 <= address < 0x1419C9CFF
                or any(start <= address < start + 0x1E for start in classifiers)):
            expected = bytes.fromhex(row["hex"])
            check(data[offset(address):offset(address) + len(expected)] == expected,
                  f"Shared attribute classifier code {address:x}")
    for row in common["data_assertions"]:
        if "complete 256-entry signed-relative classifier table" not in row.get("label", ""):
            continue
        address, expected = int(row["va"], 16), bytes.fromhex(row["hex"])
        check(data[offset(address):offset(address) + len(expected)] == expected,
              f"Shared complete attribute classifier table {address:x}")
        check(len(expected) == 1024, "Shared attribute classifier table length")
        targets = {address + value for value in struct.unpack("<256i", expected)}
        check(targets <= {address - 5, address - 3},
              f"Shared attribute classifier boolean-only targets {address:x}")

    for address in (0x1443BCFB4, 0x1443BD827, 0x1443BD899,
                    0x1443BD905, 0x1443BD98C, 0x1443BDA00,
                    0x1443BDF38, 0x1443BE289, 0x1443BE3B6):
        check(instructions.get(address) == "mov QWORD PTR [rsp+0x40],0x0",
              f"Cache query optional write pointer {address:x}")
    check(instructions.get(0x141B430A2) == "cmp rbx,0xa"
          and instructions.get(0x141B43202) == "cmp rbx,0xa",
          "Cache query append count limit")
    for address, expected in {
        0x1443B91A2: "jne 0x1443b9254",
        0x1443B988A: "mov WORD PTR [r14+0x1485],0x101",
        0x1443B9ABB: "mov WORD PTR [r14+0x1485],0x100",
        0x1443BB224: "mov BYTE PTR [r14+0x1486],0x1",
        0x144448FD1: "mov BYTE PTR [rax],0x0",
        0x144448FD4: "mov BYTE PTR [r8],0x0",
        0x1444490DA: "setg BYTE PTR [r15]",
        0x1444491AE: "mov BYTE PTR [rbp+0x0],al",
        0x14444930A: "mov BYTE PTR [rax],0x1",
        0x14441B076: "mov BYTE PTR [r13+0x610],0x0",
        0x14441B074: "jle 0x14441b07e",
        0x14441BD4C: "mov QWORD PTR [rsp+0x40],0x0",
        0x1443F9269: "call QWORD PTR [rax+0x38]",
        0x1443F92EA: "sete BYTE PTR [rdi+0x24f]",
        0x141B62DD3: "jne 0x141b62ddd",
        0x141B62DDD: "mov eax,DWORD PTR [rdi+0x1c0]",
        0x141B47ABF: "jbe 0x141b47ad9",
        0x141B42A6F: "cmp rbx,0xa",
        0x141B42AFF: "cmp bl,0x20",
        0x144408CDB: "jbe 0x144408d10",
        0x144408D19: "cmp DWORD PTR [rdi+0xe8],0xffffffff",
        0x144408D20: "jne 0x144408d3c",
        0x144408D22: "cmp DWORD PTR [rdi+0x94],ebx",
        0x144408D28: "jge 0x144408d3c",
        0x14441A50B: "movaps XMMWORD PTR [r13+0x540],xmm0",
        0x14441A73E: "movss DWORD PTR [r13+0x5c4],xmm0",
        0x14441AF4C: "jbe 0x14441af6a",
        0x14441AF5E: "mov DWORD PTR [r13+0x5d4],eax",
        0x14441D799: "test DWORD PTR [r14+0x11a8],0x10001",
        0x14441D7A4: "je 0x14441d80a",
        0x1443C41B0: "jne 0x1443c41ba",
        0x1443C420B: "cmp QWORD PTR [r15+0x1d0],rcx",
        0x1443C4218: "cmp r15,QWORD PTR [rax+0xe388]",
        0x1443C42F8: "jne 0x1443c4599",
        0x1443C45DB: "jne 0x1443c46ca",
        0x1443C46D4: "je 0x1443c4713",
        0x1443C4599: "mov DWORD PTR [r12+0x11a8],esi",
        0x1443C471A: "mov QWORD PTR [rax+0xe388],r12",
        0x1443C181F: "mov DWORD PTR [rsp+0x5c],esi",
        0x1443BDC27: "xor r9d,r9d",
        0x1443BE125: "xor r9d,r9d",
        0x1443BE163: "xor r9d,r9d",
        0x1443BE209: "xor r9d,r9d",
        0x1443BE421: "xor r9d,r9d",
        0x1443C564D: "jbe 0x1443c5689",
        0x1443C57EA: "jbe 0x1443c5860",
        0x1443B6228: "je 0x1443b624f",
        0x1443B6500: "je 0x1443b652f",
        0x1443B63D0: "jne 0x1443b6698",
        0x1443B600C: "lea rcx,[rsi+0x11b8]",
        0x1443E97F7: "mov BYTE PTR [rax+0x85],0x1",
        0x1443E991E: "mov DWORD PTR [rdi+0xd62],0x10001",
        0x1443E992E: "mov DWORD PTR [rdi+0xd2c],ecx",
        0x1443C39DB: "je 0x1443c3a45",
        0x1443ECBD6: "je 0x1443ecbe8",
        0x1443C3A7A: "je 0x1443c3b9b",
        0x1443C3C05: "je 0x1443c3d69",
        0x1443C3D85: "je 0x1443c3ec8",
        0x1443C4095: "jg 0x1443c418e",
        0x1443B51F4: "jle 0x1443b529c",
        0x1443B52A7: "movss DWORD PTR [rsi+0x11b8],xmm0",
        0x1443B52B5: "mov DWORD PTR [rsi+0x11c0],ecx",
        0x1443B52C6: "movss DWORD PTR [rsi+0x11bc],xmm0",
        0x1443B52CE: "jmp 0x1443b60c2",
        0x141B46841: "je 0x141b46998",
        0x141B4699F: "je 0x141b46a82",
        0x141B46A82: "xor eax,eax",
        0x1443EF9CC: "movd xmm6,r8d",
        0x1443EF9D1: "cvttss2si edi,xmm6",
        0x1443EF9D5: "lea r15d,[rdi+0x7]",
        0x1443EF9D9: "mov r12d,0x1876",
        0x1443EFB0B: "ucomiss xmm1,xmm6",
        0x1443EFB0E: "jbe 0x1443efae0",
        0x1443EFB9E: "mov r15d,0x1876",
        0x1443EFCC7: "ucomiss xmm6,xmm1",
        0x1443EFCCA: "jbe 0x1443efca0",
    }.items():
        check(instructions.get(address) == expected,
              f"Position-cache query branch or input {address:x}")
    start = offset(0x14557E730)
    check(data[start:start + 2] == b"\xff\x25"
          and 0x14557E736 + struct.unpack_from("<i", data, start + 2)[0] == 0x145D50B18,
          "Cache short sort uses the recorded memmove import")

    attribute_context_calls = {}
    for address, instruction in instructions.items():
        if not (0x144448FB0 <= address < 0x14444931E
                or 0x1443B9140 <= address < 0x1443BB231
                or 0x1443B3FC0 <= address < 0x1443B48F8):
            continue
        match = re.fullmatch(r"call 0x([0-9a-f]+)", instruction)
        if match:
            attribute_context_calls[address] = int(match[1], 16)
    calls = {
        0x14441B039: 0x141B47A60,
        0x14441BA1A: 0x141B408E0,
        0x14441BB75: 0x14557E9B0,
        0x14441BB84: 0x14557EA20,
        0x14441BD76: 0x141B42F50,
        0x14441BD9B: 0x1443F9200,
        0x14441BE35: 0x144448FB0,
        0x141B62DD8: 0x1443BC460,
        0x14441A78D: 0x144408CC0,
        0x14441AF2C: 0x141B46830,
        0x14441A661: 0x141B42780,
        0x14441A68B: 0x141B42780,
        0x14441A6BC: 0x141B42780,
        0x141B42791: 0x1454E8D80,
        0x141B42D8D: 0x1454E8D80,
        0x141B42904: 0x144408CC0,
        0x141B42B4C: 0x14557E730,
        0x144408D37: 0x144407A40,
        0x144417994: 0x1443BC460,
        0x14441799F: 0x14441A3B0,
        0x1443BDC2A: 0x1443C54B0,
        0x1443BE128: 0x1443C54B0,
        0x1443BE166: 0x1443C54B0,
        0x1443BE20C: 0x1443C54B0,
        0x1443BE424: 0x1443C54B0,
        0x1443C57E1: 0x141B40BD0,
        0x1443BD52B: 0x14557E9B0,
        0x1443BD566: 0x14557EA20,
        0x1443B532A: 0x141B41670,
        0x1443B535A: 0x141B41670,
        0x1443B5BBB: 0x141B41670,
        0x1443B5C77: 0x141B40BD0,
        0x1443B5378: 0x1443B61F0,
        0x1443B603B: 0x1443B6160,
        0x1443B6241: 0x1443EA8F0,
        0x1443B6521: 0x1443EA8F0,
        0x1443B6361: 0x1443ECA50,
        0x1443B6398: 0x1443EE610,
        0x1443ECC33: 0x1443EA8F0,
        0x1443C3A5A: 0x1443E9420,
        0x1443EFBF8: 0x1443EA8F0,
        0x141B46BCC: 0x141B41670,
        0x141B46C95: 0x141B41670,
        0x141B4AA39: 0x141B46830,
        0x141B4AA6A: 0x141B46830,
        0x141B4AB12: 0x1443B4F80,
        0x1443B4FC6: 0x1443B5100,
        0x1443B5239: 0x1443EFB60,
        0x1443B525F: 0x1443EF9B0,
        0x1443EFA32: 0x1443EA8F0,
        0x141B43020: 0x141B40BD0,
        0x141B43180: 0x141B40BD0,
        0x141B4329C: 0x141B42D80,
        0x141B42DEC: 0x14557E730,
        0x1443BCFDD: 0x141B42F50,
        0x1443BD854: 0x141B42F50,
        0x1443BD8BE: 0x141B42F50,
        0x1443BD92A: 0x141B42F50,
        0x1443BD9B8: 0x141B42F50,
        0x1443BDA34: 0x141B42F50,
        0x1443BDF62: 0x141B42F50,
        0x1443BE2B3: 0x141B42F50,
        0x1443BE3E0: 0x141B42F50,
        0x141B40C9E: 0x141B465F0,
        0x1443BD38B: 0x1443EE610,
        0x1443EE6B0: 0x1443EA8F0,
        0x1443BE252: 0x1443F7D90,
        0x1443BE37F: 0x1443F7D90,
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
        0x141AC7AB4: 0x141B6A7F0,
        0x151CD1605: 0x144566220,
        0x151AECCD9: 0x141B6AEF0,
        0x151AECCD1: 0x141B6ADA0,
        0x1443AFE19: 0x1443B3FC0,
        0x159EADF2A: 0x14438DB90,
        0x141ACFF02: 0x141B6C1C0,
        0x141B6B384: 0x141B6B810,
        0x141B6BAE8: 0x144569870,
        0x141B6BB16: 0x144569870,
        0x1453008F1: 0x144580C50,
        0x144580CB4: 0x145305640,
        0x1434F42C0: 0x141A92E20,
        0x141B6B1ED: 0x144566220,
        0x151AECD13: 0x1443E8310,
        0x144566287: 0x14557EA00,
        0x1443EE057: 0x145300B10,
        0x1453023FC: 0x1445671F0,
        0x145302240: 0x144568E00,
        0x145302258: 0x144568E00,
        0x145302274: 0x144568E00,
        0x145302289: 0x144568E00,
        0x1445672FD: 0x14530BD90,
        0x14530BE7C: 0x14530BEB0,
        0x14530208E: 0x145305970,
        0x14530209B: 0x1453056E0,
        0x1443E86CE: 0x1453009F0,
        0x1443E86E1: 0x145302F10,
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
        0x141B42C8E: 0x141B42D80,
        0x1443B6160: 0x159F102E0,
        0x1418FDF30: 0x150DF5F90,
        0x145305640: 0x15C605DC0,
        0x141A92E20: 0x151AECCB0,
        0x141B6ADA0: 0x151CD8810,
        0x141B6A7F0: 0x151CD1180,
        0x1453899F0: 0x15C6B2AA0,
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
    calls.update(attribute_context_calls)
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
