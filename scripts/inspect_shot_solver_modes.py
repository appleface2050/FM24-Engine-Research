"""从原PE复核同一3f输入到三种首次试算的模式分区，不执行数值试算器。"""

import argparse
import json
import math
import re
import struct
from pathlib import Path

from inspect_preparation_reference_paths import decode_graph, walk
from inspect_shot_selector_paths import normalize, stores
from verify_goal_lifecycle import verify_target_identity

ROOT = Path(__file__).resolve().parents[1]
FIRST = {0x1443F448E: 0x145304F90, 0x1443F4516: 0x145304400, 0x1443F45A3: 0x145303160}


def inspect_trial_bodies(exe, data, offset):
    """记录实际数值体与局部循环条件；不把被调正常返回当成已证实事实。"""
    ranges = {0x1418F81A0: 0x1418F83F5, 0x145303160: 0x1453038F4,
              0x145303900: 0x145303E5B, 0x145303E60: 0x1453043FF,
              0x145304400: 0x1453049C4, 0x1453049D0: 0x145304F89,
              0x145304F90: 0x1453054FE}
    expected = {
        0x1418F81A0: set(),
        0x145303160: {0x1453033EA, 0x1453034A3, 0x14530355A, 0x1453035DF,
                      0x1453037AF, 0x145303805, 0x145303828, 0x145303839,
                      0x14530385C, 0x14530386D, 0x145303890},
        0x145303900: {0x145303D55}, 0x145303E60: {0x145303FCB, 0x145303FD8},
        0x145304400: {0x145304639, 0x1453046C8, 0x145304744, 0x1453048F7,
                      0x14530491A, 0x14530492B, 0x14530494E},
        0x1453049D0: {0x145304B47, 0x145304B54},
        0x145304F90: {0x14530523C, 0x145305296, 0x1453052F2},
    }
    functions, decoded = [], {}
    for entry, end in ranges.items():
        rows, graph = decode_graph(exe, entry, end)
        reached = walk([entry], graph)
        calls = {a: normalize(rows[a][1]) for a in sorted(reached) if rows[a][1].startswith('call')}
        if set(calls) != expected[entry]:
            raise ValueError(f'Another trial-body callee at {entry:#x}')
        decoded[entry] = (rows, graph)
        functions.append({'entry': hex(entry), 'end': hex(end),
                          'calls': {hex(a): ins for a, ins in calls.items()},
                          'explicit_nonstack_stores': stores(rows, reached),
                          'scope': 'complete original code graph and write inventory; callee semantics/termination not automatically proved'})
    loop_checks = []
    for entry, initial, repeat, decrement, header, gates, budget in (
        (0x145304400, 0x145304639, 0x1453046C8, 0x1453046D7, 0x1453046D9,
         {0x1453046F1, 0x1453047FB}, 0x145304650),
        (0x145303160, 0x1453034A3, 0x14530355A, 0x14530356C, 0x14530356F,
         {0x145303588, 0x1453036AE}, 0x1453034C6),
    ):
        rows, graph = decoded[entry]
        if repeat in walk([header], graph, gates):
            raise ValueError('A repeated residual evaluation bypasses both budget gates')
        if header in walk([repeat + 5], graph, {decrement}):
            raise ValueError('Residual re-evaluation bypasses budget decrement')
        returns = {a for a, row in rows.items() if row[1].startswith('ret')}
        if returns & walk([entry], graph, {initial}):
            raise ValueError('Trial body can return before initial residual evaluation')
        if header in walk([entry], graph, {budget}):
            raise ValueError('Correction loop bypasses budget initialization')
        loop_checks.append({'entry': hex(entry), 'initial_residual': hex(initial), 'repeat': hex(repeat),
                            'budget_initialization': hex(budget), 'decrement': hex(decrement),
                            'required_gate_union': [hex(a) for a in sorted(gates)],
                            'conditional_bound': 'one initial residual plus at most four corrections, only if each residual/helper returns normally'})
    for entry, instructions in {
        0x145304400: {0x145304650: 'mov ebp,0x4', 0x1453046D7: 'dec ebp'},
        0x145303160: {0x1453034C6: 'mov r13d,0x4', 0x14530356C: 'dec r13d'},
        0x1453049D0: {0x145304C29: 'cmp BYTE PTR [rax+0xd0],0x1',
                      0x145304C30: 'sbb ebx,0xffffffff', 0x145304C36: 'cmp ebx,0x168'},
        0x145303E60: {0x145303F97: 'cmp BYTE PTR [rax+0xd0],0x1',
                      0x145303F9E: 'sbb ebx,0xffffffff', 0x145303FA8: 'cmp ebx,0x168'},
    }.items():
        rows, _ = decoded[entry]
        for site, expected_ins in instructions.items():
            if normalize(rows[site][1]) != expected_ins:
                raise ValueError('Actual correction/integration counter semantics differs')
    matrix_rows, matrix_graph = decoded[0x1418F81A0]
    matrix_writes = stores(matrix_rows, walk([0x1418F81A0], matrix_graph))
    if normalize(matrix_rows[0x1418F81CB][1]) != 'mov rax,rcx' or len(matrix_writes) != 9:
        raise ValueError('Rotation-matrix output binding differs')
    if any('[rax' not in row['instruction'].split(',', 1)[0] for row in matrix_writes):
        raise ValueError('Rotation matrix has another write domain')
    coefficient = list(struct.unpack_from('<4f', data, offset(0x145D2F2E0)))
    negative_half = struct.unpack_from('<f', data, offset(0x145684C38))[0]
    if coefficient != [.5, .5, .5, 0.] or negative_half != -.5:
        raise ValueError('Trial integration/seed coefficients differ')

    def f(value):
        return struct.unpack('<f', struct.pack('<f', value))[0]

    # 手工可检查的局部输入例；g由例子给定，不冒充自然全局初始化结果。
    tau = f(f(2.) / f(20.))
    lift = f(f(f(f(-9.8) * tau) * tau) * negative_half)
    aim_z = f(f(1.) + lift)
    delta_z = f(aim_z - f(1.))
    length = f(math.sqrt(f(f(2. * 2.) + f(delta_z * delta_z))))
    velocity = [0., f(f(2. / length) * f(20.)), f(f(delta_z / length) * f(20.))]
    return {'evidence_type': 'native_body_inventory_and_local_formula_not_complete_trial_simulation',
            'functions': functions, 'correction_loop_checks': loop_checks,
            'shared_scratch': {'position': 'Q+1a0b0', 'velocity': 'Q+1a0c0', 'spin': 'Q+1a0d0',
                               'mass_divisor': 'Q+1a0ec', 'z_stop': 'Q+1a0e8',
                               'environment_ref': '[Q+1a110]', 'Q': 'actual solver argument B+1040; identity with [B+1038] not inferred'},
            'integration_coefficients': coefficient,
            'integration_counter': {'step': 'c_next=c+1-CF, CF=(unsigned byte E+d0<1)',
                                    'if_byte_zero': 'counter does not advance; force/integration updates are still executed, actual motion depends on inputs',
                                    'if_stably_nonzero': 'at most360 integration steps, assuming force helpers return normally',
                                    'unproved': 'E constructor writes2 and copy binds source reference; retention to current shot or independent physical termination when zero remains unproved'},
            'mode2_seed_example': {'origin': [0., 0., 1.], 'target': [0., 2., 1.], 'scale': 20.,
                                   'assumed_gravity_scalar': f(-9.8), 'tau': tau,
                                   'negative_half_constant': negative_half, 'compensated_target_z': aim_z,
                                   'initial_velocity_after_compensation': velocity,
                                   'scope': 'float32 transcription of initial seed only; not native execution, final velocity or a goal'},
            'remaining': ['scratch copy checkpoint retention to current shot; complete residual output/force semantics',
                          'TLS initialization, helper normal return and numerical validity in same natural state',
                          'trial termination/output, perturbation, same new flight, defense/rules and goal']}


def inspect_scratch_producer(exe):
    """复核新建轨迹的限定复制路径；不假定初始化值保持到当前射门。"""
    rows, full = decode_graph(exe, 0x145302F10, 0x145303154,
                              external_stops={0x141B6C7E0})
    # 人工由原指令推导的条件：独立Q/T，空向量，旧引用为空，源E非空。
    choices = {0x145302F29: 0x145302F2F, 0x145302F51: 0x145302F78,
               0x145302F8C: 0x145302FBB, 0x145302FDC: 0x145302FDE,
               0x145302FE1: 0x145302FE8, 0x145302FEF: 0x145302FF1,
               0x145303104: 0x145303106, 0x145303113: 0x145303115,
               0x145303118: 0x14530311F}
    graph = dict(full)
    for site, target in choices.items():
        if target not in full[site]:
            raise ValueError('Fresh scratch condition does not select a native edge')
        graph[site] = [target]
    reached = walk([0x145302F10], graph)
    calls = {a: normalize(rows[a][1]) for a in reached if rows[a][1].startswith('call')}
    if calls != {0x145302FC8: 'call 0x14557e730', 0x145303060: 'call 0x14557e720'}:
        raise ValueError('Fresh scratch copy retains allocation/release or another call')
    if {a for a in reached if rows[a][1].startswith('ret')} != {0x145303136}:
        raise ValueError('Fresh scratch copy has another return')
    required = {0x145302FF4: 'lea r15,[r14+0x20]',
                0x1453030BB: 'movaps XMMWORD PTR [rsi+0x1a100],xmm0',
                0x1453030C7: 'movaps XMMWORD PTR [rsi+0x1a0f0],xmm0',
                0x1453030E1: 'movaps XMMWORD PTR [rsi+0x1a0e0],xmm3',
                0x1453030E8: 'movaps XMMWORD PTR [rsi+0x1a0d0],xmm2',
                0x1453030EF: 'movaps XMMWORD PTR [rsi+0x1a0c0],xmm1',
                0x1453030F6: 'movaps XMMWORD PTR [rsi+0x1a0b0],xmm0',
                0x14530311F: 'mov QWORD PTR [rsi+0x1a110],rdi'}
    for site, ins in required.items():
        if normalize(rows[site][1]) != ins or 0x145303136 in walk([0x145302F10], graph, {site}):
            raise ValueError('A scratch source/output can bypass the selected producer')
    for site, ins in {0x145302F20: 'mov r14,rdx', 0x145302F23: 'mov rsi,rcx',
                      0x145303044: 'xor ebx,ebx', 0x14530305A: 'mov r8d,0x320',
                      0x14530308B: 'add rbx,0x340', 0x145303092: 'cmp rbx,0x1a000',
                      0x1453030FD: 'mov rdi,QWORD PTR [r14+0x18]'}.items():
        if normalize(rows[site][1]) != ins:
            raise ValueError('Copy bases, record loop or environment source differs')
    # 从已导出的原PE指令绑定调用点与参数初始化；逐字节另由主验证器复核。
    raw = (ROOT / '20261031_goal_trial_scratch_parameter_source_static.txt').read_text()
    exported = {}
    for line in raw.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*(?:[0-9a-f]{2} )*[0-9a-f]{2}\s+(.+)$', line)
        if match:
            exported[int(match[1], 16)] = normalize(match[2])
    binding = {0x1443E86D3: 'lea rcx,[r15+0x1040]',
               0x1443E86DA: 'mov rdx,QWORD PTR [r15+0x1038]',
               0x1443E86E1: 'call 0x145302f10',
               0x145300A53: 'mov DWORD PTR [rdi+0x58],ebp',
               0x145300A56: 'mov DWORD PTR [rdi+0x5c],eax',
               0x145300A1C: 'mov QWORD PTR [rdi+0x18],rbx',
               0x1443E7C70: 'mov QWORD PTR [rsi+0x1b150],0x0'}
    for site, ins in binding.items():
        if exported.get(site) != ins:
            raise ValueError('Exported scratch source binding differs')
    zero_bytes = set()
    for site, relative in zip(range(0x1443E78EF, 0x1443E793C, 11), range(0x1034, 0x106c, 8)):
        if exported.get(site) != f'mov QWORD PTR [rsi+{relative:#x}],0x0':
            raise ValueError('Constructor header-zero store differs')
        zero_bytes.update(range(relative, relative + 8))
    if not set(range(0x1040, 0x1060)) <= zero_bytes:
        raise ValueError('Overlapping constructor stores do not clear Q header/environment')
    # 固定长度循环的整数算例，而非执行原生memcpy。
    offsets = list(range(0, 0x1a000, 0x340))
    assert len(offsets) == 128 and offsets[-1] + 0x340 == 0x1a000
    return {'evidence_type': 'manual_source_binding_and_original_CFG_cuts_not_execution',
            'entry': '0x145302f10', 'actual_call': '0x1443e86e1',
            'arguments': {'destination_Q': 'B+1040', 'source_T': '[B+1038]',
                          'source_environment': '[[M+ce68]+2a0] via T+18'},
            'conditions': ['Q and T are valid independent aligned objects; both vector headers zero',
                           'Q+18 and Q+1a110 zero; T+18=valid nonnull E',
                           'valid record storage, ordinary CRT zero-length memmove and memcpy contracts',
                           'constructor zero stores retained to this copy; no claim of retention to current shot'],
            'selected_edges': {hex(a): hex(t) for a, t in choices.items()},
            'calls': {hex(a): ins for a, ins in sorted(calls.items())},
            'mandatory_source_and_output_sites': {hex(a): ins for a, ins in required.items()},
            'source_to_scratch': {'T+20': 'Q+1a0b0 position', 'T+30': 'Q+1a0c0 velocity',
                                  'T+40': 'Q+1a0d0 spin', 'T+58': 'Q+1a0e8 radius/Z-stop',
                                  'T+5c': 'Q+1a0ec mass divisor', 'T+60': 'Q+1a0f0 coefficient block',
                                  'T+70': 'Q+1a100 coefficient block', 'T+18': 'Q+1a110 environment reference'},
            'source_binding_sites': {hex(a): ins for a, ins in binding.items()},
            'record_count_example': {'first_offset': offsets[0], 'last_offset': offsets[-1],
                                     'stride': 0x340, 'count': len(offsets)},
            'unproved': ['copy checkpoint and E+d0 value retention to the same actual trial',
                         'other copy branches with old references/resize; complete numerical trial outputs']}


def inspect_residual_preservation(exe):
    """复核单次误差积分内部的参数保持与条件终止，不证明自然入口。"""
    def acyclic(graph, start, original_reached=None):
        reached = walk([start], graph) if original_reached is None else original_reached
        incoming = {a: 0 for a in reached}
        for a in reached:
            for b in graph[a]:
                incoming[b] += 1
        ready = [a for a in reached if incoming[a] == 0]
        count = 0
        while ready:
            a = ready.pop()
            count += 1
            for b in graph[a]:
                incoming[b] -= 1
                if incoming[b] == 0:
                    ready.append(b)
        return count == len(reached)

    helpers = []
    for entry, end, fixed, expected in (
        (0x145305970, 0x145305A48, {}, {0x145305A3B}),
        (0x1453056E0, 0x145305969,
         {0x1453057E4: 0x1453057EA, 0x145305813: 0x145305819}, {0x1453058E0}),
    ):
        rows, graph = decode_graph(exe, entry, end)
        graph = dict(graph)
        for site, target in fixed.items():
            if target not in graph[site]:
                raise ValueError('Prepared force TLS edge differs')
            graph[site] = [target]
        reached = walk([entry], graph)
        writes = stores(rows, reached)
        if any(rows[a][1].startswith('call') for a in reached) or not acyclic(graph, entry):
            raise ValueError('Prepared force helper has another call/cycle')
        if {int(w['site'], 16) for w in writes} != expected:
            raise ValueError('Prepared force helper writes beyond accumulator')
        helpers.append({'entry': hex(entry), 'prepared_TLS_edges': {hex(a): hex(b) for a, b in fixed.items()},
                        'calls': [], 'acyclic': True, 'writes': writes})
    residuals = []
    for entry, end, counter in ((0x1453049D0, 0x145304F89, 0x145304C30),
                                (0x145303E60, 0x1453043FF, 0x145303F9E)):
        rows, graph = decode_graph(exe, entry, end)
        reached = walk([entry], graph)
        writes = stores(rows, reached)
        for row in writes:
            dest = row['instruction'].split(',', 1)[0]
            if not re.search(r'\[(?:rsi\+0x1a0(?:b0|b8|c0|c8|d0|d8)|r14(?:\+0x4)?)\]$', dest):
                raise ValueError('Residual writes outside three scratch vectors/error output')
        cut = dict(graph)
        cut[counter] = []
        if not acyclic(cut, entry, reached):
            raise ValueError('Residual contains a cycle bypassing the integration counter')
        residuals.append({'entry': hex(entry), 'writes': writes,
                          'cycle_cut': hex(counter), 'acyclic_after_counter_cut': True})
    return {'evidence_type': 'manual_argument_alias_binding_plus_original_CFG_write_and_cycle_checks',
            'helpers': helpers, 'residuals': residuals,
            'conditions': ['valid independent Q/E, error outputs and stack force buffers; no external concurrent writes',
                           'spin force two TLS guards already satisfied; valid TLS/read storage and ordinary nontrapping FP execution',
                           'E=[Q+1a110] has nonzero byte+d0 at residual entry'],
            'conclusion': 'within one residual, Q radius/mass/environment reference and E+d0 are preserved; force bodies return; at most360 integrations then finite local suffix',
            'unproved': ['same natural entry and prepared TLS, residual numerical accuracy/final trial output',
                         'other force cold-initialization paths and mode0/1 full physics loop']}


def inspect_mode2_sampling(exe):
    """恢复有限输入下的采样/高度误差，保留原比例而非标准线段交点。"""
    rows, graph = decode_graph(exe, 0x1453049D0, 0x145304F89)
    expected = {
        0x145304A2F: 'mov r15,r9', 0x145304A32: 'mov r12,r8',
        0x145304B08: 'movaps xmm6,XMMWORD PTR [rsi+0x1a0b0]',
        0x145304B69: 'movaps xmm0,xmm7',
        0x145304B6C: 'shufps xmm0,xmm6,0x23',
        0x145304B70: 'movaps xmm7,xmm6',
        0x145304B73: 'shufps xmm7,xmm0,0x24',
        0x145304C33: 'movaps xmm6,xmm0',
        0x145304BF3: 'movaps xmm1,XMMWORD PTR [r12]',
        0x145304BFB: 'subps xmm3,xmm1',
        0x145304C0C: 'jae 0x145304c48', 0x145304C20: 'ja 0x145304c80',
        0x145304C3C: 'jb 0x145304b30',
        0x145304C42: 'xorps xmm13,xmm13', 0x145304C46: 'jmp 0x145304ca3',
        0x145304C48: 'sqrtss xmm13,xmm13',
        0x145304C4D: 'mulps xmm6,xmm6', 0x145304C54: 'addss xmm3,xmm6',
        0x145304C58: 'sqrtss xmm3,xmm3', 0x145304C5C: 'sqrtss xmm2,xmm2',
        0x145304C60: 'subss xmm2,xmm3', 0x145304C64: 'subss xmm13,xmm3',
        0x145304C69: 'divss xmm13,xmm2', 0x145304C6E: 'subps xmm0,xmm7',
        0x145304C76: 'mulps xmm13,xmm0', 0x145304C7A: 'addps xmm13,xmm7',
        0x145304C86: 'subss xmm4,xmm3', 0x145304C8A: 'subss xmm6,xmm2',
        0x145304C8E: 'divss xmm6,xmm4', 0x145304C99: 'mulps xmm6,xmm0',
        0x145304C9C: 'addps xmm6,xmm7',
        0x145304DAF: 'movss xmm12,DWORD PTR [r15+0x8]',
        0x145304F12: 'movhlps xmm13,xmm13',
        0x145304F16: 'subss xmm12,xmm13',
        0x145304F20: 'movss DWORD PTR [r14+0x4],xmm12',
    }
    for site, ins in expected.items():
        if normalize(rows[site][1]) != ins:
            raise ValueError('Mode2 native sample or height-error producer differs')
    for start in (0x145304C42, 0x145304C48, 0x145304C80):
        reached = walk([start], graph, {0x145304CA3})
        if any(rows[a][1].startswith('call') for a in reached):
            raise ValueError('Sample branch has an unaccounted helper')
        if 0x145304CA3 not in {b for a in reached for b in graph[a]}:
            raise ValueError('Sample branch does not reach common error suffix')
    def f(x):
        return struct.unpack('<f', struct.pack('<f', x))[0]
    def length2(x, y):
        return f(math.sqrt(f(f(x*x) + f(y*y))))
    def sample(p, target, previous, current, radius, counter):
        dx, dy = f(target[0]-p[0]), f(target[1]-p[1])
        bx, by = f(current[0]-p[0]), f(current[1]-p[1])
        target_sq, current_sq = f(f(dx*dx)+f(dy*dy)), f(f(bx*bx)+f(by*by))
        ratio = None
        if current_sq >= target_sq:
            a = length2(previous[0], previous[1])  # 原代码使用前一位置的绝对XY。
            ratio = f(f(f(math.sqrt(target_sq))-a)/f(f(math.sqrt(current_sq))-a))
            kind = 'distance'
        elif radius > current[2]:
            ratio = f(f(previous[2]-radius)/f(previous[2]-current[2]))
            kind = 'ground'
        elif counter >= 360:
            kind = 'budget'
        else:
            raise ValueError('Local sample example has not exited')
        point = [0., 0., 0.] if ratio is None else [
            f(previous[i]+f(ratio*f(current[i]-previous[i]))) for i in range(3)]
        return {'branch': kind, 'ratio': ratio, 'sample': point,
                'height_error': f(target[2]-point[2])}
    examples = []
    for case in (
        {'origin': [4.,0.,1.], 'target': [6.,0.,2.], 'previous': [5.,0.,1.],
         'current': [7.,0.,3.], 'radius': .5, 'counter': 1},
        {'origin': [0.,0.,1.], 'target': [0.,10.,1.], 'previous': [0.,1.,1.],
         'current': [0.,2.,0.], 'radius': .5, 'counter': 1},
        {'origin': [0.,0.,1.], 'target': [0.,1000.,2.], 'previous': [0.,1.,1.],
         'current': [0.,2.,1.], 'radius': .5, 'counter': 360},
    ):
        result = sample(case['origin'], case['target'], case['previous'], case['current'],
                        case['radius'], case['counter'])
        examples.append({'input': case, 'output': result})
    if [e['output']['sample'] for e in examples] != [[8.,0.,4.], [0.,1.5,.5], [0.,0.,0.]]:
        raise ValueError('Hand-checkable native sample arithmetic differs')
    outer_rows, _ = decode_graph(exe, 0x145304400, 0x1453049C4)
    correction = {0x145304801: 'mov esi,DWORD PTR [rsp+0x44]',
                  0x14530483B: 'movd xmm0,esi',
                  0x14530483F: 'mulss xmm0,DWORD PTR [rip+0x1137bd9] # 0x14643c420',
                  0x14530484B: 'unpckhpd xmm1,xmm15',
                  0x145304850: 'addss xmm1,xmm0',
                  0x145304859: 'shufps xmm15,xmm1,0x84',
                  0x14530485E: 'movaps xmm0,xmm15',
                  0x145304862: 'subps xmm0,XMMWORD PTR [rdi]',
                  0x14530489F: 'shufps xmm6,xmm2,0x84',
                  0x1453048A7: 'mulps xmm0,xmm6',
                  0x1453048AA: 'movlps QWORD PTR [r13+0x0],xmm0',
                  0x14530493D: 'mov DWORD PTR [rip+0x1137ad9],0x3f666666 # 0x14643c420'}
    for site, ins in correction.items():
        if normalize(outer_rows[site][1]) != ins:
            raise ValueError('Mode2 height feedback producer differs')
    feedback_example = f(f(1.5) + f(f(.5)*f(.9)))
    return {'evidence_type': 'manual_register_dataflow_and_float32_local_transcription_not_execution',
            'checked_instructions': {hex(a): ins for a, ins in expected.items()},
            'height_feedback_instructions': {hex(a): ins for a, ins in correction.items()},
            'height_feedback': 'if abs(height error) exceeds current threshold and correction budget remains: temporary aim.z += error * current[14643c420], then velocity=scale*normalize(aim-origin)',
            'height_feedback_example': {'temporary_aim_z': 1.5, 'error': .5, 'assumed_gain': f(.9), 'new_aim_z': feedback_example, 'scope': 'local formula, not current natural coefficient/target'},
            'exit_priority': ['distance', 'ground', 'budget'],
            'distance_ratio': '(sqrt(target_relative_xy_sq)-length(previous_absolute_xy))/(sqrt(current_relative_xy_sq)-length(previous_absolute_xy))',
            'ground_ratio': '(previous_z-radius)/(previous_z-current_z)',
            'sample': 'previous+ratio*(current-previous); budget-only exit uses zero vector',
            'height_error': 'original target.z - sample.z; actual second error float',
            'examples': examples,
            'limits': 'finite local snapshots with nonzero interpolation denominators, not same natural trajectory; angle residual/final output still unproved'}


def inspect(exe):
    """复核模式分派、数值体清单和局部公式；完整试算输出仍未证明。"""
    data = exe.read_bytes()
    verify_target_identity(data, json.loads((ROOT / '20261019_fm24_target_identity.json').read_text()))
    pe = struct.unpack_from('<I', data, 60)[0]
    start = pe + 24 + struct.unpack_from('<H', data, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', data, start + 40 * i + 8)
                for i in range(struct.unpack_from('<H', data, pe + 6)[0])]

    def offset(a):
        for _, rva, size, raw in sections:
            if rva <= a - 0x140000000 < rva + size:
                return raw + a - 0x140000000 - rva
        raise ValueError(f'No file bytes at {a:#x}')

    tables, indirect = [], {}
    for site, base, count in ((0x1443F3A4D, 0x1443F48F0, 156), (0x1443F41F8, 0x1443F4B60, 6)):
        raw = data[offset(base):offset(base) + count * 4]
        targets = [base + value for value in struct.unpack(f'<{count}i', raw)]
        indirect[site] = targets
        tables.append({'site': hex(site), 'base': hex(base), 'bytes': raw.hex(),
                       'targets': [hex(a) for a in targets]})
    rows, full = decode_graph(exe, 0x1443F2EF0, 0x1443F48EF, indirect_targets=indirect)
    # 已初始化的第一静态TLS检查；起点Z=1、3f、现代M版本。高度门槛的两边保留。
    fixed = {0x1443F3031: 0x1443F3037, 0x1443F3110: 0x1443F313B,
             0x1443F3152: 0x1443F3154, 0x1443F3158: 0x1443F315A,
             0x1443F31CD: 0x1443F32AB, 0x1443F331D: 0x1443F33C1,
             0x1443F33C7: 0x1443F3D3B, 0x1443F3D40: 0x1443F3D46,
             0x1443F33E6: 0x1443F3428, 0x1443F3439: 0x1443F360D,
             0x1443F364D: 0x1443F3653, 0x1443F3663: 0x1443F3669,
             0x1443F41CE: 0x1443F41D0, 0x1443F430C: 0x1443F432D,
             0x1443F43B2: 0x1443F43F7, 0x1443F42C9: 0x1443F42E4, 0x1443F4608: 0x1443F460E}
    for site, target in fixed.items():
        if target not in full[site]:
            raise ValueError(f'Not a native actual-input edge {site:#x}')
    cases = []
    for mode in (0, 1, 2, 4):
        graph = dict(full)
        choices = dict(fixed)
        choices.update({0x1443F3659: 0x1443F41BE if mode < 2 else 0x1443F365F,
                        0x1443F366D: 0x1443F3673 if mode == 2 else 0x1443F41AF,
                        0x1443F42AE: 0x1443F42B0 if mode == 1 else 0x1443F42DF,
                        0x1443F436E: 0x1443F4498 if mode == 2 else 0x1443F4374,
                        0x1443F4393: 0x1443F4399 if mode < 2 else 0x1443F4520,
                        0x1443F4663: 0x1443F4665 if mode >= 3 else 0x1443F4685})
        for site, target in choices.items():
            if target not in full[site]:
                raise ValueError(f'Not a native mode edge {site:#x}')
            graph[site] = [target]
        graph[0x1443F41F8] = [indirect[0x1443F41F8][mode]]
        pre = walk([0x1443F2EF0], graph, set(FIRST))
        frontier = {target for a in pre for target in graph[a] if target in FIRST}
        expected = 0x1443F4516 if mode == 2 else (0x1443F448E if mode < 2 else 0x1443F45A3)
        if frontier != {expected}:
            raise ValueError(f'Mode{mode} has another first trial boundary')
        calls = {hex(a): normalize(rows[a][1]) for a in sorted(pre) if rows[a][1].startswith('call')}
        if any(ins not in {'call 0x14557ea20'} for ins in calls.values()):
            raise ValueError('Pretrial path has an unclassified business/helper call')
        if any(rows[a][1].startswith('ret') for a in pre):
            raise ValueError('Selected solver can return before first trial')
        if expected in walk([0x1443F2EF0], graph, {0x1443F3428}):
            raise ValueError('Actual trial bypasses modern effective-mode transfer')
        post = walk([expected + 5], graph)
        if any(rows[a][1].startswith('call') for a in post):
            raise ValueError('Posttrial suffix retains an unproved retry')
        if {a for a in post if rows[a][1].startswith('ret')} != {0x1443F47D5}:
            raise ValueError('Posttrial normal return differs')
        if 0x1443F47D5 in walk([expected + 5], graph, {0x1443F476D}):
            raise ValueError('Posttrial return bypasses velocity output copy')
        writes = stores(rows, pre)
        if {int(row['site'], 16) for row in writes} != {
            0x1443F2FCB, 0x1443F309D, 0x1443F4299,
            0x1443F367B if mode == 2 else 0x1443F41C6}:
            raise ValueError('Pretrial contains an unclassified explicit store')
        if {int(row['site'], 16) for row in stores(rows, post)} != {0x1443F476D}:
            raise ValueError('Posttrial suffix writes beyond its vector output')
        cases.append({'effective_mode': mode, 'selection_byte': 2 if mode == 2 else (3 if mode < 2 else 1),
                      'first_trial_site': hex(expected), 'first_trial_target': hex(FIRST[expected]),
                      'branches': {hex(a): hex(t) for a, t in choices.items()},
                      'pretrial_calls': calls, 'pretrial_stores': writes,
                      'post_return_calls': [], 'post_return_stores': stores(rows, post),
                      'post_return_scope': 'conditional on trial normal return, valid output buffers and x64 nonvolatile-register ABI'})
    for site, expected in {
        0x1443F3428: 'mov r12d,r15d', 0x1443F3653: 'mov al,0x3',
        0x1443F367B: 'mov BYTE PTR [rax],0x2', 0x1443F41BC: 'inc al',
        0x1443F476D: 'movaps XMMWORD PTR [rsi],xmm0',
    }.items():
        if normalize(rows[site][1]) != expected:
            raise ValueError('Effective mode/selection/output producer differs')
    constants = {hex(a): struct.unpack_from('<f', data, offset(a))[0]
                 for a in (0x145A1D4A4, 0x145A1D4B0, 0x145A1D48C, 0x145A1D4EC, 0x145A1D4C4, 0x145A1D468)}
    trials = inspect_trial_bodies(exe, data, offset)
    return {'mode2_sampling': inspect_mode2_sampling(exe), 'residual_preservation': inspect_residual_preservation(exe), 'scratch_producer': inspect_scratch_producer(exe), 'trial_bodies': trials, 'scalar_constants': constants, 'evidence_type': 'original_PE_mode_partition_CFG_not_execution', 'tables': tables,
            'conditions': ['same actual3f and updated target/scale/spin; source origin=C540, Z=1; mode input in{0,1,2,4}',
                           'M6a0>23; control B+d10 is same M; independent valid argument/output storage',
                           'finite derived distances/scalars; first thread-static initialization gate already satisfied at1443f3031; valid TLS and data reads',
                           'partition is by effective mode after1443f3428; target-height comparison retained'],
            'mode_transfer': 'input0/1 may become2 from target-height check; originZ1 prevents low-origin increase;2/4 remain',
            'cases': cases, 'unproved': ['actual numerical trial bodies and their side effects/normal return',
                                       'exact natural target, scales, spin, selected effective mode and initial TLS-source lifecycle',
                                       'ordinary perturbation, same new flight, defense/rules and goal'],
            'limits': 'Manual argument/mode dataflow plus original CFG checks; no automatic symbolic execution, alias proof or game run.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(inspect(args.exe), ensure_ascii=False, indent=2) + '\n')
    print('PASS: effective-mode partitions/conditional suffixes; trial-body call inventories; outer budget cuts; actual conditional integration counters, local seed arithmetic fresh scratch source/copy cuts, prepared force write domains, residual cycle cuts and mode2 sample/height feedback.')
    print('Conditional static evidence only; complete trial outputs and shot-to-goal mechanism remain unproved.')
