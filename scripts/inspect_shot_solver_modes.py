"""从原PE复核同一3f输入到三种首次试算的模式分区，不执行数值试算器。"""

import argparse
import json
import struct
from pathlib import Path

from inspect_preparation_reference_paths import decode_graph, walk
from inspect_shot_selector_paths import normalize, stores
from verify_goal_lifecycle import verify_target_identity

ROOT = Path(__file__).resolve().parents[1]
FIRST = {0x1443F448E: 0x145304F90, 0x1443F4516: 0x145304400, 0x1443F45A3: 0x145303160}


def inspect(exe):
    """图只证明给定模式/身份的分支与返回后缀；试算体和数值输出不在本入口范围。"""
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
    return {'scalar_constants': constants, 'evidence_type': 'original_PE_mode_partition_CFG_not_execution', 'tables': tables,
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
    print('PASS: effective-mode partitions reach three actual first trials; normal-return suffix has no retry and copies output.')
    print('Conditional CFG only; trial numerical bodies and complete shot-to-goal mechanism remain unproved.')
