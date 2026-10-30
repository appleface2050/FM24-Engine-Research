"""从原PE复核已选3f的两套目标准备及近距公共插值，不冻结目标数值。"""

import argparse
import json
import struct
from pathlib import Path

from inspect_preparation_reference_paths import decode_graph, walk
from inspect_shot_selector_paths import normalize, stores
from verify_goal_lifecycle import verify_target_identity

ROOT = Path(__file__).resolve().parents[1]


def inspect(exe):
    """CALL按正常返回处理；写域身份仍需结合报告的人工寄存器推导。"""
    data = exe.read_bytes()
    verify_target_identity(data, json.loads((ROOT / '20261019_fm24_target_identity.json').read_text()))
    pe = struct.unpack_from('<I', data, 60)[0]
    start = pe + 24 + struct.unpack_from('<H', data, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', data, start + i * 40 + 8)
                for i in range(struct.unpack_from('<H', data, pe + 6)[0])]

    def offset(address):
        for _, rva, size, raw in sections:
            if rva <= address - 0x140000000 < rva + size:
                return raw + address - 0x140000000 - rva
        raise ValueError(f'No bytes at {address:#x}')

    def table(base, count):
        raw = data[offset(base):offset(base) + 4 * count]
        targets = [base + value for value in struct.unpack(f'<{count}i', raw)]
        return {'base': hex(base), 'bytes': raw.hex(), 'targets': [hex(a) for a in targets]}, targets

    tables = []
    record, dispatch = table(0x1444306DC, 18)
    tables.append(record)
    if dispatch[0x3F - 0x36] != 0x14442957A:
        raise ValueError('Actual 3f dispatch differs')
    rows, prefix = decode_graph(exe, 0x144429171, 0x144429243,
                               indirect_targets={0x144429241: [0x14442957A]},
                               external_stops=(0x144429331, 0x14442957A, 0x14442D9D0))
    for site, target in {0x144429188: 0x14442918E, 0x1444291E2: 0x1444291F5,
                         0x144429226: 0x14442922C}.items():
        if target not in prefix[site]:
            raise ValueError('Actual selected prefix edge differs')
        prefix[site] = [target]
    reached = walk([0x144429171], prefix)
    if any(rows[a][1].startswith('call') for a in reached) or 0x14442957A not in reached:
        raise ValueError('Selected prefix has another helper or misses target dispatch')
    prefix_stores = stores(rows, reached)

    dispatch_rows, dispatch_graph = decode_graph(exe, 0x14442957A, 0x1444295A4,
                                                 external_stops=(0x14442D9D0,))
    dispatch_reached = walk([0x14442957A], dispatch_graph)
    if {normalize(dispatch_rows[a][1]) for a in dispatch_reached
        if dispatch_rows[a][1].startswith('call')} != {'call 0x14444a4e0', 'call 0x14444acc0'}:
        raise ValueError('3f branch no longer calls both recorded target alternatives')
    if stores(dispatch_rows, dispatch_reached):
        raise ValueError('3f dispatch has an unclassified store')

    functions = []
    domains = [
        (0x14444A4E0, 0x14444ACB9, {0x14444A50C, 0x14444A5B2, 0x14444A963,
          0x14444A976, 0x14444A9CA, 0x14444A9DC, 0x14444AB53},
         {0x14444A563, 0x14444A660, 0x14444A700, 0x14444A70B, 0x14444A757,
          0x14444A772, 0x14444A7F2, 0x14444A842, 0x14444A9B8, 0x14444AA16,
          0x14444AA4D, 0x14444AAF1, 0x14444AB24, 0x14444AB39, 0x14444AB40,
          0x14444ABA2, 0x14444ABB3, 0x14444ABDD, 0x14444AC06, 0x14444AC21, 0x14444AC69}),
        (0x14444ACC0, 0x14444B7AA, {0x14444B0EF, 0x14444B453, 0x14444B466,
          0x14444B4B9, 0x14444B4CB, 0x14444B643},
         {0x14444B054, 0x14444B0A2, 0x14444B19D, 0x14444B23D, 0x14444B248,
          0x14444B2B7, 0x14444B2E6, 0x14444B338, 0x14444B4A8, 0x14444B505,
          0x14444B53C, 0x14444B5E1, 0x14444B614, 0x14444B629, 0x14444B630,
          0x14444B692, 0x14444B6A3, 0x14444B6D1, 0x14444B6F6, 0x14444B711, 0x14444B759}),
        (0x14444F2C0, 0x14444F74F, set(), {0x14444F624, 0x14444F6E5, 0x14444F732}),
        (0x141B50E00, 0x141B50EE8, set(), {0x141B50EE3}),
    ]
    for entry, end, call_sites, store_sites in domains:
        local_rows, graph = decode_graph(exe, entry, end)
        local = walk([entry], graph)
        calls = {a: normalize(local_rows[a][1]) for a in sorted(local)
                 if local_rows[a][1].startswith('call')}
        writes = stores(local_rows, local)
        if set(calls) != call_sites or {int(row['site'], 16) for row in writes} != store_sites:
            raise ValueError(f'Unclassified target call/store {entry:#x}')
        functions.append({'entry': hex(entry), 'calls': {hex(a): ins for a, ins in calls.items()},
                          'stores': writes,
                          'returns': [hex(a) for a in sorted(local) if local_rows[a][1].startswith('ret')]})
        # 两个生成器都在范围调用之前真正写模式1；不从调用后状态倒推。
        if entry in (0x14444A4E0, 0x14444ACC0):
            mode, use = ((0x14444AB40, 0x14444AB53) if entry == 0x14444A4E0
                         else (0x14444B630, 0x14444B643))
            if use in walk([entry], graph, {mode}):
                raise ValueError('Spin-range call bypasses mode producer')
            for site, expected in ((mode, 'mov DWORD PTR [r14+0xe74],0x1'),):
                if normalize(local_rows[site][1]) != expected:
                    raise ValueError('Actual mode producer differs')

    indirect = {}
    for site, base, count in ((0x14443E9F4, 0x14443EAC4, 5),
                              (0x14443EA9F, 0x14443EAD8, 131)):
        record, targets = table(base, count)
        tables.append(record)
        indirect[site] = targets
    spin_rows, spin_graph = decode_graph(exe, 0x14443E9D0, 0x14443EAC2, indirect_targets=indirect)
    spin = walk([0x14443E9D0], spin_graph)
    if any(spin_rows[a][1].startswith('call') for a in spin):
        raise ValueError('Spin range has an unclassified callee')
    if {int(row['site'], 16) for row in stores(spin_rows, spin)} != {0x14443EAB2, 0x14443EAB4}:
        raise ValueError('Spin range writes beyond output pair')

    # 公共前缀保留目标Z与所有高度分支，只限定已生产的近距1.5和动作3f。
    common_rows, common = decode_graph(exe, 0x14442D9D0, 0x14442DD43,
                                       external_stops=(0x14442DD43, 0x14442E04A))
    for site, target in {0x14442D9E4: 0x14442D9EA, 0x14442DC4F: 0x14442DC55,
                         0x14442DC63: 0x14442DC69}.items():
        if target not in common[site]:
            raise ValueError('Near/3f common branch differs')
        common[site] = [target]
    common_reached = walk([0x14442D9D0], common)
    if 0x14442E04A in common_reached or 0x14442DD43 not in common_reached:
        raise ValueError('Actual common prefix has an uncovered exit')
    if not (0x1780000000001F & (1 << (0x3F - 0xD))):
        raise ValueError('3f no longer in common allowed mask')
    common_stores = stores(common_rows, common_reached)
    if {int(row['site'], 16) for row in common_stores} != {
        0x14442DA07, 0x14442DA4E, 0x14442DA83, 0x14442DB39,
        0x14442DBFD, 0x14442DCB6, 0x14442DD18, 0x14442DD2C}:
        raise ValueError('Common prefix has an unclassified store')
    calls = {hex(a): normalize(common_rows[a][1]) for a in sorted(common_reached)
             if common_rows[a][1].startswith('call')}
    if set(calls) != {'0x14442dbcb', '0x14442dc90', '0x14442dcc9'}:
        raise ValueError('Common prefix has an unclassified helper')
    # 插值两次写点均必经；不是用之前距离9的绕过分支。
    for write in (0x14442DA07, 0x14442DA4E):
        if 0x14442DD43 in walk([0x14442D9D0], common, {write}):
            raise ValueError('Near target reaches helper boundary without actual interpolation')

    def f32(value):
        return struct.unpack('<f', struct.pack('<f', value))[0]

    constants = {hex(a): struct.unpack_from('<f', data, offset(a))[0]
                 for a in (0x145A1D41C, 0x145A1D410, 0x145A1D4D4, 0x145A1D460, 0x145A1D4E4)}
    radius, height, two, correction, blend = [constants[hex(a)] for a in
        (0x145A1D41C, 0x145A1D410, 0x145A1D4D4, 0x145A1D460, 0x145A1D4E4)]
    if (radius, height, two, correction, blend) != (f32(.1112), f32(2.44), 2., f32(.1), 4.):
        raise ValueError('Current target/interpolation constants differ')
    height_parameter = f32(f32(height - f32(radius * two)) - correction)
    # 每一步按原生单精度顺序；这是局部算例，不替代真实目标生成。
    blended_x = f32(f32(f32(1.5 * 2.) + f32(0. * 2.5)) / 4.)
    blended_y = f32(f32(f32(1.5 * 52.5) + f32(2.5 * 54.5)) / 4.)
    if (blended_x, blended_y) != (.75, 53.75):
        raise ValueError('Worked interpolation arithmetic differs')
    return {'evidence_type': 'original_PE_CFG_and_manual_write_domains_not_execution',
            'conditions': ['same selected3f, Aflags4, Pflags810/1810, C5c4=1.5; ordinary ABI/CRT',
                           'C570 source is a valid nonzero side slot; original typed geometry/tables and finite valid indices',
                           'normal returns, independent P/M/C/stack; upstream natural-source gaps retained'],
            'tables': tables, 'prefix_stores': prefix_stores, 'target_functions': functions,
            'spin_range_stores': stores(spin_rows, spin),
            'common': {'calls': calls, 'stores': stores(common_rows, common_reached),
                       'mandatory_interpolation': ['0x14442da07', '0x14442da4e'],
                       'checkpoint': '0x14442dd43 before first common helper',
                       'mode': 'target generator writes1; common may write0',
                       'action_extension_scalar_flags': '3f/0/0/4 preserved before first common helper'},
            'height_parameter': {'source': '14441a45b then14441a4bb for M6a0>23',
                                 'constants': constants, 'C5d8': height_parameter},
            'worked_example': {'distance': 1.5, 'old_target': [2., 52.5],
                               'blend_reference': [0., 54.5], 'new_target': [blended_x, blended_y],
                               'scope': 'local formula only; not a claim either helper produced this target'},
            'unproved': ['precise generated target and scalar values in same natural state',
                         'three common helpers after checkpoint, solver/perturbation/new flight/defense/goal',
                         'production/retention of inherited extra cache/global/version/db1 conditions'],
            'limits': 'Branches/call coverage and stores are checked; pointer identity is manual, no game execution.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(inspect(args.exe), ensure_ascii=False, indent=2) + '\n')
    print('PASS: actual3f target dispatch; both complete target functions and leaf write domains; near interpolation to common-helper boundary.')
    print('Conditional static connection only; exact natural target, later execution and goal remain unproved.')
