"""从原PE复核已选3f公共方向、属性、速度/旋转三个实际调用的条件写域。"""

import argparse
import json
import re
from pathlib import Path

from inspect_preparation_reference_paths import decode_graph, walk
from inspect_shot_selector_paths import normalize, stores
from verify_goal_lifecycle import verify_target_identity

ROOT = Path(__file__).resolve().parents[1]


def inspect(exe):
    """保留方向返回、db4、惩罚/属性抽样及高度分支；不执行原函数。"""
    verify_target_identity(exe.read_bytes(), json.loads((ROOT / '20261019_fm24_target_identity.json').read_text()))
    branch_sets = {
        0x14444B7B0: {0x14444B7F2: 0x14444B7F8, 0x14444B7FB: 0x14444B801,
            0x14444B804: 0x14444B80A, 0x14444BD7C: 0x14444BDB4,
            0x14444BDC3: 0x14444BDC5, 0x14444BDD7: 0x14444BFC9,
            0x14444BFCC: 0x14444C067, 0x14444C073: 0x14444C09C},
        0x14444C130: {0x14444C1A1: 0x14444C1A7, 0x14444C47A: 0x14444C47C},
        0x14444C540: {0x14444C5BF: 0x14444C5C5, 0x14444C747: 0x14444C789,
            0x14444C783: 0x14444C789, 0x14444C7BE: 0x14444C7EF,
            0x14444C8BD: 0x14444C789},
    }
    expected_calls = {
        0x14444B7B0: {0x14444B7D6: 'call 0x141b51c90', 0x14444B8FD: 'call 0x141b51c90',
                     0x14444B9C2: 'call 0x141b51c90', 0x14444BD43: 'call 0x141b51c90'},
        0x14444C130: {0x14444C2F0: 'call 0x141b40bd0', 0x14444C48B: 'call 0x141b4fe90',
                     0x14444C4AD: 'call 0x141b4fe90'},
        0x14444C540: {0x14444C66D: 'call 0x14444ed60', 0x14444CB6E: 'call 0x14443e9d0',
                     0x14444CC79: 'call 0x14443e9d0'},
    }
    functions = []
    for entry, end in ((0x14444B7B0, 0x14444C121), (0x14444C130, 0x14444C531),
                        (0x14444C540, 0x14444CE29)):
        rows, graph = decode_graph(exe, entry, end)
        for site, target in branch_sets[entry].items():
            if target not in graph[site]:
                raise ValueError(f'Not an original common-helper branch {site:#x}')
            graph[site] = [target]
        reached = walk([entry], graph)
        calls = {a: normalize(rows[a][1]) for a in sorted(reached) if rows[a][1].startswith('call')}
        if calls != expected_calls[entry]:
            raise ValueError(f'Uncovered common-helper call {entry:#x}')
        writes = stores(rows, reached)
        if entry == 0x14444B7B0:
            allowed = {0x14444B7DF, 0x14444BC32, 0x14444BC52, 0x14444BC8E,
                       0x14444BD31, 0x14444BD4A, 0x14444BE10, 0x14444C0CD}
            if {int(row['site'], 16) for row in writes} != allowed:
                raise ValueError('Unclassified direction-helper write')
            for site, expected in {
                0x14444B7C7: 'lea rbx,[rcx+0xdc0]',
                0x14444C0B5: 'movabs rcx,0xfffdffffffffffff',
                0x14444C0C6: 'shl rax,0x31',
                0x14444C0CD: 'mov QWORD PTR [rsi+0xe28],rax',
            }.items():
                if normalize(rows[site][1]) != expected:
                    raise ValueError('Target/bit49 binding differs')
        else:
            # 这里只是显式写点范围；M和P/C的别名身份按报告所列手工推导。
            allowed_offsets = ({'e3d0', 'e6c', '590', '5a8'} if entry == 0x14444C130
                               else {'e34', 'e6c', 'e70', 'e74', 'e3d0'})
            for row in writes:
                offset = re.search(r'\+0x([0-9a-f]+)\]', row['instruction'].split(',', 1)[0])
                if not offset or offset[1] not in allowed_offsets:
                    raise ValueError(f'Unclassified explicit write {row}')
        if entry == 0x14444C540:
            if 0x14444C993 in reached:
                raise ValueError('Other-action mode producer remains reachable')
            for final in (0x14444CE06, 0x14444CE18):
                if 0x14444CE28 in walk([entry], graph, {final}):
                    raise ValueError('Final rotation clamp can be bypassed')
        functions.append({'entry': hex(entry), 'calls': {hex(a): ins for a, ins in calls.items()},
                          'branches': {hex(a): hex(t) for a, t in branch_sets[entry].items()},
                          'stores': writes,
                          'normal_returns': [hex(a) for a in sorted(reached) if rows[a][1].startswith('ret')]})

    # 方向子树现在允许非NULL栈字节输出；不能复用“没有外部写入”的NULL结论。
    direction = []
    for entry, end in ((0x141B51C90, 0x141B51E0C), (0x141B51E10, 0x141B51F26)):
        rows, graph = decode_graph(exe, entry, end)
        reached = walk([entry], graph)
        writes = stores(rows, reached)
        if any('[r8]' not in row['instruction'].split(',', 1)[0] for row in writes):
            raise ValueError('Direction subtree writes beyond its optional output')
        if any(re.match(r'(?!cmp |test )\w+ r8[bwd]?,', normalize(rows[a][1])) for a in reached):
            raise ValueError('Direction subtree changes its output pointer')
        calls = {hex(a): normalize(rows[a][1]) for a in sorted(reached) if rows[a][1].startswith('call')}
        direction.append({'entry': hex(entry), 'calls': calls, 'stores': writes})
    if direction[0]['calls'] != {'0x141b51e00': 'call 0x141b51e10'} or direction[1]['calls']:
        raise ValueError('Direction subtree has another helper')

    # 不能把混淆跳板后面的线性字节当成实现；从真实E9目标解码。
    trampoline, _ = decode_graph(exe, 0x14444ED60, 0x14444ED65, external_stops=(0x15A0CB580,))
    if normalize(trampoline[0x14444ED60][1]) != 'jmp 0x15a0cb580':
        raise ValueError('Scale trampoline target differs')
    scale_rows, scale_graph = decode_graph(exe, 0x15A0CB580, 0x15A0CB741)
    scale = walk([0x15A0CB580], scale_graph)
    if any(scale_rows[a][1].startswith('call') for a in scale):
        raise ValueError('Native scale leaf has a callee')
    scale_stores = stores(scale_rows, scale)
    if {int(row['site'], 16) for row in scale_stores} != {0x15A0CB61F, 0x15A0CB72F}:
        raise ValueError('Native scale leaf has another write')
    if normalize(scale_rows[0x15A0CB5A6][1]) != 'mov rax,rdx':
        raise ValueError('Native scale output pointer differs')

    # 用当前已证写域契约接真实调用者；起点修正继续复用3f/db1=0的已证叶路径。
    caller_rows, caller = decode_graph(exe, 0x14442DD43, 0x14442DDE7,
                                      external_stops=(0x14442DDE7,))
    caller[0x14442DDD1] = [0x14442DDE0]
    for site in (0x14442DD54, 0x14442DD5F, 0x14442DD6A, 0x14442DDCA):
        if 0x14442DDE0 in walk([0x14442DD43], caller, {site}):
            raise ValueError('Actual helper sequence can be bypassed')
    return {'evidence_type': 'original_PE_conditional_CFG_and_manual_write_domains_not_execution',
            'conditions': ['same selected3f and post-interpolation inputs; Pflags810 or1810; db1=0; P16f8 bit0=0',
                           'valid player/context/geometry/direction tables and pair-distance indices/records, independent storage',
                           'normal Windows x64 ABI; reused attribute/getter/RNG/distance-cache/spin-range contracts'],
            'functions': functions, 'direction_subtree': direction,
            'scale_leaf': {'entry': '0x15a0cb580', 'stores': scale_stores,
                           'fixed_global_side_effect': 'WORD at14c56adff AND DX; retained, not classified as a match-state output'},
            'result': {'checkpoint': '0x14442dde0 before solver argument preparation',
                       'action_extension_scalar': '3f/0/0 preserved',
                       'flags': '4 or (4 | (1<<49)); bit0 remains0',
                       'mode': 'input0/1 may remain or become2/4 via14444cb5a; output in{0,1,2,4}',
                       'rotation_parameters': 'each clamped to[-18,18] on normal return',
                       'target': 'X may change again; Y/Z held by these three helpers; do not freeze precise target',
                       'attribute_distance': 'mode0/2 getter uses current P+e30, not unchanged C+5c4=1.5'},
            'unproved': ['precise target/mode/rotation/scale at same natural input',
                         'solver, ordinary perturbation, same flight, defense/rules and goal',
                         'upstream extra input sources and later consumers of the retained fixed global write'],
            'limits': 'Instruction graph/write coverage is not automatic pointer-alias proof or native execution.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(inspect(args.exe), ensure_ascii=False, indent=2) + '\n')
    print('PASS: actual3f common-helper call/write domains, nonnull direction subtree, native scale target, clamps and caller sequence.')
    print('Conditional static result only; exact natural execution and goal remain unproved.')
