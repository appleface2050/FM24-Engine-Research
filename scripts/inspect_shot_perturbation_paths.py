"""复核正幅度普通射门扰动后缀的写域和整数循环，不冻结随机序列。"""

import argparse
import graphlib
import json
import re
from pathlib import Path

from inspect_preparation_reference_paths import decode_graph, walk
from inspect_shot_selector_paths import normalize, stores
from verify_goal_lifecycle import verify_target_identity

ROOT = Path(__file__).resolve().parents[1]


def inspect(exe):
    """从正幅度门槛之后开始；不证明此前幅度/属性/缓存调用已完成。"""
    verify_target_identity(exe.read_bytes(), json.loads((ROOT/'20261019_fm24_target_identity.json').read_text()))
    rows, graph = decode_graph(exe, 0x14444CE30, 0x14444E7CD)
    graph = dict(graph)
    for site, target in {0x14444D89C: 0x14444D941, 0x14444D959: 0x14444D95F,
                         0x14444E578: 0x14444DBB0}.items():
        if target not in graph[site]:
            raise ValueError('Actual db1=0/bit0=0 edge differs')
        graph[site] = [target]
    start, finish = 0x14444D886, 0x14444E71D
    reached = walk([start], graph)
    if any(rows[a][1].startswith('call') for a in reached):
        raise ValueError('Positive-amplitude suffix retains an unproved callee')
    if {a for a in reached if rows[a][1].startswith('ret')} != {finish}:
        raise ValueError('Another perturbation return exists')
    required = {0x14444D88D, 0x14444D95F, 0x14444DB2D,
                0x14444E618, 0x14444E682, 0x14444E68E, 0x14444E697, 0x14444E6A4, 0x14444E6AF}
    for site in required:
        if finish in walk([start], graph, {site}):
            raise ValueError('Normal return bypasses original save/loop initialization/output')
    if 0x14444E560 in walk([start], graph, {0x14444E4A3,0x14444E4AD}):
        raise ValueError('Retry budget bypasses both10/500 producers')
    if 0x14444E560 in walk([start], graph, {0x14444E4BF,0x14444E4C3}):
        raise ValueError('Sign trials bypass local counter initialization')
    writes = stores(rows, reached)
    rng_sites = {0x14444DCAE, 0x14444DD6E, 0x14444DDBC, 0x14444DE06,
                 0x14444DE54, 0x14444DEA5, 0x14444E288}
    output_sites = {0x14444E67B, 0x14444E682, 0x14444E68E,
                    0x14444E697, 0x14444E6A4, 0x14444E6AF}
    if {int(row['site'],16) for row in writes} != rng_sites | output_sites:
        raise ValueError('Perturbation suffix has another explicit write domain')
    # 删除所有已识别的整数循环回边，在原完整可达集合上检查无遗漏循环。
    back_edges = {0x14444DFE6: 0x14444DFC0, 0x14444DFEE: 0x14444DFC0,
                  0x14444E076: 0x14444E050, 0x14444E07E: 0x14444E050,
                  0x14444E55A: 0x14444E4D0, 0x14444E578: 0x14444DBB0}
    cut = {a:list(graph[a]) for a in reached}
    for site, target in back_edges.items():
        if target not in cut[site]:
            raise ValueError('An integer-loop back edge differs')
        cut[site].remove(target)
    graphlib.TopologicalSorter(cut).prepare()
    expected = {0x14444D886: 'movaps xmm1,XMMWORD PTR [rsi+0xe00]',
                0x14444D88D: 'movaps XMMWORD PTR [rsp+0x80],xmm1',
                0x14444D949: 'movzx ecx,BYTE PTR [rsi+0xe80]',
                0x14444D95F: 'mov BYTE PTR [rsp+0x2d],cl',
                0x14444DB2D: 'xor r13d,r13d',
                0x14444E4A3: 'mov ebp,0xa', 0x14444E4AD: 'mov ebp,0x1f4',
                0x14444E4BF: 'lea edi,[r13+0x1]', 0x14444E4C3: 'xor r10d,r10d',
                0x14444E54F: 'lea eax,[r10+0x1]',
                0x14444E553: 'cmp r10b,0x2', 0x14444E557: 'mov r10d,eax',
                0x14444E560: 'cmp r13d,ebp', 0x14444E575: 'mov r13d,edi',
                0x14444E426: 'addps xmm13,xmm12',
                0x14444E626: 'movzx ecx,BYTE PTR [rsp+0x2d]',
                0x14444E62B: 'lea rax,[rsi+0xe00]',
                0x14444E67B: 'or BYTE PTR [rsi+0xe2f],0x2',
                0x14444E682: 'movlps QWORD PTR [rsi+0xdf0],xmm9',
                0x14444E68E: 'movss DWORD PTR [rsi+0xdf8],xmm9',
                0x14444E697: 'mov BYTE PTR [rsi+0xe80],cl',
                0x14444E69D: 'mov ecx,DWORD PTR [rsp+0x88]',
                0x14444E6A7: 'mov rcx,QWORD PTR [rsp+0x80]'}
    for site, instruction in expected.items():
        if normalize(rows[site][1]) != instruction:
            raise ValueError('Positive perturbation integer/output producer differs')
    # 按字节区间核对，防止相邻宽写覆盖保存的旋转或模式。
    widths = {'XMMWORD':16, 'QWORD':8, 'DWORD':4, 'WORD':2, 'BYTE':1}
    for a in reached:
        ins = normalize(rows[a][1])
        if ins.split()[0] in {'cmp','test','nop','cs'}:
            continue
        dest = ins.split(',',1)[0]
        frame = re.search(r'(XMMWORD|QWORD|DWORD|WORD|BYTE) PTR \[rsp\+0x([0-9a-f]+)\]$', dest)
        if frame:
            lo = int(frame[2],16)
            hi = lo + widths[frame[1]]
            if lo < 0x8c and hi > 0x80 and a != 0x14444D88D:
                raise ValueError('Saved spin has an overlapping explicit writer')
            if lo < 0x2e and hi > 0x2d and a != 0x14444D95F:
                raise ValueError('Saved mode has an overlapping explicit writer')
        if re.match(r'(?:mov|xor|add|sub|lea|inc|dec|imul|and|or) r13d?,', ins):
            if a not in {0x14444DB2D,0x14444E575}:
                raise ValueError('Outer retry index has another producer')
    def half(x):
        return x//2 if x >= 0 else -((-x)//2)
    bounds = []
    for x,y in [(-(1<<31), -(1<<31)), ((1<<31)-1, (1<<31)-1), (149,199), (150,200)]:
        original, steps = [x,y], 0
        while abs(x)>149 or abs(y)>199:
            x,y = half(x),half(y)
            steps += 1
        if steps > 24:
            raise ValueError('Signed halving bound differs')
        bounds.append({'input':original,'output':[x,y],'steps':steps})
    coefficient = json.loads((ROOT/'20261030_shot_solver_modes.json').read_text())['scalar_constants']['0x145a1d468']
    return {'evidence_type':'original_PE_post_positive_amplitude_CFG_and_manual_register_bindings_not_execution',
            'frontier':hex(start), 'normal_return':hex(finish),
            'conditions':['same P/M and independent valid stack/storage; positive finite amplitude and enabled ball setting already passed',
                          'P+db1=0; saved Aflags bit0=0; no external concurrent writes; ordinary nontrapping FP execution',
                          'valid lookup table at[14643a030] for the computed signed-word indexes; derived addresses valid'],
            'prefix_unproved':'full entry-to-positive-frontier business/cache/math effects and exact amplitude from same natural inputs',
            'calls':[], 'writes':writes, 'mandatory_sites':[hex(a) for a in sorted(required)],
            'loop_back_edges':{hex(a):hex(b) for a,b in back_edges.items()},
            'cycles_after_back_edge_cuts':False,
            'manual_loop_bounds':{'outer_index':'starts0, increments1 only on retry, cap10 or500; at most501 candidate rounds',
                                  'sign_trials':'R10 starts0 per round and permits0,1,2: at most3',
                                  'coordinate_halving':'two integer coordinate loops; each at most24 signed truncating halvings',
                                  'rng':'at most7 inline draws per candidate round; no fixed random seed assumption'},
            'halving_examples':bounds,
            'tail_worked_example':{'input_velocity':[0.,20.,0.], 'given_delta':[5.,0.,0.],
                                   'saved_spin':[2.,0.,1.], 'saved_mode':2, 'input_flags':4,
                                   'output_velocity':[5.,20.,0.], 'output_spin':[2.,0.,1.],
                                   'output_mode':2, 'output_flags':4|(1<<57),
                                   'scope':'hand-checkable final-write arithmetic only; delta is not proven to be generated/accepted by the native random loop'},
            'outputs':{'velocity':'incoming solver velocity plus accepted/revised perturbation vector, float32 additions',
                       'spin':'restore exact saved P+e00/e04/e08; not regenerated from perturbed velocity',
                       'mode_byte':'restore saved P+e80',
                       'large_delta_marker':f'if norm(delta)>float32({coefficient})*norm(incoming velocity), OR bit57; this comparison is not a magnitude clamp'},
            'remaining':['exact amplitude and randomized delta, table source/retention and complete numerical validity',
                         'same natural solver output through whole caller, formal flight, defense/rules and effective goal']}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    args.output.write_text(json.dumps(inspect(args.exe),ensure_ascii=False,indent=2)+'\n')
    print('PASS: positive suffix no calls, mandatory save/output, explicit write domains and identified integer loops; natural shot-to-goal still unproved.')
