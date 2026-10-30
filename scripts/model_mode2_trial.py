"""模式2试算的有限输入静态转写；不是原生执行或自然进球证据。

仅支持非零有限平面方向、稳定非零环境计数字节、轴(0,0,1)、已初始化系数。
系数由显式输入提供；原只读角近似常数复用已从原PE核对的记录。
"""

import argparse
import json
import math
import struct
from pathlib import Path


def f(x):
    """每次原单精度算术后舍入，不模拟MXCSR异常/非有限输入。"""
    return struct.unpack('<f', struct.pack('<f', x))[0]


def add(a, b):
    return f(a + b)


def sub(a, b):
    return f(a - b)


def mul(a, b):
    return f(a * b)


def div(a, b):
    return f(a / b)


def norm(v):
    """按XYZ顺序累加平方再开根。"""
    return f(math.sqrt(add(add(mul(v[0], v[0]), mul(v[1], v[1])), mul(v[2], v[2]))))


def normalized(v):
    n = norm(v)
    return [div(x, n) for x in v]


def spin_for(v, horizontal, vertical):
    """1453045cf及重复修正的非零水平速度分支。"""
    n = norm([v[0], v[1], 0.])
    return [mul(div(v[1], n), horizontal), mul(-div(v[0], n), horizontal), vertical]


def force(v, w, p):
    """阻力与旋转力相加；参数均来自显式局部输入，非自然默认值。"""
    speed = norm(v)
    if speed <= p['drag_min_speed']:
        cd = p['drag_low']
    elif speed >= p['drag_max_speed']:
        cd = p['drag_high']
    else:
        u = div(sub(speed, p['drag_min_speed']), sub(p['drag_max_speed'], p['drag_min_speed']))
        smooth = mul(mul(u, u), sub(3., add(u, u)))
        cd = add(mul(sub(p['drag_high'], p['drag_low']), smooth), p['drag_low'])
    magnitude = mul(mul(mul(p['density'], p['half_area']), cd), speed)
    result = [mul(magnitude, -x) for x in v]
    wn = norm(w)
    if speed == 0. or wn == 0.:
        return result
    vn, wu = normalized(v), normalized(w)
    coefficient = add(mul(div(mul(wn, p['radius']), speed), p['spin_slope']), p['spin_intercept'])
    # 原函数先算speed平方，再乘rho*half_area，最后乘旋转系数。
    speed_sq = add(add(mul(v[0], v[0]), mul(v[1], v[1])), mul(v[2], v[2]))
    magnitude = mul(mul(speed_sq, mul(p['density'], p['half_area'])), coefficient)
    cross = [sub(mul(wu[1], vn[2]), mul(wu[2], vn[1])),
             sub(mul(wu[2], vn[0]), mul(wu[0], vn[2])),
             sub(mul(wu[0], vn[1]), mul(wu[1], vn[0]))]
    return [add(result[i], mul(magnitude, cross[i])) for i in range(3)]


def angle_error(actual, target, c):
    """复用已恢复的有限非零XY方向公式，符号轴固定为明确支持的+Z。"""
    a = normalized([actual[0], actual[1], 0.])
    b = normalized([target[0], target[1], 0.])
    dot = add(mul(a[0], b[0]), mul(a[1], b[1]))
    clipped = min(1., max(0., dot))
    root = f(math.sqrt(sub(1., mul(clipped, clipped))))
    q = div(sub(root, clipped), add(add(root, abs(clipped)), c['0x14584c5d4']))
    poly = mul(add(mul(mul(c['0x145a1350c'], q), q), c['0x145a13510']), q)
    phi = add(poly, c['0x145870800'])
    cross = sub(mul(b[0], a[1]), mul(b[1], a[0]))
    return -phi if cross < 0. else phi


def rotate(delta, theta, c):
    """轴+Z的原近似矩阵；本模型拒绝需要范围归约的角度。"""
    def sine(x):
        if not c['0x145830658'] <= x <= c['0x1456d56d4']:
            raise ValueError('Unsupported range-reduction input')
        b = sub(mul(x, c['0x145a0a9fc']), mul(mul(x, c['0x145a0aa00']), abs(x)))
        return add(mul(sub(mul(abs(b), b), b), c['0x145a0aa04']), b)
    sn, cs = sine(theta), sine(add(theta, c['0x145831614']))
    return [add(add(mul(cs, delta[0]), mul(-sn, delta[1])), mul(0., delta[2])),
            add(add(mul(sn, delta[0]), mul(cs, delta[1])), mul(0., delta[2])),
            add(add(mul(0., delta[0]), mul(0., delta[1])), mul(add(sub(1., cs), cs), delta[2]))]


def residual(origin, target, velocity, spin, p, c):
    """1453049d0的稳定非零计数路径；返回误差及临时终态，非正式球状态。"""
    position, v = origin[:], velocity[:]
    desired = [sub(target[i], origin[i]) for i in range(3)]
    target_sq = add(mul(desired[0], desired[0]), mul(desired[1], desired[1]))
    for step in range(360):
        previous = position[:]
        h = mul(sub(1., p['time_scalar']), p['step']) if step == 0 and p['time_scalar'] > 0 else p['step']
        total_force = force(v, spin, p)
        acceleration = [add(div(total_force[i], p['mass']), p['gravity'][i]) for i in range(3)]
        position = [add(add(mul(mul(mul(h, h), acceleration[i]), .5), mul(v[i], h)), previous[i]) for i in range(3)]
        v = [add(mul(h, acceleration[i]), v[i]) for i in range(3)]
        dx, dy = sub(position[0], origin[0]), sub(position[1], origin[1])
        current_sq = add(mul(dx, dx), mul(dy, dy))
        if current_sq >= target_sq:
            # 这里必须保留绝对前一位置长度，不能改成标准线段交点。
            a = norm([previous[0], previous[1], 0.])
            q = div(sub(f(math.sqrt(target_sq)), a), sub(f(math.sqrt(current_sq)), a))
            kind = 'distance'
        elif p['radius'] > position[2]:
            q = div(sub(previous[2], p['radius']), sub(previous[2], position[2]))
            kind = 'ground'
        elif step == 359:
            q, kind = None, 'budget'
        else:
            continue
        sample = [0., 0., 0.] if q is None else [add(mul(q, sub(position[i], previous[i])), previous[i]) for i in range(3)]
        actual = [sub(sample[i], origin[i]) for i in range(3)]
        return {'angle': angle_error(actual, desired, c), 'height': sub(target[2], sample[2]),
                'steps': step + 1, 'exit': kind, 'sample': sample,
                'terminal_position': position, 'terminal_velocity': v}
    raise AssertionError('Counter path must exit by360')


def trial(inputs, c):
    """组合初值与至多四轮修正，保留最后的发射初速与末步速度的差别。"""
    p = inputs['parameters']
    origin, target, scale = inputs['origin'], inputs['target'], inputs['scale']
    delta = [sub(target[i], origin[i]) for i in range(3)]
    initial = [mul(x, scale) for x in normalized(delta)]
    tau = div(norm([delta[0], delta[1], 0.]), norm([initial[0], initial[1], 0.]))
    aim = target[:]
    aim[2] = add(aim[2], mul(mul(mul(p['gravity'][2], tau), tau), -.5))
    velocity = [mul(x, scale) for x in normalized([sub(aim[i], origin[i]) for i in range(3)])]
    spin = spin_for(velocity, inputs['horizontal_spin'], inputs['vertical_spin'])
    history = []
    for correction in range(5):
        r = residual(origin, target, velocity, spin, p, c)
        history.append({'correction': correction, 'aim': aim[:], 'launch_velocity': velocity[:],
                        'launch_spin': spin[:], 'residual': r})
        angle_bad = abs(r['angle']) > p['angle_threshold']
        height_bad = abs(r['height']) > p['height_threshold']
        if correction == 4 or not (angle_bad or height_bad):
            break
        if angle_bad:
            shifted = rotate([sub(aim[i], origin[i]) for i in range(3)], mul(-r['angle'], p['angle_gain']), c)
            aim = [add(origin[i], shifted[i]) for i in range(3)]
        if height_bad:
            aim[2] = add(aim[2], mul(r['height'], p['height_gain']))
        velocity = [mul(x, scale) for x in normalized([sub(aim[i], origin[i]) for i in range(3)])]
        spin = spin_for(velocity, inputs['horizontal_spin'], inputs['vertical_spin'])
    return {'queries': history, 'returned_launch_velocity': velocity, 'returned_launch_spin': spin,
            'last_residual_terminal_velocity': history[-1]['residual']['terminal_velocity'],
            'within_input_tolerances': not (angle_bad or height_bad)}


def examples():
    """显式假设的模型算例；不冒充目标生成器的自然输出或游戏实测。"""
    root = Path(__file__).resolve().parents[1]
    proof = json.loads((root / '20261030_shot_solver_modes.json').read_text())
    constants = {a: row['float'] for a, row in proof['mode2_angle']['constants'].items()}
    r = f(.1112)
    parameters = {'radius': r, 'mass': f(.43), 'half_area': mul(mul(mul(f(math.pi), r), r), .5),
                  'density': f(1.224978566), 'drag_min_speed': f(8.), 'drag_max_speed': f(21.),
                  'drag_low': f(.41), 'drag_high': f(.24), 'spin_intercept': f(.12), 'spin_slope': f(.77),
                  'gravity': [0., 0., f(-9.8)], 'step': f(1/12), 'time_scalar': 0.,
                  'angle_threshold': f(.001), 'height_threshold': f(.01),
                  'angle_gain': f(.95), 'height_gain': f(.9)}
    records = []
    for name, offset, horizontal, vertical in [('straight_no_force', 0., 0., 0.),
                                               ('gravity_drag', 0., 0., 0.),
                                               ('gravity_drag_spin', 0., 2., 1.),
                                               ('translated_origin', 51., 0., 0.),
                                               ('limited_speed_ground_exit', 0., 0., 0.),
                                               ('zero_tolerance_straight', 0., 0., 0.)]:
        p = dict(parameters)
        if name in {'straight_no_force', 'zero_tolerance_straight'}:
            p.update(density=0., gravity=[0., 0., 0.])
        if name == 'zero_tolerance_straight':
            p.update(angle_threshold=0., height_threshold=0.)
        distance, scale = (20., 5.) if name == 'limited_speed_ground_exit' else (2., 20.)
        inputs = {'origin': [0., offset, 1.], 'target': [0., add(offset, distance), 1.],
                  'scale': scale, 'horizontal_spin': horizontal, 'vertical_spin': vertical, 'parameters': p}
        records.append({'name': name, 'input': inputs, 'result': trial(inputs, constants)})
    first = records[0]['result']
    if len(first['queries']) != 1 or first['returned_launch_velocity'] != [0.,20.,0.] or first['returned_launch_spin'] != [0.,-0.,0.]:
        raise ValueError('Constant straight-flight worked example differs')
    last = next(r['result'] for r in records if r['name'] == 'limited_speed_ground_exit')
    if len(last['queries']) != 5 or last['within_input_tolerances']:
        raise ValueError('Limited-speed budget example unexpectedly reports convergence')
    zero = records[-1]['result']
    if len(zero['queries']) != 5 or zero['within_input_tolerances']:
        raise ValueError('Zero-tolerance approximation residual should exhaust correction budget')
    # 对照之前独立保存的角误差局部转写，避免组合时颠倒叉积方向。
    for case in proof['mode2_angle']['examples']:
        actual, target = case['actual_xy']+[0.], case['target_xy']+[0.]
        if angle_error(actual, target, constants) != case['residual']['error']:
            raise ValueError('Combined angular kernel disagrees with retained local evidence')
    return {'evidence_type': 'STATIC_TRANSCRIPTION_ONLY_NOT_NATIVE_EXECUTION_NOT_NATURAL_GOAL_EVIDENCE',
            'readonly_constants_source': '20261030_shot_solver_modes.json:mode2_angle.constants',
            'supported_scope': 'finite nonzero XY directions at every normalization, nonzero sample denominators, fixed valid parameters/nonzero environment counter, initialized globals, U=(0,0,1), range-reduced rotation angles',
            'unproved': ['independent native semantic equivalence, zero-direction/nonfinite branches, full parameter lifecycle',
                         'same natural target/scale/spin, ordinary perturbation, formal flight, defense/rules and goal'],
            'cases': records}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = examples()
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    for case in result['cases']:
        r = case['result']
        print(case['name'], 'queries=', len(r['queries']), 'launch=', r['returned_launch_velocity'],
              'within_tolerances=', r['within_input_tolerances'])
