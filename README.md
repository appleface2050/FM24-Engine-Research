# FM2024 比赛与转会机制逆向调查

研究开始日期：20261014。日期依据：用户首次要求调查 FM2024 比赛胜负、进球与失球的模拟机制。

目标为本机 Steam Windows 桌面版 `24.4.2+2081827`。本仓库保存只读取证与结论，不修改游戏或存档，不包含游戏程序、原始资源归档或存档。

当前研究方向：仅使用 FM24 自身程序和随附资源做静态分析，扩展到全场动作、比赛结果与电脑俱乐部的转会决策。停止游戏内对照实验，第三方编辑器内容不作为后续证据。下列历史运行内存观察仅保留已有来源记录，本轮未新增此类观察。

- [电脑转会决策静态分析](20261015_FM2024电脑转会决策.md)：候选名单任务、估值更新局部规则、报价与日期处理；选人排序、卖方接受与球员签约公式尚未恢复。
- [整体静态分析](20261014_FM2024整体静态分析.md)：原生属性编号、权重消费者、运动缩放、QME 关联及后续从结果回溯的研究路线。
- [FM26 参考与 FM24 复核](20261014_FM26参考与FM24复核.md)：跨版本资源编码、本机 3454 条 QME 分布记录及已恢复的局部随机数算术。
- [属性抽样与时间计算](20261014_属性抽样与时间计算.md)：属性对应的整数抽样、缓存刷新及反应缓存进入时间字段的局部路径；尚未闭合实际进球/扑救公式。
- [调查报告](20261014_FM2024比赛机制调查.md)：已确认事实、公式证据、版本限制和未解决问题。
- [守门员属性研究](20261014_FM2024守门员属性研究.md)：哪些属性对失球与胜负更重要、原作者实验、评分相关性与证据局限。
- `20261014_gk_experiment_observations.json`、`20261014_goalkeeper_hint_observations.json`：门将实验关键单元格及本机随附说明的定位与释义。
- `20261014_resource_observations.json`：按 FMF 清单恢复的相关成员位置、字段与未缩放 int32 候选。
- `20261014_static_inventory.json`：PE 区段与有界字符串检索结果。
- `20261014_native_attribute_observations.json`、`20261014_native_attribute_pseudocode.c.txt`、`20261014_native_attribute_parser.asm.txt`：本轮仅依据 FM24 恢复的属性编号及局部原生消费者；编号不是比赛对象字段偏移。
- `20261014_code_readonly_snapshot.json`：四个 128 字节代码窗口的只读运行内存观察。
- `20261014_xg_globals_readonly.json`：当前加载的模型索引、sigmoid 参数和 regular 系数；是数据读取，不是执行 trace。
- `20261014_focused_pseudocode.c.txt`、`20261014_xg_consumer_pseudocode.c.txt`：Ghidra CLI 局部伪代码，保留未知调用及反编译限制。
- `20261014_rea_session.json`：REA 的目标绑定及全量分析超时记录；没有完成的原生函数 dossier。
- `inspect_simatch.py`：复核资源成员定位的脚本；仅支持本次观测到的归档布局，不是通用 FMF/JSB 解码库。

解析器现在完整解码 `qme_stat_relevant_attribute_data.jsb` 的 22 条统计关联，保存为 `attribute_links`；完整解码 `qme_distribution_data.jsb` 的 3454 条记录，保存摘要为 `distribution_summary`。最小例子：`pass_completion` 输出 `[passing, decisions]`；这验证配置关联，不表示两项等权，也不表示完整比赛的传球公式。首条分布记录的数值 worked example 见 FM26 参考与 FM24 复核报告。

`20261014_match_rng_static.asm.txt` 保存本机随机数初始化与输出的指令窗口；没有在游戏中执行这些代码。

需要 Python 3.10+ 和 `zstandard`。在仓库根目录执行：

```bash
python3 -m pip install -r requirements.txt
```

自行提供所拥有的 FM24 安装目录；路径字段均相对于游戏安装根目录。复核命令：

```bash
python3 inspect_simatch.py \
  '/path/to/Football Manager 2024/data/simatch.fmf' \
  /tmp/fm24-resource-observations.json
```

最小 worked example：输入归档内 `simatch/expected_goals/models/24_1_2_3/coefficient_output_penalties.jsb`；清单给出文件偏移 `42024`、压缩长度 `152`、解压长度 `184`。按清单读取并解压，预期得到 184 字节，其中 `intercept` 后的原始四字节为 `60 c7 cd 00`，little-endian int32 候选为 `13485920`。这验证成员定位与原始数值读取。其加载后截距约 `1.348592`，其他输入贡献设为 0 时 sigmoid 输出约 `0.7939`；这仅是表达式演算，不证明实际点球进球率或该模型在某场比赛中被选用。

无新增核心概念。本次未发现既有实现中的可安全删除项；本次调查生成的重复中间预览在整理时收敛，不扩大无关重构。

## 独立仓库与更新

发布渠道：[GitHub](https://github.com/appleface2050/FM24-Engine-Research)（https://github.com/appleface2050/FM24-Engine-Research）。当前是部分机制的研究记录，尚未恢复完整进球、扑救或胜负公式。

仓库从原个人研究项目独立提取，首次发布包含当前文件快照，不导入原仓库历史。此前的社区实验和只读运行观察保留为历史材料；后续研究仅采用 FM24 自身程序及随附资源的静态证据，不使用第三方编辑器内容。

日常更新直接在本仓库提交、推送；父仓库只更新 `packages/fm24-match-mechanisms` 的 submodule 指针。原游戏版本、函数地址、输入文件标识及证据局限保留在各研究记录中。
