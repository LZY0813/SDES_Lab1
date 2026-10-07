# S-DES 加解密与安全分析

项目使用 Python + PySide6 实现课程给定的 S-DES，覆盖 GUI 加解密、ASCII 字符串、暴力破解、密钥碰撞和等效密钥分析。

![二进制加解密界面](results/screenshots/01_binary.png)

## 功能与作业关卡

| 关卡 | 功能 | 状态 |
|---|---|---|
| 第1关 | 8-bit 分组、10-bit 密钥、GUI 加解密、完整轮过程 | 已完成 |
| 第2关 | Python/JavaScript 全域交叉验证、公开仓库测试向量复现 | 已完成 |
| 第3关 | ASCII 逐字节加解密、HEX 展示、原始字节导出 | 已完成 |
| 第4关 | 穷举 1024 个密钥、多明密文对筛选、计时、JSON 导出 | 已完成 |
| 第5关 | 256×1024 全域碰撞统计、等效密钥检查 | 已完成 |

## 课程算法参数

- 分组长度：8 bit
- 主密钥长度：10 bit
- 加密：`IP → fk(K1) → SW → fk(K2) → IP⁻¹`
- 解密：`IP → fk(K2) → SW → fk(K1) → IP⁻¹`
- 密钥扩展：`Ki=P8(Shift^i(P10(K))), i=1,2`
- SBox2：采用作业文档中的课程修改版

K1、K2 均从 `P10(K)` 出发，对左右两个 5-bit 半区分别循环左移 1 位和 2 位，不采用累计三位移位。

## 快速验证

### 本项目逐轮向量

```text
明文 P = 11010111
密钥 K = 1010000010
K1     = 10100100
K2     = 10010010
密文 C = 11101000
解密   = 11010111
```

## 交叉测试数据对照

测试数据参考：[wen-yan-chen/sdes-project](https://github.com/wen-yan-chen/sdes-project)。下列“本项目结果”均由当前代码实际运行得到。

### 基本加解密与交叉测试

| 测试项 | 输入 | 参考仓库结果 | 本项目结果 | 状态 |
|---|---|---|---|---|
| K1生成 | `K=1010000010` | `10100100` | `10100100` | 一致 |
| K2生成 | `K=1010000010` | `10010010` | `10010010` | 一致 |
| 8-bit加密 | `P=10111101`、`K=1010000010` | `C=11000011` | `C=11000011` | 通过 |
| 8-bit解密 | `C=11000011`、`K=1010000010` | `P=10111101` | `P=10111101` | 通过 |

### ASCII字符串测试

| 测试项 | 参考仓库数据 | 本项目实际结果 | 状态/说明 |
|---|---|---|---|
| 明文 | `This is a pen` | `This is a pen` | 一致 |
| 字符数量 | 13 | 13 | 一致 |
| 密文长度 | README写为112 bit | 104 bit（13×8） | 参考README存在笔误 |
| 密文表示 | 连续二进制字符串 | `82 0C 83 63 C2 83 63 C2 F9 C2 4F 5C 7E` | 底层13字节一致，展示格式不同 |
| 解密结果 | `This is a pen` | `This is a pen` | 通过 |

### 暴力破解测试

共同明密文对：`10111101 → 11000011`。

| 候选序号 | 参考仓库候选 | 本项目候选 | 状态 |
|---:|---|---|---|
| 1 | `0000010001` | `0000010001` | 一致 |
| 2 | `0100010001` | `0100010001` | 一致 |
| 3 | `1010000010` | `1010000010` | 一致 |
| 4 | `1110000010` | `1110000010` | 一致 |
| 合计 | 4个 | 4个 | 通过 |

### 固定明文碰撞测试

共同固定明文：`10111101`，遍历全部1024个密钥。

| 指标 | 参考仓库结果 | 本项目结果 | 状态 |
|---|---:|---:|---|
| 总密钥数 | 1024 | 1024 | 一致 |
| 不同密文数 | 254 | 254 | 一致 |
| 2个密钥对应同一密文 | 40个密文 | 40个密文 | 一致 |
| 4个密钥对应同一密文 | 172个密文 | 172个密文 | 一致 |
| 6个密钥对应同一密文 | 40个密文 | 40个密文 | 一致 |
| 8个密钥对应同一密文 | 2个密文 | 2个密文 | 一致 |

详细过程和扩展分析见 [五关测试报告](docs/test_report.md)。

## 安装与启动

要求 Windows、Python 3.11 或更高版本。

```powershell
.\setup.bat
.\start.bat
```

手动方式：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run.py
```

GUI 本身不依赖 Node.js；只有重建 Python/JavaScript 全域交叉验证时需要 Node.js。

## 测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\validate.py
.\.venv\Scripts\python.exe scripts\capture_gui.py
```

最近一次完整测试：

```text
33 passed
GUI 自动操作检查：15/15 通过
Python/JavaScript 比较：262144/262144 一致
双向解密检查：524288 次，错误 0
```

`capture_gui.py` 只捕获本程序窗口客户区，不读取桌面其他区域。

## 项目结构

```text
sdes-course-project/
├─ src/sdes/
│  ├─ core.py             # 置换、密钥扩展、轮函数、加解密、ASCII
│  ├─ analysis.py         # 暴力破解、碰撞及等效密钥分析
│  └─ gui.py              # PySide6 四页 GUI
├─ reference/sdes.js      # 独立 JavaScript 位数组实现
├─ tests/                 # 33 项自动化测试
├─ scripts/
│  ├─ validate.py         # 重建全域验证和统计结果
│  └─ capture_gui.py      # GUI 自动测试、截图和 GIF
├─ results/               # 精简后的可复现实验结果
├─ docs/                  # 用户、开发、算法与测试文档
└─ run.py
```

## 关键实验结论

- 固定任意明文时，1024 个密钥映射到最多 256 个密文，必然存在碰撞。
- 本参数下每个固定明文实际产生 254 种密文。
- 1024 个密钥只有 512 个不同的完整加密映射。
- 存在 512 组两两等效密钥。例如 `1010000010` 与 `1110000010` 对全部 256 个明文产生完全相同的密文。
- 因此增加明密文对不一定能恢复唯一的 10-bit 主密钥。

## 文档与证据

- [算法规范与逐位推导](docs/algorithm_spec.md)
- [用户指南](docs/user_guide.md)
- [开发手册及接口](docs/developer_guide.md)
- [五关测试报告](docs/test_report.md)
- [小组分工表](docs/team_contributions.md)
- [提交指南](docs/submission_guide.md)
- [暴力破解 GIF](results/recordings/brute_force.gif)
- [碰撞统计 CSV](results/collision_statistics.csv)
- [跨组测试向量](results/test_vectors/vectors.csv)

## 小组成员
- 李政豫 (学号: 20246446)
- 杨涵 (学号: 20246464)