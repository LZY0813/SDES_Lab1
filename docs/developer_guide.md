# 开发手册

## 结构

```text
src/sdes/core.py       核心算法与 ASCII 处理
src/sdes/analysis.py   暴力破解和碰撞分析
src/sdes/gui.py        PySide6 GUI
reference/sdes.js      独立 JavaScript 参考实现
tests/                 自动化测试
scripts/validate.py    重建精简验证结果
scripts/capture_gui.py GUI 自动操作、截图和 GIF
```

## 核心接口

| 接口 | 说明 |
|---|---|
| `parse_bits(text,width)` | 校验并解析固定宽度二进制 |
| `subkeys(key)` | 按作业公式生成 K1、K2 |
| `crypt(block,key,decrypt=False)` | 单个 8-bit 分组加/解密 |
| `trace(...)` | 返回全部中间步骤 |
| `encrypt_ascii/decrypt_ascii` | ASCII 逐字节处理 |
| `brute_force(pairs)` | 穷举全部 1024 个密钥 |
| `collision_analysis()` | 完整碰撞与等效密钥分析 |

耗时任务由单个 QThread 执行，使 GUI 保持响应；这不是并行破解。GUI 不直接实现密码算法，只调用算法层。

## 验证策略

- 固定逐位测试向量；
- 对全部 1024×256 组合验证加解密往返；
- Python 整数实现与 JavaScript 位数组实现分别计算有序密文字节流；
- 比较两个实现的 SHA-256 摘要，避免提交数十 MB 重复中间 JSON；
- 完整统计每个明文下的密钥碰撞与全域等效密钥。
