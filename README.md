# bitku-fast

Bitcoin Core 钱包密码恢复工具 — **CPU 高性能优化版**

基于 [budong1212/bitku](https://github.com/budong1212/bitku)，保持所有功能不变，专注于 CPU 运行速度提升（目标 10x）。

---

## ⚡ 与原版的性能差异

| 优化项 | 原版 | 优化版 |
|--------|------|--------|
| SHA-512 循环内存分配 | `Vec<u8>` 堆分配（每次迭代） | `[u8; 64]` 栈数组（零堆分配） |
| Sha512 hasher 构造 | 每次迭代 `Sha512::new()` | 循环内 `finalize_reset()` 复用 |
| AES buffer | `ciphertext.to_vec()` 堆分配 | `[u8; 16]` 栈数组 |
| SHA-NI 硬件加速 | 未启用 | `sha2` asm feature + target-cpu=native |
| LTO | `lto = true`（thin） | `lto = "fat"`（全量跨 crate 内联） |
| panic 开销 | unwinding | `panic = "abort"` |

---

## 📊 预期加速分析

```
原版热路径（每个密码）：
  iter_count × (Vec::new + Vec::push + Vec 释放 + Sha512::new)
  ≈ iter_count × ~150ns 额外开销

优化版热路径：
  iter_count × (finalize_reset + array copy)
  ≈ iter_count × ~5ns 额外开销

+ SHA-NI 硬件指令：SHA-512 本身提速 3~5x（支持的 CPU 上）
+ fat LTO：跨 crate 内联消除函数调用边界
总预期加速：5x ~ 15x（取决于 CPU 型号和 iter_count）
```

---

## 🚀 编译运行

```bash
# 必须用 release 模式才能获得全部优化
cargo build --release

# 运行
./target/release/btc-recovery-rust
```

> **注意**：`.cargo/config.toml` 中启用了 `target-cpu=native`，
> 编译产物与编译机 CPU 绑定，不可跨机器复制。
> 如需分发，删除该配置文件后重新编译。

---

## 功能说明

功能与原版完全一致：
- 支持 Berkeley DB 和 SQLite 两种钱包格式
- GUI 界面（eframe/egui）
- 单密码测试
- 字典攻击（Rayon 多线程并行）
- 实时进度与速度显示
