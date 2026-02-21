# Android 内核HOOK工具包

**其他语言版本: [English](README.md), [中文](README_zh.md).**

本仓库包含一组 Linux 内核模块（LKM）及配套的用户态工具，专为 **Android aarch64** 内核设计。它们展示了多种高级内核操作技术，包括文件操作、进程隐藏、系统属性修改和系统调用劫持。所有模块都包含了对现代内核缓解措施（如 **CFI** 和 **sys_call_table 写保护**）的绕过方法。

> **⚠️ 警告**：这些模块仅用于**教育目的**。在生产设备上运行可能导致系统不稳定、安全漏洞或永久性损坏。请仅在您拥有完全控制权的测试设备上使用。

---

## 目录

- [概述](#概述)
- [模块介绍](#模块介绍)
  - [1. filecopy – 内核空间文件复制](#1-filecopy-–-内核空间文件复制)
  - [2. hideproc – 隐藏并保护进程](#2-hideproc-–-隐藏并保护进程)
  - [3. propedit – 修改 Android 系统属性](#3-propedit-–-修改-android-系统属性)
  - [4. syscall_hijack – 伪造 sysinfo() 数据](#4-syscall_hijack-–-伪造-sysinfo-数据)
- [技术亮点](#技术亮点)
- [编译与使用](#编译与使用)
- [许可证](#许可证)

---

## 概述

Android 内核（尤其是 5.4 以上版本）实现了多项安全特性，使得直接操作内核结构变得困难：

- **CFI（控制流完整性）**：验证间接函数调用，防止函数指针劫持。
- **只读 sys_call_table**：系统调用表被标记为只读，禁止直接修改。
- **受限符号导出**：`kallsyms_lookup_name` 不再导出，动态符号解析变得复杂。

本仓库中的模块通过以下方法绕过这些限制：

- 使用 **kprobe** 获取 `kallsyms_lookup_name` 的地址（针对内核 ≥5.7）。
- 在包装函数上使用 **`no_sanitize("cfi")`** 属性绕过 CFI 检查。
- **mmuhack**：直接操作页表，临时禁用内核内存（如 `sys_call_table`）的写保护。
- **物理内存写入**（在 `propedit` 中）：从内核直接修改用户态内存。

每个模块都附带一个通过 `/dev/` 设备文件进行 **ioctl** 通信的小型用户态程序。

---

## 模块介绍

### 1. filecopy – 内核空间文件复制

**目标**：完全在内核中复制文件（源路径 → 目标路径），绕过用户态文件 I/O。

- **内核驱动**：`filecopy.c`
- **用户态工具**：`filecopy_main.c`

**工作原理**：

1. 通过 `kallsyms_lookup_name` 解析内核函数 `filp_open`、`filp_close`、`kernel_read` 和 `kernel_write` 的地址。
2. 为每个函数指针创建 CFI 绕过包装函数（`__attribute__((no_sanitize("cfi")))`）。
3. 收到 `FILECOPY_IOC_COPY` ioctl 时：
   - 以只读方式打开源文件。
   - 以写方式打开/创建目标文件（`O_WRONLY|O_CREAT|O_TRUNC`，权限 0644）。
   - 分配内核缓冲区（64 KB）并执行读写循环直到 EOF。
   - 关闭两个文件并释放缓冲区。

**用途**：
- 复制受 SELinux 或其他 MAC 机制保护的文件（用户态无法访问，但内核可以）。
- 作为内核文件 I/O 和 CFI 绕过的教学示例。

---

### 2. hideproc – 隐藏并保护进程

**目标**：彻底隐藏指定 PID 的进程（从 `/proc` 中消失），并防止被杀死。

- **内核驱动**：`hideproc.c`
- **用户态工具**：`hideproc_main.c`

**劫持的系统调用**：

| 系统调用   | 作用                                   |
|-----------|----------------------------------------|
| `openat`  | 阻止访问 `/proc/<pid>/...` 下的文件      |
| `getdents64` | 从 `/proc` 目录列表中移除 `<pid>` 条目 |
| `kill`    | 对隐藏的 PID 返回 `-ESRCH`（无此进程）    |

**技术细节**：

- 使用 **mmuhack** 临时禁用 `sys_call_table` 的写保护。
- 将原始系统调用条目替换为自定义钩子函数。
- 钩子函数先调用原始系统调用（通过 CFI 绕过包装），然后过滤结果。
- 对于 `openat`：如果路径以 `/proc/` 开头且 PID 匹配，则关闭已打开的文件描述符并返回 `-ENOENT`。
- 对于 `getdents64`：如果目录是 `/proc`，扫描目录项列表；如果某项的名称恰好是隐藏的 PID（纯数字字符串），则将该条目从结果缓冲区中移除。
- 对于 `kill`：如果目标 PID 等于隐藏 PID，返回 `-ESRCH`。

**用途**：
- 隐藏监控或反取证进程。
- 保护关键系统服务不被误杀。
- 演示系统调用劫持和进程隐藏技术。

---

### 3. propedit – 修改 Android 系统属性

**目标**：修改任意 Android 系统属性的值，即使是通常只读或受 SELinux 保护的属性。

- **内核驱动**：`propedit.c`
- **用户态工具**：`propedit_main.cpp`

**背景**：Android 属性存储在共享内存中（`/dev/__properties__/`）。每个属性由一个 `prop_info` 结构体表示，包含 `serial`（用于同步）和 `value` 数组。属性区域映射到每个使用属性的进程。

**工作原理**：

1. **用户态**：
   - 扫描 `/proc/self/maps` 定位属性区域（文件名为 `/dev/__properties__/*`）。
   - 通过暴力搜索在区域中查找目标属性键名，寻找可能的 `prop_info` 结构。
   - 找到后，获取 `value` 字段的**虚拟地址**，通过 ioctl (`PROP_IOC_WRITE`) 将该地址和新值发送给内核驱动。

2. **内核**：
   - 通过遍历当前进程的页表（`current->mm`）将用户虚拟地址转换为**物理地址**。
   - 使用 `ioremap_cache` 将包含目标地址的物理页映射到内核虚拟地址空间。
   - 将新值拷贝到映射的内存中（确保不跨页；属性值最大 92 字节，安全）。
   - 解除映射。

**为什么有效**：直接写入属性内存的物理页，所有进程都能看到修改，且不会触发任何系统调用或 SELinux 检查。`serial` 字段保持不变，属性系统保持一致性。

**用途**：
- 修改 `ro.*`（只读）属性。
- 绕过基于属性的限制（例如银行应用检测）。
- 不使用 `setprop`（可能被监控）更改系统设置。

**限制**：需要 root 权限，且仅在属性区域物理连续或可逐页映射的内核上工作。已在 Android 14（内核 6.1）上测试。

---

### 4. syscall_hijack – 伪造 sysinfo() 数据

**目标**：劫持 `sysinfo` 系统调用，向所有用户态程序返回伪造的系统统计信息（运行时间、总内存、空闲内存、进程数）。

- **内核驱动**：`syscall_hijack.c`
- **用户态工具**：`syscall_hijack_main.c`

**工作原理**：

- 使用 **mmuhack** 禁用 `sys_call_table` 的写保护。
- 将 `__arm64_sys_sysinfo` 条目替换为自定义函数 `hijack_sysinfo`。
- 自定义函数首先调用原始 `sysinfo`（通过 CFI 绕过包装）获取真实数据，如果伪造模式已启用，则用预配置的 `struct sysinfo`（通过 ioctl 设置）覆盖用户态缓冲区。
- 伪造数据存储在内核全局变量 `fake_sysinfo` 中，可在运行时更新。

**用途**：
- 测试对系统资源指标有反应的应用程序。
- 隐藏系统的真实资源使用情况。
- 演示系统调用劫持和数据篡改。

---

## 技术亮点

### CFI 绕过
所有使用间接函数调用的模块（例如从钩子调用原始系统调用）都将这些调用包装在带有 `__attribute__((no_sanitize("cfi")))` 的函数中。这可以防止编译器插入 CFI 检查，避免通过修改后的函数指针调用时导致内核崩溃。

### 动态符号解析 (kallsyms_lookup_name)
对于内核 ≥5.7，`kallsyms_lookup_name` 不再导出。模块使用 **kprobe** 探测符号 `"kallsyms_lookup_name"` 来获取其运行时地址，然后用该地址解析其他内核符号（`filp_open`、`sys_call_table` 等）。

### mmuhack – 禁用内核内存写保护
`sys_call_table`（及其他内核只读数据）受到页表条目的保护，这些条目将页面标记为只读。要修改表，模块需要：

1. 定位 `init_mm` 结构（内核的内存描述符）。
2. 对于系统调用条目的虚拟地址，遍历页表获得 PTE（页表项）。
3. 使用自定义的 `set_pte_at`（或直接赋值）重写 PTE，赋予写权限（`pte_mkwrite`）。
4. 修改完成后，将 PTE 恢复为只读（`pte_wrprotect`）。

此技术适用于 aarch64，并已在内核 6.1 上测试。

### 物理内存写入 (propedit)
`propedit` 不使用 `copy_to_user`（无法绕过属性保护），而是将目标用户虚拟地址转换为物理地址，然后使用 `ioremap_cache` 创建到该物理页的内核映射。这样内核就可以直接修改任何进程（包括自身）的内存，而无需经过标准拷贝例程。

---

## 编译与使用

### 前提条件
- 已 root 的 Android 设备，具有可用的内核头文件（或匹配的内核编译环境）。
- ARM64（`aarch64`）架构。
- 内核版本 5.4 – 6.1（其他版本可能需调整）。

### 编译模块
每个模块目录应包含 `.c` 源文件和 `Makefile`。示例 `Makefile`：

```makefile
obj-m += filecopy.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

将源文件复制到目标设备，然后运行 `make`。生成的 `.ko` 文件可用 `insmod` 加载。

### 用户态工具
使用相应编译器编译用户态工具：

- C 程序：`gcc filecopy_main.c -o filecopy`
- C++ 程序（propedit）：`g++ propedit_main.cpp -o propedit`

### 典型工作流程
1. `insmod module.ko`
2. 运行用户态工具并传入所需参数。
3. 观察效果（例如 `ls /proc` 查看隐藏的 PID，`getprop` 验证属性更改，`free -m` 查看伪造的 sysinfo）。
4. `rmmod module` 卸载模块。

---

## 许可证

本仓库中的所有代码均根据 **GNU 通用公共许可证 (GPL) 第二版** 发布，符合 Linux 内核模块的要求。

---

**作者**：systemnb  
**仓库**：[android-kernel-hacking-toolkit](https://github.com/systemnb/android-kernel-hacking-toolkit)  
**日期**：2026 年 2 月