# Android Kernel Hacking Toolkit

**Read this in other languages: [English](README.md), [中文](README_zh.md).**

This repository contains a collection of Linux kernel modules (LKM) and accompanying userspace utilities designed for **Android aarch64** kernels. They demonstrate various advanced kernel manipulation techniques, including file operations, process hiding, system property modification, and system call hijacking. All modules include workarounds for modern kernel mitigations such as **CFI (Control Flow Integrity)** and **sys_call_table write protection**.

> **⚠️ WARNING**: These modules are for **educational purposes only**. Running them on production devices can cause instability, security vulnerabilities, or permanent damage. Use only on test devices where you have full control and responsibility.

---

## Table of Contents

- [Overview](#overview)
- [Modules](#modules)
  - [1. filecopy – Kernel‑Space File Copy](#1-filecopy--kernelspace-file-copy)
  - [2. hideproc – Hide and Protect a Process](#2-hideproc--hide-and-protect-a-process)
  - [3. propedit – Modify Android System Properties](#3-propedit--modify-android-system-properties)
  - [4. syscall_hijack – Fake sysinfo() Data](#4-syscall_hijack--fake-sysinfo-data)
- [Technical Highlights](#technical-highlights)
- [Compilation & Usage](#compilation--usage)
- [License](#license)

---

## Overview

Android kernels (especially from version 5.4 onward) implement several security features that make it difficult to directly manipulate kernel structures:

- **CFI (Control Flow Integrity)**: Validates indirect function calls to prevent function pointer hijacking.
- **Read‑only sys_call_table**: The system call table is marked read‑only, preventing direct modification.
- **Restricted symbol exports**: `kallsyms_lookup_name` is no longer exported, making dynamic symbol resolution harder.

The modules in this repository overcome these restrictions using:

- **kprobes** to retrieve the address of `kallsyms_lookup_name` (for kernels ≥5.7).
- **`no_sanitize("cfi")`** attributes on wrapper functions to bypass CFI checks.
- **mmuhack**: Direct page‑table manipulation to temporarily disable write protection on kernel memory (e.g., `sys_call_table`).
- **Physical memory writes** (in `propedit`) to modify userspace memory from the kernel.

Each module comes with a small userspace program that communicates via **ioctl** on a `/dev/` device file.

---

## Modules

### 1. filecopy – Kernel‑Space File Copy

**Goal**: Copy a file from a source path to a destination path entirely within the kernel, bypassing userspace file I/O.

- **Kernel driver**: `filecopy.c`
- **Userspace tool**: `filecopy_main.c`

**How it works**:

1. Resolves addresses of kernel functions `filp_open`, `filp_close`, `kernel_read`, and `kernel_write` via `kallsyms_lookup_name`.
2. Wraps each function pointer with a CFI‑bypass function (`__attribute__((no_sanitize("cfi")))`).
3. When an ioctl with `FILECOPY_IOC_COPY` is received:
   - Opens the source file (`O_RDONLY`).
   - Opens/creates the destination file (`O_WRONLY|O_CREAT|O_TRUNC`, mode 0644).
   - Allocates a kernel buffer (64 KB) and performs a read‑write loop until EOF.
   - Closes both files and frees the buffer.

**Use cases**:
- Copy files that might be protected by SELinux or other MAC mechanisms that restrict userspace access but allow kernel access.
- Educational example of kernel file I/O and CFI bypass.

---

### 2. hideproc – Hide and Protect a Process

**Goal**: Completely hide a process (identified by PID) from `/proc` and prevent it from being killed.

- **Kernel driver**: `hideproc.c`
- **Userspace tool**: `hideproc_main.c`

**Hooked system calls**:

| Syscall   | Purpose                                           |
|-----------|---------------------------------------------------|
| `openat`  | Block access to `/proc/<pid>/...` files           |
| `getdents64` | Remove the `<pid>` directory entry from `/proc` |
| `kill`    | Return `-ESRCH` for any signal targeting the hidden PID |

**Techniques**:

- Uses **mmuhack** to temporarily disable write protection on `sys_call_table`.
- Replaces the original syscall entries with custom hook functions.
- The hook functions call the original syscalls (via CFI‑bypass wrappers) and then filter results.
- For `openat`: if the path starts with `/proc/` and the PID matches the protected one, the file descriptor is closed and `-ENOENT` is returned.
- For `getdents64`: if the directory is `/proc`, the list of directory entries is scanned; any entry whose name is exactly the protected PID (i.e., a numeric string) is removed from the result buffer before copying back to userspace.
- For `kill`: if the target PID equals the protected PID, return `-ESRCH` (no such process).

**Use cases**:
- Conceal a monitoring or anti‑forensics process.
- Protect a critical system service from being accidentally killed.
- Demonstrate syscall hooking and process hiding techniques.

---

### 3. propedit – Modify Android System Properties

**Goal**: Change the value of any Android system property, even those that are normally read‑only or protected by SELinux.

- **Kernel driver**: `propedit.c`
- **Userspace tool**: `propedit_main.cpp`

**Background**: Android properties are stored in shared memory (`/dev/__properties__/`). Each property is represented by a `prop_info` structure containing a `serial` (for synchronization) and a `value` array. The property area is mapped into every process that uses properties.

**How it works**:

1. **Userspace**:
   - Scans `/proc/self/maps` to locate the property region(s) (files named `/dev/__properties__/*`).
   - Performs a brute‑force search for the target property key by scanning the region for plausible `prop_info` structures.
   - Once found, it obtains the **virtual address** of the `value` field and sends it to the kernel driver via ioctl (`PROP_IOC_WRITE`), along with the new value.

2. **Kernel**:
   - Translates the user virtual address to a **physical address** by walking the page tables of the current process (`current->mm`).
   - Uses `ioremap_cache` to map the physical page containing the target address into the kernel virtual address space.
   - Copies the new value into the mapped memory (ensuring it does not cross a page boundary; property values are ≤92 bytes, so safe).
   - Unmaps the memory.

**Why this works**: By writing directly to the physical memory backing the property, the modification is visible to all processes, and no syscall or SELinux checks are triggered. The `serial` field is left untouched, so the property system remains consistent.

**Use cases**:
- Modify `ro.*` (read‑only) properties after boot.
- Bypass property‑based restrictions (e.g., in banking apps).
- Change system settings without using `setprop` (which may be monitored).

**Limitations**: Requires root and works only on kernels where the property region is physically contiguous or can be mapped page‑by‑page. Tested on Android 14 (kernel 6.1).

---

### 4. syscall_hijack – Fake sysinfo() Data

**Goal**: Intercept the `sysinfo` system call and return fake system statistics (uptime, total RAM, free RAM, number of processes) to all userspace programs.

- **Kernel driver**: `syscall_hijack.c`
- **Userspace tool**: `syscall_hijack_main.c`

**How it works**:

- Uses **mmuhack** to disable write protection on `sys_call_table`.
- Replaces the `__arm64_sys_sysinfo` entry with a custom function `hijack_sysinfo`.
- The custom function first calls the original `sysinfo` (via a CFI‑bypass wrapper) to obtain the real data, then, if fake mode is enabled, overwrites the userspace buffer with a pre‑configured `struct sysinfo` (provided via ioctl).
- The fake data is stored in a kernel global variable (`fake_sysinfo`) and can be updated at runtime.

**Use cases**:
- Test applications that react to system resource metrics.
- Conceal the true resource usage of a system.
- Demonstrate system call hijacking and data tampering.

---

## Technical Highlights

### CFI Bypass
All modules that use indirect function calls (e.g., calling original syscalls from hooks) wrap those calls in functions marked with `__attribute__((no_sanitize("cfi")))`. This prevents the compiler from inserting CFI checks that would otherwise cause a panic when calling through a modified function pointer.

### Dynamic Symbol Resolution (kallsyms_lookup_name)
For kernels ≥5.7, `kallsyms_lookup_name` is not exported. The modules use a **kprobe** on the symbol `"kallsyms_lookup_name"` to obtain its runtime address. This address is then used to resolve other kernel symbols (`filp_open`, `sys_call_table`, etc.).

### mmuhack – Disabling Write Protection on Kernel Memory
The `sys_call_table` (and other kernel read‑only data) is protected by page‑table entries that mark the pages as read‑only. To modify the table, the modules:

1. Locate the `init_mm` structure (the memory descriptor for the kernel).
2. For the virtual address of the syscall entry, traverse the page tables to obtain the PTE (Page Table Entry).
3. Use a custom `set_pte_at` (or fallback to direct assignment) to rewrite the PTE with write permission enabled (`pte_mkwrite`).
4. After modification, restore the PTE to read‑only (`pte_wrprotect`).

This technique works on aarch64 and has been tested on kernels up to 6.1.

### Physical Memory Write (propedit)
Instead of using `copy_to_user` (which would not bypass property protections), `propedit` translates the target user virtual address to a physical address and then uses `ioremap_cache` to create a kernel mapping to that physical page. This allows the kernel to directly modify the memory of any process (including itself) without going through standard copy routines.

---

## Compilation & Usage

### Prerequisites
- A rooted Android device with kernel headers available (or a matching kernel build environment).
- ARM64 (`aarch64`) architecture.
- Kernel version 5.4 – 6.1 (may work on others with adjustments).

### Building a Module
Each module directory should contain the `.c` source and a `Makefile`. Example `Makefile`:

```makefile
obj-m += filecopy.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Copy the source to the target device, then run `make`. The resulting `.ko` file can be inserted with `insmod`.

### Userspace Tools
Compile each userspace tool with the appropriate compiler:

- C programs: `gcc filecopy_main.c -o filecopy`
- C++ program (propedit): `g++ propedit_main.cpp -o propedit`

### Typical Workflow
1. `insmod module.ko`
2. Run the userspace tool with required arguments.
3. Observe the effect (e.g., `ls /proc` to see hidden PID, `getprop` to verify property change, `free -m` to see fake sysinfo).
4. `rmmod module` to unload.

---

## License

All code in this repository is released under the **GNU General Public License (GPL)** version 2, as required for Linux kernel modules.

---

**Author**: systemnb  
**Repository**: [android-kernel-hacking-toolkit](https://github.com/systemnb/android-kernel-hacking-toolkit)  
**Date**: February 2026