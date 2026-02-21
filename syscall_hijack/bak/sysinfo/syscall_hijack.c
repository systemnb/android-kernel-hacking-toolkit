/*
 * syscall_hijack_sysinfo.c - 劫持 sysinfo 系统调用 (aarch64)
 * 通过 ioctl 设置伪造的系统信息，所有进程调用 sysinfo() 将看到伪造的数据。
 * 使用 mmuhack 解除 sys_call_table 写保护。
 *
 * 编译: make -C /lib/modules/$(uname -r)/build M=$PWD modules
 * 加载: insmod syscall_hijack_sysinfo.ko
 * 测试: 使用用户程序设置伪造信息 (例如 ./set_fake_sysinfo)
 * 查看效果: 运行 free -m 或编写小程序查看 sysinfo 结构。
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
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/sysinfo.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/unistd.h>

#define DEVICE_NAME "syscall_hijack_sysinfo"
#define IOC_MAGIC 'I'
#define SET_FAKE_SYSINFO _IOW(IOC_MAGIC, 1, struct sysinfo)

/* 伪造的系统信息结构体（用户可设置） */
static struct sysinfo fake_sysinfo = {0};
static int fake_enabled = 0;   // 0=禁用,1=启用
static DEFINE_MUTEX(info_lock);

/* 原系统调用指针 */
static long (*orig_sys_sysinfo)(const struct pt_regs *);

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

    printk("[syscall_hijack] update_mapping_prot: 0x%lx, start_rodata: 0x%lx, end_rodata: 0x%lx\n",
           (unsigned long)my_update_mapping_prot, start_rodata, end_rodata);

    if (!my_update_mapping_prot || !start_rodata || !end_rodata) {
        pr_err("syscall_hijack: mmuhack init failed - missing symbols\n");
        return -1;
    }

    my_set_memory_ro = (void *)my_kallsyms_lookup_name("set_memory_ro");
    my_set_memory_rw = (void *)my_kallsyms_lookup_name("set_memory_rw");
    my_find_vm_area = (void *)my_kallsyms_lookup_name("find_vm_area");

    if (!my_set_memory_ro || !my_set_memory_rw || !my_find_vm_area) {
        pr_err("syscall_hijack: mmuhack init failed - missing memory functions\n");
        return -1;
    }

    init_mm_ptr = (struct mm_struct *)my_kallsyms_lookup_name("init_mm");
    if (!init_mm_ptr) {
        pr_err("syscall_hijack: cannot find init_mm\n");
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
            pr_warn("syscall_hijack: set_pte_at not found, falling back to direct assignment\n");
    }
    if (!flush_tlb_kernel_range_ptr) {
        unsigned long sym_addr = my_kallsyms_lookup_name("flush_tlb_kernel_range");
        flush_tlb_kernel_range_ptr = (flush_tlb_kernel_range_t)sym_addr;
        if (!flush_tlb_kernel_range_ptr)
            pr_warn("syscall_hijack: flush_tlb_kernel_range not found, cannot flush TLB\n");
    }
    if (set_pte_at_ptr) {
        set_pte_at_ptr(mm, addr, ptep, pte);
    } else {
        *ptep = pte;
        if (flush_tlb_kernel_range_ptr)
            flush_tlb_kernel_range_ptr(addr, addr + PAGE_SIZE);
        else
            pr_err("syscall_hijack: cannot flush TLB, system may become unstable\n");
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
        pr_err("syscall_hijack: cannot get pte for 0x%lx\n", page_addr);
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
        pr_err("syscall_hijack: cannot get pte for 0x%lx\n", page_addr);
        return -EINVAL;
    }
    pte_t pte = READ_ONCE(*ptep);
    pte = pte_wrprotect(pte);
    my_set_pte_at(init_mm_ptr, page_addr, ptep, pte);
    return 0;
}
/* -------------------- mmuhack 结束 -------------------- */

/* CFI 绕过包装 */
__attribute__((no_sanitize("cfi")))
static long sys_sysinfo_wrapper(const struct pt_regs *regs)
{
    return orig_sys_sysinfo(regs);
}

/* 自定义 sysinfo：篡改返回的数据 */
static asmlinkage long hijack_sysinfo(const struct pt_regs *regs)
{
    struct sysinfo __user *info = (struct sysinfo __user *)regs->regs[0];
    long ret;

    ret = sys_sysinfo_wrapper(regs);
    if (ret != 0) return ret;

    if (!fake_enabled) return ret;

    /* 将伪造的数据覆盖到用户空间 */
    if (copy_to_user(info, &fake_sysinfo, sizeof(struct sysinfo))) {
        return -EFAULT;
    }

    pr_info("syscall_hijack: sysinfo() returning fake data\n");
    return 0;
}

/* 替换系统调用 */
static int replace_syscalls(void)
{
    unsigned long *sys_call_table = find_syscall_table();
    unsigned long addr;

    if (!sys_call_table) {
        pr_err("syscall_hijack: cannot find sys_call_table\n");
        return -ENOENT;
    }

    addr = my_kallsyms_lookup_name("__arm64_sys_sysinfo");
    if (!addr) {
        pr_err("syscall_hijack: cannot find __arm64_sys_sysinfo\n");
        return -ENOENT;
    }
    orig_sys_sysinfo = (void *)addr;

    if (unprotect_syscall_entry(__NR_sysinfo)) {
        pr_err("syscall_hijack: failed to unprotect syscall entry\n");
        return -EPERM;
    }

    sys_call_table[__NR_sysinfo] = (unsigned long)hijack_sysinfo;

    if (protect_syscall_entry(__NR_sysinfo)) {
        pr_warn("syscall_hijack: failed to re-protect syscall entry, but hook is active\n");
    }

    pr_info("syscall_hijack: sys_sysinfo hooked successfully\n");
    return 0;
}

static void restore_syscalls(void)
{
    unsigned long *sys_call_table = find_syscall_table();
    if (!sys_call_table) return;

    if (unprotect_syscall_entry(__NR_sysinfo) == 0) {
        sys_call_table[__NR_sysinfo] = (unsigned long)orig_sys_sysinfo;
        protect_syscall_entry(__NR_sysinfo);
    }
    pr_info("syscall_hijack: syscalls restored\n");
}

/* 设备接口 */
static long hijack_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct sysinfo info;
    // int enable = 0;

    if (_IOC_TYPE(cmd) != IOC_MAGIC) return -ENOTTY;
    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID) && !capable(CAP_SYS_ADMIN))
        return -EPERM;

    switch (cmd) {
    case SET_FAKE_SYSINFO:
        if (copy_from_user(&info, (void __user *)arg, sizeof(struct sysinfo)))
            return -EFAULT;
        mutex_lock(&info_lock);
        memcpy(&fake_sysinfo, &info, sizeof(struct sysinfo));
        /* 只要结构体非全零即启用，或者用户可以显式设置启用标志 */
        fake_enabled = 1;
        mutex_unlock(&info_lock);
        pr_info("syscall_hijack: fake sysinfo set\n");
        return 0;
    default:
        return -ENOTTY;
    }
}

static const struct file_operations hijack_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = hijack_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = hijack_ioctl,
#endif
};

static struct miscdevice hijack_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &hijack_fops,
    .mode  = 0600,
};

static int __init hijack_init(void)
{
    int ret;

    if (init_memhack() != 0) {
        pr_err("syscall_hijack: mmuhack initialization failed\n");
        return -1;
    }

    ret = replace_syscalls();
    if (ret) return ret;

    ret = misc_register(&hijack_dev);
    if (ret) {
        pr_err("syscall_hijack: misc_register failed: %d\n", ret);
        restore_syscalls();
        return ret;
    }

    pr_info("syscall_hijack: loaded. device=/dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit hijack_exit(void)
{
    misc_deregister(&hijack_dev);
    restore_syscalls();
    pr_info("syscall_hijack: unloaded\n");
}

module_init(hijack_init);
module_exit(hijack_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("systemnb");
MODULE_DESCRIPTION("System call hijacking example: sysinfo() return fake data (aarch64)");