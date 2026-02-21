/*
 * Android 属性修改驱动 - 通过物理地址写入
 * 适用于 Android 14+ (内核 6.1)
 * 编译: make -C /lib/modules/$(uname -r)/build M=$PWD modules
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/io.h>
#include <linux/version.h>

#define DEVICE_NAME "propedit"
#define PROP_IOC_MAGIC  'P'
#define PROP_IOC_WRITE  _IOW(PROP_IOC_MAGIC, 2, struct prop_write_args)

#define PROP_VALUE_MAX  92

struct prop_write_args {
    uint64_t value_addr;   // 用户空间地址
    char new_value[PROP_VALUE_MAX];
};

/* 页表遍历：将虚拟地址转换为物理地址 */
static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61)
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    pud = pud_offset(p4d, va);
#else
    pud = pud_offset(pgd, va);
#endif
    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return 0;

    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte))
        return 0;

    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);

    return page_addr + page_offset;
}

/* 向物理地址写入数据（仅限一页内） */
static int write_physical_address(phys_addr_t pa, const char *buf, size_t len)
{
    void *vaddr;
    size_t offset = pa & (PAGE_SIZE - 1);
    phys_addr_t page_base = pa & PAGE_MASK;
    size_t map_size = offset + len;

    /* 确保不跨页（属性值最大92字节，不会跨页） */
    if (map_size > PAGE_SIZE)
        map_size = PAGE_SIZE;

    vaddr = ioremap_cache(page_base, map_size);
    if (!vaddr)
        return -ENOMEM;

    memcpy(vaddr + offset, buf, len);
    iounmap(vaddr);
    return 0;
}

static long propedit_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct prop_write_args args;
    struct mm_struct *mm = current->mm;
    phys_addr_t pa;

    if (_IOC_TYPE(cmd) != PROP_IOC_MAGIC)
        return -ENOTTY;

    if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
        return -EFAULT;

    args.new_value[sizeof(args.new_value) - 1] = '\0';
    pr_info("propedit: writing to user address 0x%llx, value=%s\n",
            args.value_addr, args.new_value);

    if (!mm)
        return -EINVAL;

    pa = translate_linear_address(mm, args.value_addr);
    if (!pa) {
        pr_err("propedit: failed to translate address\n");
        return -EFAULT;
    }

    pr_info("propedit: physical address 0x%llx\n", (u64)pa);

    return write_physical_address(pa, args.new_value, strlen(args.new_value) + 1);
}

static const struct file_operations propedit_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = propedit_ioctl,
};

static struct miscdevice propedit_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &propedit_fops,
    .mode  = 0666,
};

static int __init propedit_init(void)
{
    int ret = misc_register(&propedit_dev);
    if (ret)
        pr_err("propedit: misc_register failed\n");
    else
        pr_info("propedit: loaded\n");
    return ret;
}

static void __exit propedit_exit(void)
{
    misc_deregister(&propedit_dev);
    pr_info("propedit: unloaded\n");
}

module_init(propedit_init);
module_exit(propedit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("systemnb");
MODULE_DESCRIPTION("Property editor using physical address write");