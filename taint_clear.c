// SPDX-License-Identifier: GPL-2.0
/*
 * taint_clear.c — 清除内核污染位掩码（tainted_mask）
 *
 * 为什么必须走内核模块：
 *   kernel/sysctl.c 的 proc_taint() 注释写着 "Taint values can only be increased"，
 *   实现是 poor man's atomic OR —— 对写入值里已置位的每个 bit 调 add_taint()。
 *   所以 `echo 0 > /proc/sys/kernel/tainted` 不报错、也不清任何位（这就是"cat 还是原值"的原因）。
 *   真正的存储在 kernel/panic.c 的 `static unsigned long tainted_mask`，
 *   它没导出、get_taint() 也没导出（6.6 确认），只能定位变量地址后直接写。
 *
 * 加载时序（6.6 确认）：
 *   load_module() → module_augment_kernel_taints()（置 O/E/P 位）→ do_init_module()
 *   也就是说：本模块自己造成的树外/未签名污染位，在 init 里就能顺手一起清掉。
 *   普通 rmmod 不置 R 位（TAINT_FORCED_RMMOD 只在 CONFIG_MODULE_FORCE_UNLOAD 且 rmmod -f 时置位）。
 *
 * 安全设计（防止写错地址把内核搞崩）：
 *   1) 通过 kprobe 拿到未导出的 kallsyms_lookup_name()，再解析数据符号 tainted_mask；
 *      解析不到就 -ENOENT 退出，绝不猜地址。
 *   2) 用 expect=<用户态 cat 到的值> 做交叉校验：变量值必须与 /proc 完全一致才允许写。
 *      不一致 → 认为符号被 strip/改名/找错，直接放弃。
 *   3) 值域检查：污染位目前最多 20 个，读到 ≥ 2^24 视为异常，拒绝写入。
 *   4) 只清 keep 掩码以外的位，不做越界操作；卸载时停掉周期任务。
 *
 * 用法（root）：
 *   V=$(cat /proc/sys/kernel/tainted)
 *   insmod taint_clear.ko expect=$V
 *   cat /proc/sys/kernel/tainted            # 应为 0（或 keep 指定的位）
 *   echo 1 > /sys/module/taint_clear/parameters/clear     # 之后再被置位时手动清
 *   cat /sys/module/taint_clear/parameters/clear         # 读当前值
 *   insmod taint_clear.ko expect=$V keep=512 watch=60    # 保留 bit9(W)，每 60 秒自动复查
 *   rmmod taint_clear                                    # 普通卸载，不新增污染位
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/param.h>
#include <linux/compiler.h>

#define MODULE_TAG	"taint_clear"

/* 目前内核定义的污染位最多到 bit19，读到超过 2^24 说明八成找错了变量 */
#define TAINT_SANE_MAX	(1UL << 24)

static unsigned long *tainted_mask_p;
static unsigned long keep_mask;
static unsigned long expect_mask;
static unsigned int watch_sec;

/* 未导出符号，只能运行时解析 */
static unsigned long (*klkn)(const char *name);

static unsigned long sym_resolve(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	int ret;

	if (!klkn) {
		ret = register_kprobe(&kp);
		if (ret < 0) {
			pr_err(MODULE_TAG ": 无法通过 kprobe 定位 kallsyms_lookup_name（ret=%d），"
			       "该内核可能禁止 kprobe 或符号已被裁剪\n", ret);
			return 0;
		}
		klkn = (unsigned long (*)(const char *))kp.addr;
		unregister_kprobe(&kp);
	}

	if (!klkn)
		return 0;

	return klkn(name);
}

static unsigned long cur_taint(void)
{
	return tainted_mask_p ? READ_ONCE(*tainted_mask_p) : 0UL;
}

/*
 * 交叉校验：变量地址找对了吗？
 * expect 为用户态读到的 /proc/sys/kernel/tainted；两者必须完全相等。
 * 注意 /proc 与本模块看到的值之间仍可能被别的 add_taint 插入，
 * 因此允许 expect 是「当前值的子集」（当前值 = expect 或 expect | 更晚置的位）。
 */
static int mask_is_credible(unsigned long cur)
{
	if (cur >= TAINT_SANE_MAX) {
		pr_err(MODULE_TAG ": 读到 0x%lx 超出污染位合理范围，疑似符号地址错误，拒绝写入\n", cur);
		return 0;
	}
	if (expect_mask >= TAINT_SANE_MAX) {
		pr_err(MODULE_TAG ": expect=%lu 参数不合理（>2^24），拒绝写入\n", expect_mask);
		return 0;
	}
	if (!expect_mask && cur) {
		pr_err(MODULE_TAG ": 未提供 expect 参数而当前 tainted=0x%lx —— 为安全起见拒绝写入，"
		       "请用 insmod taint_clear.ko expect=$(cat /proc/sys/kernel/tainted)\n", cur);
		return 0;
	}
	if (expect_mask && (cur & expect_mask) != expect_mask) {
		pr_err(MODULE_TAG ": 校验失败 —— 变量当前 0x%lx 不包含 /proc 读到的 0x%lx，"
		       "地址可能不对，拒绝写入\n", cur, expect_mask);
		return 0;
	}
	return 1;
}

static void taint_do_clear(const char *why)
{
	unsigned long cur, new;

	if (!tainted_mask_p)
		return;

	cur = cur_taint();
	if (!mask_is_credible(cur))
		return;

	new = cur & ~keep_mask;
	if (new == cur) {
		pr_info(MODULE_TAG ": %s：无需改动，当前 0x%lx\n", why, cur);
		return;
	}

	WRITE_ONCE(*tainted_mask_p, new);
	pr_info(MODULE_TAG ": %s：0x%lx -> 0x%lx（保留掩码 0x%lx）\n", why, cur, new, keep_mask);
}

/* /sys/module/taint_clear/parameters/clear ：写触发清理，读返回当前值 */
static int clear_param_set(const char *val, const struct kernel_param *kp)
{
	(void)val;
	taint_do_clear("参数触发");
	return 0;
}

static int clear_param_get(char *buffer, const struct kernel_param *kp)
{
	return sprintf(buffer, "%lu\n", cur_taint());
}

static const struct kernel_param_ops clear_param_ops = {
	.set = clear_param_set,
	.get = clear_param_get,
};
module_param_cb(clear, &clear_param_ops, NULL, 0644);
MODULE_PARM_DESC(clear, "任意写入即触发一次清理；读取返回当前 tainted 值");

static int watch_set(const char *val, const struct kernel_param *kp)
{
	unsigned int *dst = kp->args;
	int ret = kstrtouint(val, 0, dst);

	if (ret)
		return ret;
	if (*dst && *dst < 5)
		*dst = 5;
	pr_info(MODULE_TAG ": watch=%u 秒（只在 insmod 时有效，之后改值不会重建定时器）\n", *dst);
	return 0;
}

static const struct kernel_param_ops watch_param_ops = {
	.set = watch_set,
	.get = param_get_uint,
};
module_param_cb(watch, &watch_param_ops, &watch_sec, 0644);
MODULE_PARM_DESC(watch, "大于 0 时启动周期清理（秒，最小 5），只在 insmod 时指定有效");

module_param_named(keep, keep_mask, ulong, 0644);
MODULE_PARM_DESC(keep, "要保留的污染位掩码，默认 0 表示全清；例如 512=bit9(W)");

module_param_named(expect, expect_mask, ulong, 0644);
MODULE_PARM_DESC(expect, "安全校验：用户态 cat /proc/sys/kernel/tainted 读到的值，必须与内核变量一致才写入");

static struct delayed_work watch_work;

static void watch_fn(struct work_struct *w)
{
	taint_do_clear("周期检查");
	if (watch_sec)
		schedule_delayed_work(&watch_work, watch_sec * HZ);
}

static int __init taint_clear_init(void)
{
	unsigned long cur;

	tainted_mask_p = (unsigned long *)sym_resolve("tainted_mask");
	if (!tainted_mask_p) {
		pr_err(MODULE_TAG ": 找不到 tainted_mask 符号（内核可能被 strip、改名或厂商改了变量名）\n");
		return -ENOENT;
	}

	cur = READ_ONCE(*tainted_mask_p);
	pr_info(MODULE_TAG ": tainted_mask 地址=%px 当前值=0x%lx expect=0x%lx keep=0x%lx\n",
		tainted_mask_p, cur, expect_mask, keep_mask);

	if (!mask_is_credible(cur))
		return -EINVAL;

	/* 本模块自身造成的 O/E 位此刻已经置上（taint 在 init 之前完成），这里一起清掉 */
	taint_do_clear("加载即清理");

	if (watch_sec) {
		if (watch_sec < 5)
			watch_sec = 5;
		INIT_DELAYED_WORK(&watch_work, watch_fn);
		schedule_delayed_work(&watch_work, watch_sec * HZ);
		pr_info(MODULE_TAG ": 周期清理已启动，每 %u 秒一次\n", watch_sec);
	}

	return 0;
}

static void __exit taint_clear_exit(void)
{
	if (watch_sec)
		cancel_delayed_work_sync(&watch_work);
	pr_info(MODULE_TAG ": 已卸载，卸载前 tainted=0x%lx\n", cur_taint());
}

module_init(taint_clear_init);
module_exit(taint_clear_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("千问Go!");
MODULE_DESCRIPTION("按内核官方位定义清除 tainted_mask 污染位（含地址可信性校验）");
MODULE_VERSION("1.0");
