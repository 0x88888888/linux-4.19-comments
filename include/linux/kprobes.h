#ifndef _LINUX_KPROBES_H
#define _LINUX_KPROBES_H
/*
 *  Kernel Probes (KProbes)
 *  include/linux/kprobes.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2002, 2004
 *
 * 2002-Oct	Created by Vamsi Krishna S <vamsi_krishna@in.ibm.com> Kernel
 *		Probes initial implementation ( includes suggestions from
 *		Rusty Russell).
 * 2004-July	Suparna Bhattacharya <suparna@in.ibm.com> added jumper probes
 *		interface to access function arguments.
 * 2005-May	Hien Nguyen <hien@us.ibm.com> and Jim Keniston
 *		<jkenisto@us.ibm.com>  and Prasanna S Panchamukhi
 *		<prasanna@in.ibm.com> added function-return probes.
 */
#include <linux/compiler.h>
#include <linux/linkage.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/ftrace.h>
#include <asm/kprobes.h>

//有定义
#ifdef CONFIG_KPROBES

/* kprobe_status settings */
#define KPROBE_HIT_ACTIVE	0x00000001
#define KPROBE_HIT_SS		0x00000002
#define KPROBE_REENTER		0x00000004
#define KPROBE_HIT_SSDONE	0x00000008

#else /* CONFIG_KPROBES */
#include <asm-generic/kprobes.h>
typedef int kprobe_opcode_t;
struct arch_specific_insn {
	int dummy;
};
#endif /* CONFIG_KPROBES */

struct kprobe;
struct pt_regs;
struct kretprobe;
struct kretprobe_instance;
typedef int (*kprobe_pre_handler_t) (struct kprobe *, struct pt_regs *);
typedef void (*kprobe_post_handler_t) (struct kprobe *, struct pt_regs *,
				       unsigned long flags);
typedef int (*kprobe_fault_handler_t) (struct kprobe *, struct pt_regs *,
				       int trapnr);
typedef int (*kretprobe_handler_t) (struct kretprobe_instance *,
				    struct pt_regs *);

/*
 * jprobe在2017年 october的时候被abolish了
 */
struct kprobe {
	struct hlist_node hlist;

	/* list of kprobes for multi-handler support */
	struct list_head list;

	/*count the number of times this probe was temporarily disarmed */
	unsigned long nmissed;

	/* location of the probe point 
	 *
	 * addr为进程内的绝对虚拟地址
	 */
	kprobe_opcode_t *addr;

	/* Allow user to indicate symbol name of the probe point */
	const char *symbol_name;

	/* Offset into the symbol 
	 *
	 * offset 为距离symbol_name的距离offset
	 */
	unsigned int offset;

	/* Called before addr is executed. 
	 *
	 * 在 kprobe_int3_handler(), kprobe_ftrace_handler()中调用
	 */
	kprobe_pre_handler_t pre_handler;

	/* Called after addr is executed, unless...
	 *
	 * 在kprobe_debug_handler(),kprobe_ftrace_handler()
	 *   aggr_post_handler()中调用
	 */
	kprobe_post_handler_t post_handler;

	/*
	 * ... called if executing addr causes a fault (eg. page fault).
	 * Return 1 if it handled fault, otherwise kernel will see it.
	 *
	 * 在 kprobe_fault_handler()中调用
	 *
	 * 在执行pre_handler、post_handler或单步执行被探测指令时出现内存异常则会调用该回调函数；
	 */
	kprobe_fault_handler_t fault_handler;

	/* Saved opcode (which has been replaced with breakpoint) 
	 *
	 * 保存的被探测点原始指令
	 */
	kprobe_opcode_t opcode;

	/* copy of the original instruction 
	 *
	 * 被复制的被探测点的原始指令，用于单步执行，架构强相关（可能包含指令模拟函数）
	 */
	struct arch_specific_insn ainsn;

	/*
	 * Indicates various status flags.
	 * Protected by kprobe_mutex after this kprobe is registered.
	 *
	 * KPROBE_FLAG_GONE, KPROBE_FLAG_DISABLED
	 * KPROBE_FLAG_OPTIMIZED, KPROBE_FLAG_FTRACE
	 */
	u32 flags;
};

/* Kprobe status flags */
#define KPROBE_FLAG_GONE	1 /* breakpoint has already gone */
#define KPROBE_FLAG_DISABLED	2 /* probe is temporarily disabled */
#define KPROBE_FLAG_OPTIMIZED	4 /*
				   * probe is really optimized.
				   * NOTE:
				   * this flag is only for optimized_kprobe.
				   */
#define KPROBE_FLAG_FTRACE	8 /* probe is using ftrace */

/* Has this kprobe gone ? */
static inline int kprobe_gone(struct kprobe *p)
{
	return p->flags & KPROBE_FLAG_GONE;
}

/* Is this kprobe disabled ? */
static inline int kprobe_disabled(struct kprobe *p)
{
	return p->flags & (KPROBE_FLAG_DISABLED | KPROBE_FLAG_GONE);
}

/* Is this kprobe really running optimized path ? */
static inline int kprobe_optimized(struct kprobe *p)
{
	return p->flags & KPROBE_FLAG_OPTIMIZED;
}

/* Is this kprobe uses ftrace ? */
static inline int kprobe_ftrace(struct kprobe *p)
{
	return p->flags & KPROBE_FLAG_FTRACE;
}

/*
 * Function-return probe -
 * Note:
 * User needs to provide a handler function, and initialize maxactive.
 * maxactive - The maximum number of instances of the probed function that
 * can be active concurrently.
 * nmissed - tracks the number of times the probed function's return was
 * ignored, due to maxactive being too low.
 *
 *
 * 在arch_prepare_kretprobe()中设置被kprobe函数的返回地址为 kretprobe_trampoline,实现ret hook
 */
struct kretprobe {
	struct kprobe kp;
	/*
	 * handler在被探测函数返回后被调用
	 *
	 * 在trampoline_handler()中被调用
	 */
	kretprobe_handler_t handler;
	/*
	 * entry_handler会在被探测函数执行之前被调用
	 *
	 * 在pre_handler_kretprobe中被调用
	 */
	kretprobe_handler_t entry_handler;
	/*
	 * 同时支持并行探测的上限，因为kretprobe会跟踪一个函数从开始到结束，
	 * 因此对于一些调用比较频繁的被探测函数，在探测的时间段内重入的概率比较高，
	 * 这个maxactive字段值表示在重入情况发生时，
	 * 支持同时检测的进程数（执行流数）的上限，
	 * 若并行触发的数量超过了这个上限，则kretprobe不会进行跟踪探测，
	 * 仅仅增加nmissed字段的值以作提示
	 */
	int maxactive;
	int nmissed;
	size_t data_size;
	struct hlist_head free_instances;
	raw_spinlock_t lock;
};

/*
 * 被探测函数在跟踪期间可能存在并发执行的现象，
 * 因此kretprobe使用一个kretprobe_instance来跟踪一个执行流，
 * 支持的上限为maxactive。在没有触发探测时，
 * 所有的kretprobe_instance实例都保存在free_instances表中，
 * 每当有执行流触发一次kretprobe探测，
 * 都会从该表中取出一个空闲的kretprobe_instance实例用来跟踪
 */
struct kretprobe_instance {
	struct hlist_node hlist;
	struct kretprobe *rp;
	// 保存原始被探测函数的返回地址
	kprobe_opcode_t *ret_addr;
	//task用于绑定其跟踪的进程
	struct task_struct *task;
	char data[0];
};

struct kretprobe_blackpoint {
	const char *name;
	void *addr;
};

struct kprobe_blacklist_entry {
	struct list_head list;
	unsigned long start_addr;
	unsigned long end_addr;
};

//有定义
#ifdef CONFIG_KPROBES
DECLARE_PER_CPU(struct kprobe *, current_kprobe);
DECLARE_PER_CPU(struct kprobe_ctlblk, kprobe_ctlblk);

/*
 * For #ifdef avoidance:
 */
static inline int kprobes_built_in(void)
{
	return 1;
}

//有定义
#ifdef CONFIG_KRETPROBES
extern void arch_prepare_kretprobe(struct kretprobe_instance *ri,
				   struct pt_regs *regs);
extern int arch_trampoline_kprobe(struct kprobe *p);
#else /* CONFIG_KRETPROBES */
static inline void arch_prepare_kretprobe(struct kretprobe *rp,
					struct pt_regs *regs)
{
}
static inline int arch_trampoline_kprobe(struct kprobe *p)
{
	return 0;
}
#endif /* CONFIG_KRETPROBES */

extern struct kretprobe_blackpoint kretprobe_blacklist[];

static inline void kretprobe_assert(struct kretprobe_instance *ri,
	unsigned long orig_ret_address, unsigned long trampoline_address)
{
	if (!orig_ret_address || (orig_ret_address == trampoline_address)) {
		printk("kretprobe BUG!: Processing kretprobe %p @ %p\n",
				ri->rp, ri->rp->kp.addr);
		BUG();
	}
}

//没有定义
#ifdef CONFIG_KPROBES_SANITY_TEST
extern int init_test_probes(void);
#else
static inline int init_test_probes(void)
{
	return 0;
}
#endif /* CONFIG_KPROBES_SANITY_TEST */

extern int arch_prepare_kprobe(struct kprobe *p);
extern void arch_arm_kprobe(struct kprobe *p);
extern void arch_disarm_kprobe(struct kprobe *p);
extern int arch_init_kprobes(void);
extern void show_registers(struct pt_regs *regs);
extern void kprobes_inc_nmissed_count(struct kprobe *p);
extern bool arch_within_kprobe_blacklist(unsigned long addr);
extern bool arch_kprobe_on_func_entry(unsigned long offset);
extern bool kprobe_on_func_entry(kprobe_opcode_t *addr, const char *sym, unsigned long offset);

extern bool within_kprobe_blacklist(unsigned long addr);

struct kprobe_insn_cache {
	struct mutex mutex;
	void *(*alloc)(void);	/* allocate insn page */
	void (*free)(void *);	/* free insn page */
	struct list_head pages; /* list of kprobe_insn_page */
	size_t insn_size;	/* size of instruction slot */
	int nr_garbage;
};

//在include/asm/kprobes.h中有定义
#ifdef __ARCH_WANT_KPROBES_INSN_SLOT
extern kprobe_opcode_t *__get_insn_slot(struct kprobe_insn_cache *c);
extern void __free_insn_slot(struct kprobe_insn_cache *c,
			     kprobe_opcode_t *slot, int dirty);
/* sleep-less address checking routine  */
extern bool __is_insn_slot_addr(struct kprobe_insn_cache *c,
				unsigned long addr);

#define DEFINE_INSN_CACHE_OPS(__name)					\
extern struct kprobe_insn_cache kprobe_##__name##_slots;		\
									\
static inline kprobe_opcode_t *get_##__name##_slot(void)		\
{									\
	return __get_insn_slot(&kprobe_##__name##_slots);		\
}									\
									\
static inline void free_##__name##_slot(kprobe_opcode_t *slot, int dirty)\
{									\
	__free_insn_slot(&kprobe_##__name##_slots, slot, dirty);	\
}									\
									\
static inline bool is_kprobe_##__name##_slot(unsigned long addr)	\
{									\
	return __is_insn_slot_addr(&kprobe_##__name##_slots, addr);	\
}
#else /* __ARCH_WANT_KPROBES_INSN_SLOT */
#define DEFINE_INSN_CACHE_OPS(__name)					\
static inline bool is_kprobe_##__name##_slot(unsigned long addr)	\
{									\
	return 0;							\
}
#endif

DEFINE_INSN_CACHE_OPS(insn);

#ifdef CONFIG_OPTPROBES
/*
 * Internal structure for direct jump optimized probe
 */
struct optimized_kprobe {
	struct kprobe kp;
	struct list_head list;	/* list for optimizing queue */
	struct arch_optimized_insn optinsn;
};

/* Architecture dependent functions for direct jump optimization */
extern int arch_prepared_optinsn(struct arch_optimized_insn *optinsn);
extern int arch_check_optimized_kprobe(struct optimized_kprobe *op);
extern int arch_prepare_optimized_kprobe(struct optimized_kprobe *op,
					 struct kprobe *orig);
extern void arch_remove_optimized_kprobe(struct optimized_kprobe *op);
extern void arch_optimize_kprobes(struct list_head *oplist);
extern void arch_unoptimize_kprobes(struct list_head *oplist,
				    struct list_head *done_list);
extern void arch_unoptimize_kprobe(struct optimized_kprobe *op);
extern int arch_within_optimized_kprobe(struct optimized_kprobe *op,
					unsigned long addr);

extern void opt_pre_handler(struct kprobe *p, struct pt_regs *regs);

DEFINE_INSN_CACHE_OPS(optinsn);

#ifdef CONFIG_SYSCTL
extern int sysctl_kprobes_optimization;
extern int proc_kprobes_optimization_handler(struct ctl_table *table,
					     int write, void __user *buffer,
					     size_t *length, loff_t *ppos);
#endif
extern void wait_for_kprobe_optimizer(void);
#else
static inline void wait_for_kprobe_optimizer(void) { }
#endif /* CONFIG_OPTPROBES */
#ifdef CONFIG_KPROBES_ON_FTRACE
extern void kprobe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
				  struct ftrace_ops *ops, struct pt_regs *regs);
extern int arch_prepare_kprobe_ftrace(struct kprobe *p);
#endif

int arch_check_ftrace_location(struct kprobe *p);

/* Get the kprobe at this addr (if any) - called with preemption disabled */
struct kprobe *get_kprobe(void *addr);
void kretprobe_hash_lock(struct task_struct *tsk,
			 struct hlist_head **head, unsigned long *flags);
void kretprobe_hash_unlock(struct task_struct *tsk, unsigned long *flags);
struct hlist_head * kretprobe_inst_table_head(struct task_struct *tsk);

/* kprobe_running() will just return the current_kprobe on this CPU */
static inline struct kprobe *kprobe_running(void)
{
	return (__this_cpu_read(current_kprobe));
}

static inline void reset_current_kprobe(void)
{
	__this_cpu_write(current_kprobe, NULL);
}

/*
 * entry_64.S中掉用 do_int3()
 *  do_int3()
 *   kprobe_int3_handler()
 *    get_kprobe_ctlblk()
 */
static inline struct kprobe_ctlblk *get_kprobe_ctlblk(void)
{
	return this_cpu_ptr(&kprobe_ctlblk);
}

kprobe_opcode_t *kprobe_lookup_name(const char *name, unsigned int offset);
int register_kprobe(struct kprobe *p);
void unregister_kprobe(struct kprobe *p);
int register_kprobes(struct kprobe **kps, int num);
void unregister_kprobes(struct kprobe **kps, int num);
unsigned long arch_deref_entry_point(void *);

int register_kretprobe(struct kretprobe *rp);
void unregister_kretprobe(struct kretprobe *rp);
int register_kretprobes(struct kretprobe **rps, int num);
void unregister_kretprobes(struct kretprobe **rps, int num);

void kprobe_flush_task(struct task_struct *tk);
void recycle_rp_inst(struct kretprobe_instance *ri, struct hlist_head *head);

int disable_kprobe(struct kprobe *kp);
int enable_kprobe(struct kprobe *kp);

void dump_kprobe(struct kprobe *kp);

#else /* !CONFIG_KPROBES: */

static inline int kprobes_built_in(void)
{
	return 0;
}
static inline int kprobe_fault_handler(struct pt_regs *regs, int trapnr)
{
	return 0;
}
static inline struct kprobe *get_kprobe(void *addr)
{
	return NULL;
}
static inline struct kprobe *kprobe_running(void)
{
	return NULL;
}
static inline int register_kprobe(struct kprobe *p)
{
	return -ENOSYS;
}
static inline int register_kprobes(struct kprobe **kps, int num)
{
	return -ENOSYS;
}
static inline void unregister_kprobe(struct kprobe *p)
{
}
static inline void unregister_kprobes(struct kprobe **kps, int num)
{
}
static inline int register_kretprobe(struct kretprobe *rp)
{
	return -ENOSYS;
}
static inline int register_kretprobes(struct kretprobe **rps, int num)
{
	return -ENOSYS;
}
static inline void unregister_kretprobe(struct kretprobe *rp)
{
}
static inline void unregister_kretprobes(struct kretprobe **rps, int num)
{
}
static inline void kprobe_flush_task(struct task_struct *tk)
{
}
static inline int disable_kprobe(struct kprobe *kp)
{
	return -ENOSYS;
}
static inline int enable_kprobe(struct kprobe *kp)
{
	return -ENOSYS;
}
#endif /* CONFIG_KPROBES */
static inline int disable_kretprobe(struct kretprobe *rp)
{
	return disable_kprobe(&rp->kp);
}
static inline int enable_kretprobe(struct kretprobe *rp)
{
	return enable_kprobe(&rp->kp);
}

#ifndef CONFIG_KPROBES
static inline bool is_kprobe_insn_slot(unsigned long addr)
{
	return false;
}
#endif
#ifndef CONFIG_OPTPROBES
static inline bool is_kprobe_optinsn_slot(unsigned long addr)
{
	return false;
}
#endif

#endif /* _LINUX_KPROBES_H */
