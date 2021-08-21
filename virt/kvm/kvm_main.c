/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * kvm_dev_ioctl  控制VMM的 /dev/kvm 设备
 * kvm_vcpu_compat_ioctl  控制创建出来的vcpu
 * kvm_vm_compat_ioctl 控制创建出来的vm 
 * kvm_device_ioctl 
 *
 * 下面几个file_operations需要注意:
 * kvm_chardev_ops /dev/kvm 的操作
 * kvm_device_fops 虚拟设备的文件操作
 * kvm_vcpu_fops   vcpu层面的文件操作
 * kvm_vm_fops     虚拟机层面的文件操作
 * 
 * vhost_net_fops  /dev/vhost-net的操作
 */

#include <kvm/iodev.h>

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/reboot.h>
#include <linux/debugfs.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/syscore_ops.h>
#include <linux/cpu.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/sched/stat.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/anon_inodes.h>
#include <linux/profile.h>
#include <linux/kvm_para.h>
#include <linux/pagemap.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/compat.h>
#include <linux/srcu.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/bsearch.h>

#include <asm/processor.h>
#include <asm/io.h>
#include <asm/ioctl.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>

#include "coalesced_mmio.h"
#include "async_pf.h"
#include "vfio.h"

#define CREATE_TRACE_POINTS
#include <trace/events/kvm.h>

/* Worst case buffer size needed for holding an integer. */
#define ITOA_MAX_LEN 12

MODULE_AUTHOR("Qumranet");
MODULE_LICENSE("GPL");

/* Architectures should define their poll value according to the halt latency */
unsigned int halt_poll_ns = KVM_HALT_POLL_NS_DEFAULT;
module_param(halt_poll_ns, uint, 0644);
EXPORT_SYMBOL_GPL(halt_poll_ns);

/* Default doubles per-vcpu halt_poll_ns. */
unsigned int halt_poll_ns_grow = 2;
module_param(halt_poll_ns_grow, uint, 0644);
EXPORT_SYMBOL_GPL(halt_poll_ns_grow);

/* Default resets per-vcpu halt_poll_ns . */
unsigned int halt_poll_ns_shrink;
module_param(halt_poll_ns_shrink, uint, 0644);
EXPORT_SYMBOL_GPL(halt_poll_ns_shrink);

/*
 * Ordering of locks:
 *
 *	kvm->lock --> kvm->slots_lock --> kvm->irq_lock
 */

DEFINE_SPINLOCK(kvm_lock);
static DEFINE_RAW_SPINLOCK(kvm_count_lock);
LIST_HEAD(vm_list);

static cpumask_var_t cpus_hardware_enabled;
static int kvm_usage_count;
static atomic_t hardware_enable_failed;

//在kvm_init中创建
struct kmem_cache *kvm_vcpu_cache;
EXPORT_SYMBOL_GPL(kvm_vcpu_cache);

static __read_mostly struct preempt_ops kvm_preempt_ops;

// /sys/kernel/debug/kvm
struct dentry *kvm_debugfs_dir;
EXPORT_SYMBOL_GPL(kvm_debugfs_dir);

static int kvm_debugfs_num_entries;
static const struct file_operations *stat_fops_per_vm[];

static long kvm_vcpu_ioctl(struct file *file, unsigned int ioctl,
			   unsigned long arg);
#ifdef CONFIG_KVM_COMPAT
static long kvm_vcpu_compat_ioctl(struct file *file, unsigned int ioctl,
				  unsigned long arg);
#define KVM_COMPAT(c)	.compat_ioctl	= (c)
#else
static long kvm_no_compat_ioctl(struct file *file, unsigned int ioctl,
				unsigned long arg) { return -EINVAL; }
#define KVM_COMPAT(c)	.compat_ioctl	= kvm_no_compat_ioctl
#endif
static int hardware_enable_all(void);
static void hardware_disable_all(void);

static void kvm_io_bus_destroy(struct kvm_io_bus *bus);

static void mark_page_dirty_in_slot(struct kvm_memory_slot *memslot, gfn_t gfn);

__visible bool kvm_rebooting;
EXPORT_SYMBOL_GPL(kvm_rebooting);

static bool largepages_enabled = true;

#define KVM_EVENT_CREATE_VM 0
#define KVM_EVENT_DESTROY_VM 1
static void kvm_uevent_notify_change(unsigned int type, struct kvm *kvm);
static unsigned long long kvm_createvm_count;
static unsigned long long kvm_active_vms;

__weak int kvm_arch_mmu_notifier_invalidate_range(struct kvm *kvm,
		unsigned long start, unsigned long end, bool blockable)
{
	return 0;
}

bool kvm_is_reserved_pfn(kvm_pfn_t pfn)
{
	if (pfn_valid(pfn))
		return PageReserved(pfn_to_page(pfn));

	return true;
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 *
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_create_vcpu()
 *    kvm_arch_vcpu_setup()
 *     vcpu_load()
 */
void vcpu_load(struct kvm_vcpu *vcpu)
{
	int cpu = get_cpu();
	preempt_notifier_register(&vcpu->preempt_notifier);
	
	kvm_arch_vcpu_load(vcpu, cpu);
	put_cpu();
}
EXPORT_SYMBOL_GPL(vcpu_load);

void vcpu_put(struct kvm_vcpu *vcpu)
{
	preempt_disable();
	kvm_arch_vcpu_put(vcpu);
	preempt_notifier_unregister(&vcpu->preempt_notifier);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(vcpu_put);

/* TODO: merge with kvm_arch_vcpu_should_kick */
static bool kvm_request_needs_ipi(struct kvm_vcpu *vcpu, unsigned req)
{
	int mode = kvm_vcpu_exiting_guest_mode(vcpu);

	/*
	 * We need to wait for the VCPU to reenable interrupts and get out of
	 * READING_SHADOW_PAGE_TABLES mode.
	 */
	if (req & KVM_REQUEST_WAIT)
		return mode != OUTSIDE_GUEST_MODE;

	/*
	 * Need to kick a running VCPU, but otherwise there is nothing to do.
	 */
	return mode == IN_GUEST_MODE;
}

static void ack_flush(void *_completed)
{
}

static inline bool kvm_kick_many_cpus(const struct cpumask *cpus, bool wait)
{
	if (unlikely(!cpus))
		cpus = cpu_online_mask;

	if (cpumask_empty(cpus))
		return false;

	smp_call_function_many(cpus, ack_flush, NULL, wait);
	return true;
}

bool kvm_make_vcpus_request_mask(struct kvm *kvm, unsigned int req,
				 unsigned long *vcpu_bitmap, cpumask_var_t tmp)
{
	int i, cpu, me;
	struct kvm_vcpu *vcpu;
	bool called;

	me = get_cpu();

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!test_bit(i, vcpu_bitmap))
			continue;

		kvm_make_request(req, vcpu);
		cpu = vcpu->cpu;

		if (!(req & KVM_REQUEST_NO_WAKEUP) && kvm_vcpu_wake_up(vcpu))
			continue;

		if (tmp != NULL && cpu != -1 && cpu != me &&
		    kvm_request_needs_ipi(vcpu, req))
			__cpumask_set_cpu(cpu, tmp);
	}

	called = kvm_kick_many_cpus(tmp, !!(req & KVM_REQUEST_WAIT));
	put_cpu();

	return called;
}

/*
 * ioapic_mmio_write()
 *  ioapic_write_indirect()
 *   kvm_make_scan_ioapic_request()
 *    kvm_make_all_cpus_request(req=KVM_REQ_SCAN_IOAPIC)
 */
bool kvm_make_all_cpus_request(struct kvm *kvm, unsigned int req)
{
	cpumask_var_t cpus;
	bool called;
	static unsigned long vcpu_bitmap[BITS_TO_LONGS(KVM_MAX_VCPUS)]
		= {[0 ... BITS_TO_LONGS(KVM_MAX_VCPUS)-1] = ULONG_MAX};

	zalloc_cpumask_var(&cpus, GFP_ATOMIC);

	called = kvm_make_vcpus_request_mask(kvm, req, vcpu_bitmap, cpus);

	free_cpumask_var(cpus);
	return called;
}

#ifndef CONFIG_HAVE_KVM_ARCH_TLB_FLUSH_ALL
void kvm_flush_remote_tlbs(struct kvm *kvm)
{
	/*
	 * Read tlbs_dirty before setting KVM_REQ_TLB_FLUSH in
	 * kvm_make_all_cpus_request.
	 */
	long dirty_count = smp_load_acquire(&kvm->tlbs_dirty);

	/*
	 * We want to publish modifications to the page tables before reading
	 * mode. Pairs with a memory barrier in arch-specific code.
	 * - x86: smp_mb__after_srcu_read_unlock in vcpu_enter_guest
	 * and smp_mb in walk_shadow_page_lockless_begin/end.
	 * - powerpc: smp_mb in kvmppc_prepare_to_enter.
	 *
	 * There is already an smp_mb__after_atomic() before
	 * kvm_make_all_cpus_request() reads vcpu->mode. We reuse that
	 * barrier here.
	 */
	if (!kvm_arch_flush_remote_tlb(kvm)
	    || kvm_make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH))
		++kvm->stat.remote_tlb_flush;
	cmpxchg(&kvm->tlbs_dirty, dirty_count, 0);
}
EXPORT_SYMBOL_GPL(kvm_flush_remote_tlbs);
#endif

void kvm_reload_remote_mmus(struct kvm *kvm)
{
	kvm_make_all_cpus_request(kvm, KVM_REQ_MMU_RELOAD);
}

/*
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_create_vcpu()
 *    kvm_arch_vcpu_create()
 *     vmx_create_vcpu()
 *      kvm_vcpu_init()
 *
 * 将vcpu_vmx 和kvm关联起来,对vCPU的通用部分进行初始化
 */
int kvm_vcpu_init(struct kvm_vcpu *vcpu, struct kvm *kvm, unsigned id)
{
	struct page *page;
	int r;

	mutex_init(&vcpu->mutex);
	vcpu->cpu = -1;
	vcpu->kvm = kvm;
	vcpu->vcpu_id = id;
	vcpu->pid = NULL;
	init_swait_queue_head(&vcpu->wq);
	kvm_async_pf_vcpu_init(vcpu);

	vcpu->pre_pcpu = -1;
	INIT_LIST_HEAD(&vcpu->blocked_vcpu_list);

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		r = -ENOMEM;
		goto fail;
	}
	//设置好run这个page
	vcpu->run = page_address(page);

	kvm_vcpu_set_in_spin_loop(vcpu, false);
	kvm_vcpu_set_dy_eligible(vcpu, false);
	vcpu->preempted = false;

    //对体系结构相关的部分进行初始化
	r = kvm_arch_vcpu_init(vcpu);
	if (r < 0)
		goto fail_free_run;
	return 0;

fail_free_run:
	free_page((unsigned long)vcpu->run);
fail:
	return r;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_init);

void kvm_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	/*
	 * no need for rcu_read_lock as VCPU_RUN is the only place that
	 * will change the vcpu->pid pointer and on uninit all file
	 * descriptors are already gone.
	 */
	put_pid(rcu_dereference_protected(vcpu->pid, 1));
	kvm_arch_vcpu_uninit(vcpu);
	free_page((unsigned long)vcpu->run);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_uninit);

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
static inline struct kvm *mmu_notifier_to_kvm(struct mmu_notifier *mn)
{
	return container_of(mn, struct kvm, mmu_notifier);
}

static void kvm_mmu_notifier_change_pte(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long address,
					pte_t pte)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	kvm->mmu_notifier_seq++;
	kvm_set_spte_hva(kvm, address, pte);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static int kvm_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
						    struct mm_struct *mm,
						    unsigned long start,
						    unsigned long end,
						    bool blockable)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int need_tlb_flush = 0, idx;
	int ret;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	/*
	 * The count increase must become visible at unlock time as no
	 * spte can be established without taking the mmu_lock and
	 * count is also read inside the mmu_lock critical section.
	 */
	kvm->mmu_notifier_count++;
	need_tlb_flush = kvm_unmap_hva_range(kvm, start, end);
	need_tlb_flush |= kvm->tlbs_dirty;
	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);

	ret = kvm_arch_mmu_notifier_invalidate_range(kvm, start, end, blockable);

	srcu_read_unlock(&kvm->srcu, idx);

	return ret;
}

static void kvm_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);

	spin_lock(&kvm->mmu_lock);
	/*
	 * This sequence increase will notify the kvm page fault that
	 * the page that is going to be mapped in the spte could have
	 * been freed.
	 */
	kvm->mmu_notifier_seq++;
	smp_wmb();
	/*
	 * The above sequence increase must be visible before the
	 * below count decrease, which is ensured by the smp_wmb above
	 * in conjunction with the smp_rmb in mmu_notifier_retry().
	 */
	kvm->mmu_notifier_count--;
	spin_unlock(&kvm->mmu_lock);

	BUG_ON(kvm->mmu_notifier_count < 0);
}

static int kvm_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
					      struct mm_struct *mm,
					      unsigned long start,
					      unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	young = kvm_age_hva(kvm, start, end);
	if (young)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static int kvm_mmu_notifier_clear_young(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long start,
					unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	/*
	 * Even though we do not flush TLB, this will still adversely
	 * affect performance on pre-Haswell Intel EPT, where there is
	 * no EPT Access Bit to clear so that we have to tear down EPT
	 * tables instead. If we find this unacceptable, we can always
	 * add a parameter to kvm_age_hva so that it effectively doesn't
	 * do anything on clear_young.
	 *
	 * Also note that currently we never issue secondary TLB flushes
	 * from clear_young, leaving this job up to the regular system
	 * cadence. If we find this inaccurate, we might come up with a
	 * more sophisticated heuristic later.
	 */
	young = kvm_age_hva(kvm, start, end);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static int kvm_mmu_notifier_test_young(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	young = kvm_test_age_hva(kvm, address);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static void kvm_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	kvm_arch_flush_shadow_all(kvm);
	srcu_read_unlock(&kvm->srcu, idx);
}

static const struct mmu_notifier_ops kvm_mmu_notifier_ops = {
	.flags			= MMU_INVALIDATE_DOES_NOT_BLOCK,
	.invalidate_range_start	= kvm_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= kvm_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= kvm_mmu_notifier_clear_flush_young,
	.clear_young		= kvm_mmu_notifier_clear_young,
	.test_young		= kvm_mmu_notifier_test_young,
	.change_pte		= kvm_mmu_notifier_change_pte,
	.release		= kvm_mmu_notifier_release,
};

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	kvm->mmu_notifier.ops = &kvm_mmu_notifier_ops;
	return mmu_notifier_register(&kvm->mmu_notifier, current->mm);
}

#else  /* !(CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER) */

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	return 0;
}

#endif /* CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER */

static struct kvm_memslots *kvm_alloc_memslots(void)
{
	int i;
	struct kvm_memslots *slots;

	slots = kvzalloc(sizeof(struct kvm_memslots), GFP_KERNEL);
	if (!slots)
		return NULL;

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++)
		slots->id_to_index[i] = slots->memslots[i].id = i;

	return slots;
}

static void kvm_destroy_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	if (!memslot->dirty_bitmap)
		return;

	kvfree(memslot->dirty_bitmap);
	memslot->dirty_bitmap = NULL;
}

/*
 * Free any memory in @free but not in @dont.
 */
static void kvm_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free,
			      struct kvm_memory_slot *dont)
{
	if (!dont || free->dirty_bitmap != dont->dirty_bitmap)
		kvm_destroy_dirty_bitmap(free);

	kvm_arch_free_memslot(kvm, free, dont);

	free->npages = 0;
}

static void kvm_free_memslots(struct kvm *kvm, struct kvm_memslots *slots)
{
	struct kvm_memory_slot *memslot;

	if (!slots)
		return;

	kvm_for_each_memslot(memslot, slots)
		kvm_free_memslot(kvm, memslot, NULL);

	kvfree(slots);
}

static void kvm_destroy_vm_debugfs(struct kvm *kvm)
{
	int i;

	if (!kvm->debugfs_dentry)
		return;

	debugfs_remove_recursive(kvm->debugfs_dentry);

	if (kvm->debugfs_stat_data) {
		for (i = 0; i < kvm_debugfs_num_entries; i++)
			kfree(kvm->debugfs_stat_data[i]);
		kfree(kvm->debugfs_stat_data);
	}
}

/*
 * kvm_dev_ioctl()
 *  kvm_dev_ioctl_create_vm()
 *   kvm_create_vm_debugfs()
 * 
 */
static int kvm_create_vm_debugfs(struct kvm *kvm, int fd)
{
	char dir_name[ITOA_MAX_LEN * 2];
	struct kvm_stat_data *stat_data;
	struct kvm_stats_debugfs_item *p;

	if (!debugfs_initialized())
		return 0;

	snprintf(dir_name, sizeof(dir_name), "%d-%d", task_pid_nr(current), fd);
	// dir=sys/kernel/debug/kvm/%d-%d
	kvm->debugfs_dentry = debugfs_create_dir(dir_name, kvm_debugfs_dir);

	kvm->debugfs_stat_data = kcalloc(kvm_debugfs_num_entries,
					 sizeof(*kvm->debugfs_stat_data),
					 GFP_KERNEL);
	if (!kvm->debugfs_stat_data)
		return -ENOMEM;

	for (p = debugfs_entries; p->name; p++) {
		stat_data = kzalloc(sizeof(*stat_data), GFP_KERNEL);
		if (!stat_data)
			return -ENOMEM;

		stat_data->kvm = kvm;
		stat_data->offset = p->offset;
		kvm->debugfs_stat_data[p - debugfs_entries] = stat_data;
		//创建文件
		debugfs_create_file(p->name, 0644, kvm->debugfs_dentry,
				    stat_data, stat_fops_per_vm[p->kind]);
	}
	return 0;
}

/*
 * kvm_dev_ioctl()
 *  kvm_dev_ioctl_create_vm()
 *   kvm_create_vm()
 *
 * 创建vm
 */
static struct kvm *kvm_create_vm(unsigned long type)
{
	int r, i;

	//创建一个虚拟机对象
	struct kvm *kvm = kvm_arch_alloc_vm();

	if (!kvm)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&kvm->mmu_lock);
	mmgrab(current->mm);
	kvm->mm = current->mm;
	/*
	 * 初始化kvm->irqfds, kvm->ioeventfds
	 */
	kvm_eventfd_init(kvm);
	mutex_init(&kvm->lock);
	mutex_init(&kvm->irq_lock);
	mutex_init(&kvm->slots_lock);
	refcount_set(&kvm->users_count, 1);
	INIT_LIST_HEAD(&kvm->devices);

    /*
     * 初始化kvm->arch下面的成员
     */ 
	r = kvm_arch_init_vm(kvm, type);
	if (r)
		goto out_err_no_disable;

    //执行VMXON
	r = hardware_enable_all();
	if (r)
		goto out_err_no_disable;

#ifdef CONFIG_HAVE_KVM_IRQFD
	INIT_HLIST_HEAD(&kvm->irq_ack_notifier_list);
#endif

	BUILD_BUG_ON(KVM_MEM_SLOTS_NUM > SHRT_MAX);

	r = -ENOMEM;
	// 给虚拟机kvm分配kvm_memslots对象
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		struct kvm_memslots *slots = kvm_alloc_memslots();
		if (!slots)
			goto out_err_no_srcu;
		/*
		 * Generations must be different for each address space.
		 * Init kvm generation close to the maximum to easily test the
		 * code of handling generation number wrap-around.
		 */
		slots->generation = i * 2 - 150;
		rcu_assign_pointer(kvm->memslots[i], slots);
	}

	if (init_srcu_struct(&kvm->srcu))
		goto out_err_no_srcu;
	if (init_srcu_struct(&kvm->irq_srcu))
		goto out_err_no_irq_srcu;
	//给虚拟机kvm分配kvm_io_bus
	for (i = 0; i < KVM_NR_BUSES /* 4 */; i++) {
		rcu_assign_pointer(kvm->buses[i],
			kzalloc(sizeof(struct kvm_io_bus), GFP_KERNEL));
		if (!kvm->buses[i])
			goto out_err;
	}

    /*
     * kvm->mmu_notifier.ops == kvm_mmu_notifier_ops
     */
	r = kvm_init_mmu_notifier(kvm);
	if (r)
		goto out_err;

	spin_lock(&kvm_lock);
	list_add(&kvm->vm_list, &vm_list);
	spin_unlock(&kvm_lock);

	preempt_notifier_inc();

	return kvm;

out_err:
	cleanup_srcu_struct(&kvm->irq_srcu);
out_err_no_irq_srcu:
	cleanup_srcu_struct(&kvm->srcu);
out_err_no_srcu:
	hardware_disable_all();
out_err_no_disable:
	refcount_set(&kvm->users_count, 0);
	for (i = 0; i < KVM_NR_BUSES; i++)
		kfree(kvm_get_bus(kvm, i));
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++)
		kvm_free_memslots(kvm, __kvm_memslots(kvm, i));
	kvm_arch_free_vm(kvm);
	mmdrop(current->mm);
	return ERR_PTR(r);
}

static void kvm_destroy_devices(struct kvm *kvm)
{
	struct kvm_device *dev, *tmp;

	/*
	 * We do not need to take the kvm->lock here, because nobody else
	 * has a reference to the struct kvm at this point and therefore
	 * cannot access the devices list anyhow.
	 */
	list_for_each_entry_safe(dev, tmp, &kvm->devices, vm_node) {
		list_del(&dev->vm_node);
		dev->ops->destroy(dev);
	}
}

static void kvm_destroy_vm(struct kvm *kvm)
{
	int i;
	struct mm_struct *mm = kvm->mm;

	kvm_uevent_notify_change(KVM_EVENT_DESTROY_VM, kvm);
	kvm_destroy_vm_debugfs(kvm);
	kvm_arch_sync_events(kvm);
	spin_lock(&kvm_lock);
	list_del(&kvm->vm_list);
	spin_unlock(&kvm_lock);
	kvm_free_irq_routing(kvm);
	for (i = 0; i < KVM_NR_BUSES; i++) {
		struct kvm_io_bus *bus = kvm_get_bus(kvm, i);

		if (bus)
			kvm_io_bus_destroy(bus);
		kvm->buses[i] = NULL;
	}
	kvm_coalesced_mmio_free(kvm);
#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
	mmu_notifier_unregister(&kvm->mmu_notifier, kvm->mm);
#else
	kvm_arch_flush_shadow_all(kvm);
#endif
	kvm_arch_destroy_vm(kvm);
	kvm_destroy_devices(kvm);
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++)
		kvm_free_memslots(kvm, __kvm_memslots(kvm, i));
	cleanup_srcu_struct(&kvm->irq_srcu);
	cleanup_srcu_struct(&kvm->srcu);
	kvm_arch_free_vm(kvm);
	preempt_notifier_dec();
	hardware_disable_all();
	mmdrop(mm);
}

void kvm_get_kvm(struct kvm *kvm)
{
	refcount_inc(&kvm->users_count);
}
EXPORT_SYMBOL_GPL(kvm_get_kvm);

void kvm_put_kvm(struct kvm *kvm)
{
	if (refcount_dec_and_test(&kvm->users_count))
		kvm_destroy_vm(kvm);
}
EXPORT_SYMBOL_GPL(kvm_put_kvm);


static int kvm_vm_release(struct inode *inode, struct file *filp)
{
	struct kvm *kvm = filp->private_data;

	kvm_irqfd_release(kvm);

	kvm_put_kvm(kvm);
	return 0;
}

/*
 * Allocation size is twice as large as the actual dirty bitmap size.
 * See x86's kvm_vm_ioctl_get_dirty_log() why this is needed.
 *
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_set_memory_region()
 *    kvm_set_memory_region()
 *     __kvm_set_memory_region()
 *      kvm_create_dirty_bitmap()
 *
 * 创建modify log bitmap
 */
static int kvm_create_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	unsigned long dirty_bytes = 2 * kvm_dirty_bitmap_bytes(memslot);

	memslot->dirty_bitmap = kvzalloc(dirty_bytes, GFP_KERNEL);
	if (!memslot->dirty_bitmap)
		return -ENOMEM;

	return 0;
}

/*
 * Insert memslot and re-sort memslots based on their GFN,
 * so binary search could be used to lookup GFN.
 * Sorting algorithm takes advantage of having initially
 * sorted array and known changed memslot position.
 *
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_set_memory_region()
 *    kvm_set_memory_region()
 *     __kvm_set_memory_region()
 *      update_memslots()
 */
static void update_memslots(struct kvm_memslots *slots,
			    struct kvm_memory_slot *new)
{
	int id = new->id;
	int i = slots->id_to_index[id];
	struct kvm_memory_slot *mslots = slots->memslots;

	WARN_ON(mslots[i].id != id);
	if (!new->npages) {
		WARN_ON(!mslots[i].npages);
		if (mslots[i].npages)
			slots->used_slots--;
	} else {
		if (!mslots[i].npages)
			slots->used_slots++;
	}

    //根据base_gfn排序
	while (i < KVM_MEM_SLOTS_NUM - 1 &&
	       new->base_gfn <= mslots[i + 1].base_gfn) {
	       
		if (!mslots[i + 1].npages)
			break;
		mslots[i] = mslots[i + 1];
		slots->id_to_index[mslots[i].id] = i;
		i++;
	}

	/*
	 * The ">=" is needed when creating a slot with base_gfn == 0,
	 * so that it moves before all those with base_gfn == npages == 0.
	 *
	 * On the other hand, if new->npages is zero, the above loop has
	 * already left i pointing to the beginning of the empty part of
	 * mslots, and the ">=" would move the hole backwards in this
	 * case---which is wrong.  So skip the loop when deleting a slot.
	 */
	if (new->npages) {
		while (i > 0 &&
		       new->base_gfn >= mslots[i - 1].base_gfn) {
			mslots[i] = mslots[i - 1];
			slots->id_to_index[mslots[i].id] = i;
			i--;
		}
	} else
		WARN_ON_ONCE(i != slots->used_slots);

	mslots[i] = *new;
	slots->id_to_index[mslots[i].id] = i;
}

static int check_memory_region_flags(const struct kvm_userspace_memory_region *mem)
{
	u32 valid_flags = KVM_MEM_LOG_DIRTY_PAGES;

#ifdef __KVM_HAVE_READONLY_MEM
	valid_flags |= KVM_MEM_READONLY;
#endif

	if (mem->flags & ~valid_flags)
		return -EINVAL;

	return 0;
}

/*
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_set_memory_region()
 *    kvm_set_memory_region()
 *     __kvm_set_memory_region()
 *      install_new_memslots()
 */
static struct kvm_memslots *install_new_memslots(struct kvm *kvm,
		int as_id, struct kvm_memslots *slots)
{
	struct kvm_memslots *old_memslots = __kvm_memslots(kvm, as_id);

	/*
	 * Set the low bit in the generation, which disables SPTE caching
	 * until the end of synchronize_srcu_expedited.
	 */
	WARN_ON(old_memslots->generation & 1);
	slots->generation = old_memslots->generation + 1;

	rcu_assign_pointer(kvm->memslots[as_id], slots);
	synchronize_srcu_expedited(&kvm->srcu);

	/*
	 * Increment the new memslot generation a second time. This prevents
	 * vm exits that race with memslot updates from caching a memslot
	 * generation that will (potentially) be valid forever.
	 *
	 * Generations must be unique even across address spaces.  We do not need
	 * a global counter for that, instead the generation space is evenly split
	 * across address spaces.  For example, with two address spaces, address
	 * space 0 will use generations 0, 4, 8, ... while * address space 1 will
	 * use generations 2, 6, 10, 14, ...
	 */
	slots->generation += KVM_ADDRESS_SPACE_NUM * 2 - 1;

	kvm_arch_memslots_updated(kvm, slots);

	return old_memslots;
}

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding kvm->slots_lock for write.
 *
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_set_memory_region()
 *    kvm_set_memory_region()
 *     __kvm_set_memory_region()
 *
 * 做好guest os的物理内存地址与qemu进程 virtal address的对应关系的管理
 * 并没有分配任何的物理page，分配物理page要在ept异常中搞定
 *
 * 对用户态传过来的kvm_userspace_memory_region, 在kvm中进行相应 add, update,delete
 */
int __kvm_set_memory_region(struct kvm *kvm,
			    const struct kvm_userspace_memory_region *mem)
{
	int r;
	gfn_t base_gfn;
	unsigned long npages;
	struct kvm_memory_slot *slot;
	struct kvm_memory_slot old, new;
	struct kvm_memslots *slots = NULL, *old_memslots;
	int as_id, id;
	enum kvm_mr_change change;

	r = check_memory_region_flags(mem);
	if (r)
		goto out;

	r = -EINVAL;
	
    /*
     * slot的低16位是插槽号，往上是address space的id，
     * 将插槽号和地址空间id都取出来
     */
	as_id = mem->slot >> 16;
	id = (u16)mem->slot;

	/* General sanity checks */
	if (mem->memory_size & (PAGE_SIZE - 1)) //低12字节必须为0，也就是必须4k对齐
		goto out;
	
	if (mem->guest_phys_addr & (PAGE_SIZE - 1)) //和上面一个意思
		goto out;
	
	/* We can read the guest memory with __xxx_user() later on. */
	if ((id < KVM_USER_MEM_SLOTS) &&
	    ((mem->userspace_addr & (PAGE_SIZE - 1)) ||
	     !access_ok(VERIFY_WRITE,
			(void __user *)(unsigned long)mem->userspace_addr,
			mem->memory_size)))
		goto out;

    //address space id 和 slot id 只有一个超过最大值了
	if (as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_MEM_SLOTS_NUM)
		goto out;

	// mem->memory_size不能大过头，溢出了
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

    //从kvm->memslots[]中得到相应的slot
	slot = id_to_memslot(__kvm_memslots(kvm, as_id), id);

	//在guest os中的物理page number
	base_gfn = mem->guest_phys_addr >> PAGE_SHIFT;
	//要操作的page的数量
	npages = mem->memory_size >> PAGE_SHIFT;

	if (npages > KVM_MEM_MAX_NR_PAGES)
		goto out;

    //复制过来
	new = old = *slot;

	new.id = id;
	new.base_gfn = base_gfn;
	new.npages = npages;
	new.flags = mem->flags;

	if (npages) { //是新建或者修改了
 		if (!old.npages) //新建
			change = KVM_MR_CREATE;
		else { /*修改, Modify an existing slot. */
			if ((mem->userspace_addr != old.userspace_addr) ||
			    (npages != old.npages) ||
			    ((new.flags ^ old.flags) & KVM_MEM_READONLY))
				goto out;

			if (base_gfn != old.base_gfn)
				change = KVM_MR_MOVE;
			else if (new.flags != old.flags)
				change = KVM_MR_FLAGS_ONLY; //只是修改FLAG
			else { /* Nothing to change. */
				r = 0;
				goto out;
			}
		}
	} else { //是删除
		if (!old.npages)
			goto out;

		change = KVM_MR_DELETE;
		new.base_gfn = 0;
		new.flags = 0;
	}

    //创建
	if ((change == KVM_MR_CREATE) || (change == KVM_MR_MOVE)) {
		/* Check for overlaps 
		 * 下面的循环检查是否有overlap
	     */
		r = -EEXIST;
		//遍历kvm->memslots[as_id]
		kvm_for_each_memslot(slot, __kvm_memslots(kvm, as_id)) {
			if (slot->id == id)
				continue;
			if (!((base_gfn + npages <= slot->base_gfn) ||
			      (base_gfn >= slot->base_gfn + slot->npages)))
				goto out;//要操作的page范围不在slot管理的范围内，就返回吧
		}
	}

    //走到这里，说明没有找到对应的slot，需要新创建slots，分配slot
    
	/* Free page dirty bitmap if unneeded */
	if (!(new.flags & KVM_MEM_LOG_DIRTY_PAGES))
		new.dirty_bitmap = NULL;

	r = -ENOMEM;
	if (change == KVM_MR_CREATE) { //新建，需要相应的slots
		new.userspace_addr = mem->userspace_addr;

        /*
         * 设置new这个 kvm_memory_slot
         * 填写好slot->arch.rmap[]和slot->arch.lpage_info[]
         */
		if (kvm_arch_create_memslot(kvm, &new, npages))
			goto out_free;
	}

	/* Allocate page dirty bitmap if needed */
	//确定是否需要有modified log bitmap
	if ((new.flags & KVM_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap) {
		if (kvm_create_dirty_bitmap(&new) < 0)
			goto out_free;
	}

    //分配一个新的kvm_memslots出来
	slots = kvzalloc(sizeof(struct kvm_memslots), GFP_KERNEL);
	if (!slots)
		goto out_free;

	//复制一个slots过来
	memcpy(slots, __kvm_memslots(kvm, as_id), sizeof(struct kvm_memslots));

    //删除或者移动操作
	if ((change == KVM_MR_DELETE) || (change == KVM_MR_MOVE)) {
		slot = id_to_memslot(slots, id);
		slot->flags |= KVM_MEMSLOT_INVALID;

		old_memslots = install_new_memslots(kvm, as_id, slots);

		/* From this point no new shadow pages pointing to a deleted,
		 * or moved, memslot will be created.
		 *
		 * validation of sp->gfn happens in:
		 *	- gfn_to_hva (kvm_read_guest, gfn_to_pfn)
		 *	- kvm_is_visible_gfn (mmu_check_roots)
		 */
		kvm_arch_flush_shadow_memslot(kvm, slot);

		/*
		 * We can re-use the old_memslots from above, the only difference
		 * from the currently installed memslots is the invalid flag.  This
		 * will get overwritten by update_memslots anyway.
		 */
		slots = old_memslots;
	}

    //x86中为空函数
	r = kvm_arch_prepare_memory_region(kvm, &new, mem, change);
	if (r)
		goto out_slots;

	/* actual memory is freed via old in kvm_free_memslot below */
	if (change == KVM_MR_DELETE) {
		new.dirty_bitmap = NULL;
		memset(&new.arch, 0, sizeof(new.arch));
	}

    //将new插入到slots，并且排序
	update_memslots(slots, &new);

	//将slots放入到kvm->slots[as_id]
	old_memslots = install_new_memslots(kvm, as_id, slots);

    //计算出并且记录下kvm->arch.n_max_mmu_pages
	kvm_arch_commit_memory_region(kvm, mem, &old, &new, change);

    //释放掉old的东西
	kvm_free_memslot(kvm, &old, &new);
	kvfree(old_memslots);
	return 0;

out_slots:
	kvfree(slots);
out_free:
	kvm_free_memslot(kvm, &new, &old);
out:
	return r;
}
EXPORT_SYMBOL_GPL(__kvm_set_memory_region);

/*
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_set_memory_region()
 *    kvm_set_memory_region()
 *
 * 创建qemu虚拟内存与vm物理内存的映射关系
 */
int kvm_set_memory_region(struct kvm *kvm,
			  const struct kvm_userspace_memory_region *mem)
{
	int r;

	mutex_lock(&kvm->slots_lock);
	
	r = __kvm_set_memory_region(kvm, mem);
	mutex_unlock(&kvm->slots_lock);
	return r;
}
EXPORT_SYMBOL_GPL(kvm_set_memory_region);

/*
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_set_memory_region()
 * 
 * 创建qemu虚拟内存与vm物理内存的映射关系
 */
static int kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
					  struct kvm_userspace_memory_region *mem)
{
	if ((u16)mem->slot >= KVM_USER_MEM_SLOTS)
		return -EINVAL;

	return kvm_set_memory_region(kvm, mem);
}

int kvm_get_dirty_log(struct kvm *kvm,
			struct kvm_dirty_log *log, int *is_dirty)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int i, as_id, id;
	unsigned long n;
	unsigned long any = 0;

	as_id = log->slot >> 16;
	id = (u16)log->slot;
	if (as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_USER_MEM_SLOTS)
		return -EINVAL;

    //得到kvm->memslots[as_id]
	slots = __kvm_memslots(kvm, as_id);
	//从slots得到相应的slot
	memslot = id_to_memslot(slots, id);
	if (!memslot->dirty_bitmap)
		return -ENOENT;

	n = kvm_dirty_bitmap_bytes(memslot);

	for (i = 0; !any && i < n/sizeof(long); ++i)
		any = memslot->dirty_bitmap[i];

	if (copy_to_user(log->dirty_bitmap, memslot->dirty_bitmap, n))
		return -EFAULT;

	if (any)
		*is_dirty = 1;
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_get_dirty_log);

#ifdef CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT
/**
 *
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl_get_dirty_log()
 *   kvm_get_dirty_log_protect()
 *
 * kvm_get_dirty_log_protect - get a snapshot of dirty pages, and if any pages
 *	are dirty write protect them for next write.
 * @kvm:	pointer to kvm instance
 * @log:	slot id and address to which we copy the log
 * @is_dirty:	flag set if any page is dirty
 *
 * We need to keep it in mind that VCPU threads can write to the bitmap
 * concurrently. So, to avoid losing track of dirty pages we keep the
 * following order:
 *
 *    1. Take a snapshot of the bit and clear it if needed.
 *    2. Write protect the corresponding page.
 *    3. Copy the snapshot to the userspace.
 *    4. Upon return caller flushes TLB's if needed.
 *
 * Between 2 and 4, the guest may write to the page using the remaining TLB
 * entry.  This is not a problem because the page is reported dirty using
 * the snapshot taken before and step 4 ensures that writes done after
 * exiting to userspace will be logged for the next call.
 *
 */
int kvm_get_dirty_log_protect(struct kvm *kvm,
			struct kvm_dirty_log *log, bool *is_dirty)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int i, as_id, id;
	unsigned long n;
	unsigned long *dirty_bitmap;
	unsigned long *dirty_bitmap_buffer;

	as_id = log->slot >> 16;
	id = (u16)log->slot;
	if (as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_USER_MEM_SLOTS)
		return -EINVAL;

	slots = __kvm_memslots(kvm, as_id);
	memslot = id_to_memslot(slots, id);

	dirty_bitmap = memslot->dirty_bitmap;
	if (!dirty_bitmap)
		return -ENOENT;

    //需要的字节数量
	n = kvm_dirty_bitmap_bytes(memslot);

    //dirty_bitmap在分配的时候就分配了2倍的大小
	dirty_bitmap_buffer = kvm_second_dirty_bitmap(memslot);
	memset(dirty_bitmap_buffer, 0, n);

	spin_lock(&kvm->mmu_lock);
	*is_dirty = false;

	//每次处理sizeof(long)这么多
	for (i = 0; i < n / sizeof(long); i++) {
		unsigned long mask;
		gfn_t offset;

		if (!dirty_bitmap[i])//不dirty，就continue了
			continue;

		*is_dirty = true;

        //得到原本的long,并且清0，
		mask = xchg(&dirty_bitmap[i], 0);
		
		dirty_bitmap_buffer[i] = mask;

		if (mask) {
			offset = i * BITS_PER_LONG;
			kvm_arch_mmu_enable_log_dirty_pt_masked(kvm, memslot,
								offset, mask);
		}
	}

	spin_unlock(&kvm->mmu_lock);
	//复制到用户空间去
	if (copy_to_user(log->dirty_bitmap, dirty_bitmap_buffer, n))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_get_dirty_log_protect);
#endif

bool kvm_largepages_enabled(void)
{
	return largepages_enabled;
}

void kvm_disable_largepages(void)
{
	largepages_enabled = false;
}
EXPORT_SYMBOL_GPL(kvm_disable_largepages);

struct kvm_memory_slot *gfn_to_memslot(struct kvm *kvm, gfn_t gfn)
{
	return __gfn_to_memslot(kvm_memslots(kvm), gfn);
}
EXPORT_SYMBOL_GPL(gfn_to_memslot);

struct kvm_memory_slot *kvm_vcpu_gfn_to_memslot(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return __gfn_to_memslot(kvm_vcpu_memslots(vcpu), gfn);
}

bool kvm_is_visible_gfn(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot = gfn_to_memslot(kvm, gfn);

	if (!memslot || memslot->id >= KVM_USER_MEM_SLOTS ||
	      memslot->flags & KVM_MEMSLOT_INVALID)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(kvm_is_visible_gfn);

unsigned long kvm_host_page_size(struct kvm *kvm, gfn_t gfn)
{
	struct vm_area_struct *vma;
	unsigned long addr, size;

	size = PAGE_SIZE;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return PAGE_SIZE;

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, addr);
	if (!vma)
		goto out;

	size = vma_kernel_pagesize(vma);

out:
	up_read(&current->mm->mmap_sem);

	return size;
}

static bool memslot_is_readonly(struct kvm_memory_slot *slot)
{
	return slot->flags & KVM_MEM_READONLY;
}

/*
 * tdp_page_fault()
 *	try_async_pf() 
 *   __gfn_to_pfn_memslot(atomic==false)
 *    __gfn_to_hva_many()
 *
 * 从guest page frame number 转成 host 中qemu进程的 virtual page frame number
 */
static unsigned long __gfn_to_hva_many(struct kvm_memory_slot *slot, gfn_t gfn,
				       gfn_t *nr_pages, bool write)
{
    //根本就没有和qemu进程建立gpa到hva对应的映射管理关系
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return KVM_HVA_ERR_BAD;

    
	if (memslot_is_readonly(slot) && write)//权限矛盾了
		return KVM_HVA_ERR_RO_BAD;

	if (nr_pages)
		*nr_pages = slot->npages - (gfn - slot->base_gfn);

    //从guest page frame number 转成 host 中qemu进程的 virtual page frame number
	return __gfn_to_hva_memslot(slot, gfn);
}

static unsigned long gfn_to_hva_many(struct kvm_memory_slot *slot, gfn_t gfn,
				     gfn_t *nr_pages)
{
	return __gfn_to_hva_many(slot, gfn, nr_pages, true);
}

unsigned long gfn_to_hva_memslot(struct kvm_memory_slot *slot,
					gfn_t gfn)
{
	return gfn_to_hva_many(slot, gfn, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_hva_memslot);

unsigned long gfn_to_hva(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_hva_many(gfn_to_memslot(kvm, gfn), gfn, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_hva);

unsigned long kvm_vcpu_gfn_to_hva(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return gfn_to_hva_many(kvm_vcpu_gfn_to_memslot(vcpu, gfn), gfn, NULL);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_gfn_to_hva);

/*
 * If writable is set to false, the hva returned by this function is only
 * allowed to be read.
 */
unsigned long gfn_to_hva_memslot_prot(struct kvm_memory_slot *slot,
				      gfn_t gfn, bool *writable)
{
	unsigned long hva = __gfn_to_hva_many(slot, gfn, NULL, false);

	if (!kvm_is_error_hva(hva) && writable)
		*writable = !memslot_is_readonly(slot);

	return hva;
}

unsigned long gfn_to_hva_prot(struct kvm *kvm, gfn_t gfn, bool *writable)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	return gfn_to_hva_memslot_prot(slot, gfn, writable);
}

unsigned long kvm_vcpu_gfn_to_hva_prot(struct kvm_vcpu *vcpu, gfn_t gfn, bool *writable)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	return gfn_to_hva_memslot_prot(slot, gfn, writable);
}

static inline int check_user_page_hwpoison(unsigned long addr)
{
	int rc, flags = FOLL_HWPOISON | FOLL_WRITE;

	rc = get_user_pages(addr, 1, flags, NULL, NULL);
	return rc == -EHWPOISON;
}

/*
 * The fast path to get the writable pfn which will be stored in @pfn,
 * true indicates success, otherwise false is returned.  It's also the
 * only part that runs if we can are in atomic context.
 *
 * tdp_page_fault()
 *	try_async_pf() 
 *   __gfn_to_pfn_memslot()
 *    hva_to_pfn() 
 *     hva_to_pfn_fast()
 *
 * 已经在ept页表中分配好page的情况，直接更具hva获取pfn就是了
 */
static bool hva_to_pfn_fast(unsigned long addr, bool write_fault,
			    bool *writable, kvm_pfn_t *pfn)
{
	struct page *page[1];
	int npages;

	/*
	 * Fast pin a writable pfn only if it is a write fault request
	 * or the caller allows to map a writable pfn for a read fault
	 * request.
	 *
	 * 只能是写操作
	 */
	if (!(write_fault || writable))
		return false;

    //终于分配物理page了
	npages = __get_user_pages_fast(addr, 1, 1, page);
	if (npages == 1) {
		*pfn = page_to_pfn(page[0]);

		if (writable)
			*writable = true;
		return true;
	}

	return false;
}

/*
 * The slow path to get the pfn of the specified host virtual address,
 * 1 indicates success, -errno is returned if error is detected.
 *
 * tdp_page_fault()
 *	try_async_pf() 
 *   __gfn_to_pfn_memslot()
 *    hva_to_pfn()
 *     hva_to_pfn_slow()
 *
 * 在没有做好ept中page到hva映射的情况下，用这个来分配page，并且做好映射
 */
static int hva_to_pfn_slow(unsigned long addr, bool *async, bool write_fault,
			   bool *writable, kvm_pfn_t *pfn)
{
	unsigned int flags = FOLL_HWPOISON;
	struct page *page;
	int npages = 0;

	might_sleep();

	if (writable)
		*writable = write_fault;

	if (write_fault)
		flags |= FOLL_WRITE;
	if (async)
		flags |= FOLL_NOWAIT;

    //分配好物理page，并且做好映射
	npages = get_user_pages_unlocked(addr, 1, &page, flags);
	if (npages != 1)
		return npages;

	/* map read fault as writable if possible */
	if (unlikely(!write_fault) && writable) {
		struct page *wpage;

		if (__get_user_pages_fast(addr, 1, 1, &wpage) == 1) {
			*writable = true;
			put_page(page);
			page = wpage;
		}
	}
	*pfn = page_to_pfn(page);
	return npages;
}

static bool vma_is_valid(struct vm_area_struct *vma, bool write_fault)
{
	if (unlikely(!(vma->vm_flags & VM_READ)))
		return false;

	if (write_fault && (unlikely(!(vma->vm_flags & VM_WRITE))))
		return false;

	return true;
}

static int hva_to_pfn_remapped(struct vm_area_struct *vma,
			       unsigned long addr, bool *async,
			       bool write_fault, bool *writable,
			       kvm_pfn_t *p_pfn)
{
	unsigned long pfn;
	int r;

	r = follow_pfn(vma, addr, &pfn);
	if (r) {
		/*
		 * get_user_pages fails for VM_IO and VM_PFNMAP vmas and does
		 * not call the fault handler, so do it here.
		 */
		bool unlocked = false;
		r = fixup_user_fault(current, current->mm, addr,
				     (write_fault ? FAULT_FLAG_WRITE : 0),
				     &unlocked);
		if (unlocked)
			return -EAGAIN;
		if (r)
			return r;

		r = follow_pfn(vma, addr, &pfn);
		if (r)
			return r;

	}

	if (writable)
		*writable = true;

	/*
	 * Get a reference here because callers of *hva_to_pfn* and
	 * *gfn_to_pfn* ultimately call kvm_release_pfn_clean on the
	 * returned pfn.  This is only needed if the VMA has VM_MIXEDMAP
	 * set, but the kvm_get_pfn/kvm_release_pfn_clean pair will
	 * simply do nothing for reserved pfns.
	 *
	 * Whoever called remap_pfn_range is also going to call e.g.
	 * unmap_mapping_range before the underlying pages are freed,
	 * causing a call to our MMU notifier.
	 */ 
	kvm_get_pfn(pfn);

	*p_pfn = pfn;
	return 0;
}

/*
 * Pin guest page in memory and return its pfn.
 * @addr: host virtual address which maps memory to the guest
 * @atomic: whether this function can sleep
 * @async: whether this function need to wait IO complete if the
 *         host page is not in the memory
 * @write_fault: whether we should get a writable host page
 * @writable: whether it allows to map a writable host page for !@write_fault
 *
 * The function will map a writable host page for these two cases:
 * 1): @write_fault = true
 * 2): @write_fault = false && @writable, @writable will tell the caller
 *     whether the mapping is writable.
 *
 * tdp_page_fault()
 *	try_async_pf() 
 *   __gfn_to_pfn_memslot()
 *    hva_to_pfn()
 *
 * 从host qemu进程的virtual page frame number 转成 host 的 physical page frame number
 */
static kvm_pfn_t hva_to_pfn(unsigned long addr, bool atomic, bool *async,
			bool write_fault, bool *writable)
{
	struct vm_area_struct *vma;
	kvm_pfn_t pfn = 0;
	int npages, r;

	/* we can do it either atomically or asynchronously, not both */
	/*这里二者不能同时为真*/
	BUG_ON(atomic && async);

    /*已经在ept页表中分配好page的情况，直接根据hva获取pfn就是了*/
	if (hva_to_pfn_fast(addr, write_fault, writable, &pfn)) 
		return pfn;

	if (atomic)
		return KVM_PFN_ERR_FAULT;

    /*如果前面没有成功(也就是没有分配物理page)，则调用hva_to_pfn_slow*/
	npages = hva_to_pfn_slow(addr, async, write_fault, writable, &pfn); //查tlb缓存
	if (npages == 1)
		return pfn;

	down_read(&current->mm->mmap_sem);
	if (npages == -EHWPOISON ||
	      (!async && check_user_page_hwpoison(addr))) {
		pfn = KVM_PFN_ERR_HWPOISON;
		goto exit;
	}

retry:
	vma = find_vma_intersection(current->mm, addr, addr + 1);

	if (vma == NULL)
		pfn = KVM_PFN_ERR_FAULT;
	else if (vma->vm_flags & (VM_IO | VM_PFNMAP)) {
		r = hva_to_pfn_remapped(vma, addr, async, write_fault, writable, &pfn);
		if (r == -EAGAIN)
			goto retry;
		if (r < 0)
			pfn = KVM_PFN_ERR_FAULT;
		
	} else {
		if (async && vma_is_valid(vma, write_fault))
			*async = true;
		pfn = KVM_PFN_ERR_FAULT;
	}
exit:
	up_read(&current->mm->mmap_sem);
	return pfn;
}

/*
 * tdp_page_fault()
 *	try_async_pf() 
 *   __gfn_to_pfn_memslot(atomic==false)第一次调用
 */
kvm_pfn_t __gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn,
			       bool atomic, bool *async, bool write_fault,
			       bool *writable)
{
    //从gfn得到qemu对应的hva
	unsigned long addr = __gfn_to_hva_many(slot, gfn, NULL, write_fault);

	if (addr == KVM_HVA_ERR_RO_BAD) {//写操作不对了
		if (writable)
			*writable = false;
		return KVM_PFN_ERR_RO_FAULT;
	}

	if (kvm_is_error_hva(addr)) {
		if (writable)
			*writable = false;
		return KVM_PFN_NOSLOT;
	}

	/* Do not map writable pfn in the readonly memslot. */
	if (writable && memslot_is_readonly(slot)) {
		*writable = false;
		writable = NULL;
	}

    //从host qemu进程的virtual page frame number 转成 host 的 physical page frame number
	return hva_to_pfn(addr, atomic, async, write_fault,
			  writable);
}
EXPORT_SYMBOL_GPL(__gfn_to_pfn_memslot);

kvm_pfn_t gfn_to_pfn_prot(struct kvm *kvm, gfn_t gfn, bool write_fault,
		      bool *writable)
{
	return __gfn_to_pfn_memslot(gfn_to_memslot(kvm, gfn), gfn, false, NULL,
				    write_fault, writable);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_prot);

/*
 * gfn_to_pfn()
 *  gfn_to_pfn_memslot()
 */
kvm_pfn_t gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn)
{
	return __gfn_to_pfn_memslot(slot, gfn, false, NULL, true, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_memslot);

kvm_pfn_t gfn_to_pfn_memslot_atomic(struct kvm_memory_slot *slot, gfn_t gfn)
{
	return __gfn_to_pfn_memslot(slot, gfn, true, NULL, true, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_memslot_atomic);

kvm_pfn_t gfn_to_pfn_atomic(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_pfn_memslot_atomic(gfn_to_memslot(kvm, gfn), gfn);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_atomic);

kvm_pfn_t kvm_vcpu_gfn_to_pfn_atomic(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return gfn_to_pfn_memslot_atomic(kvm_vcpu_gfn_to_memslot(vcpu, gfn), gfn);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_gfn_to_pfn_atomic);

/*
 * guset page frame number 对应的memslot
 * 找到对应的host page frame number
 */

kvm_pfn_t gfn_to_pfn(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_pfn_memslot(gfn_to_memslot(kvm, gfn), gfn);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn);

kvm_pfn_t kvm_vcpu_gfn_to_pfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return gfn_to_pfn_memslot(kvm_vcpu_gfn_to_memslot(vcpu, gfn), gfn);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_gfn_to_pfn);

int gfn_to_page_many_atomic(struct kvm_memory_slot *slot, gfn_t gfn,
			    struct page **pages, int nr_pages)
{
	unsigned long addr;
	gfn_t entry = 0;

	addr = gfn_to_hva_many(slot, gfn, &entry);
	if (kvm_is_error_hva(addr))
		return -1;

	if (entry < nr_pages)
		return 0;

	return __get_user_pages_fast(addr, nr_pages, 1, pages);
}
EXPORT_SYMBOL_GPL(gfn_to_page_many_atomic);

static struct page *kvm_pfn_to_page(kvm_pfn_t pfn)
{
	if (is_error_noslot_pfn(pfn))
		return KVM_ERR_PTR_BAD_PAGE;

	if (kvm_is_reserved_pfn(pfn)) {
		WARN_ON(1);
		return KVM_ERR_PTR_BAD_PAGE;
	}

	return pfn_to_page(pfn);
}


struct page *gfn_to_page(struct kvm *kvm, gfn_t gfn)
{
	kvm_pfn_t pfn;

	pfn = gfn_to_pfn(kvm, gfn);

	return kvm_pfn_to_page(pfn);
}
EXPORT_SYMBOL_GPL(gfn_to_page);

struct page *kvm_vcpu_gfn_to_page(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	kvm_pfn_t pfn;

	pfn = kvm_vcpu_gfn_to_pfn(vcpu, gfn);

	return kvm_pfn_to_page(pfn);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_gfn_to_page);

void kvm_release_page_clean(struct page *page)
{
	WARN_ON(is_error_page(page));

	kvm_release_pfn_clean(page_to_pfn(page));
}
EXPORT_SYMBOL_GPL(kvm_release_page_clean);

void kvm_release_pfn_clean(kvm_pfn_t pfn)
{
	if (!is_error_noslot_pfn(pfn) && !kvm_is_reserved_pfn(pfn))
		put_page(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(kvm_release_pfn_clean);

void kvm_release_page_dirty(struct page *page)
{
	WARN_ON(is_error_page(page));

	kvm_release_pfn_dirty(page_to_pfn(page));
}
EXPORT_SYMBOL_GPL(kvm_release_page_dirty);

void kvm_release_pfn_dirty(kvm_pfn_t pfn)
{
	kvm_set_pfn_dirty(pfn);
	kvm_release_pfn_clean(pfn);
}
EXPORT_SYMBOL_GPL(kvm_release_pfn_dirty);

void kvm_set_pfn_dirty(kvm_pfn_t pfn)
{
	if (!kvm_is_reserved_pfn(pfn)) {
		struct page *page = pfn_to_page(pfn);

		if (!PageReserved(page))
			SetPageDirty(page);
	}
}
EXPORT_SYMBOL_GPL(kvm_set_pfn_dirty);

void kvm_set_pfn_accessed(kvm_pfn_t pfn)
{
	if (!kvm_is_reserved_pfn(pfn))
		mark_page_accessed(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(kvm_set_pfn_accessed);

void kvm_get_pfn(kvm_pfn_t pfn)
{
	if (!kvm_is_reserved_pfn(pfn))
		get_page(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(kvm_get_pfn);

static int next_segment(unsigned long len, int offset)
{
	if (len > PAGE_SIZE - offset)
		return PAGE_SIZE - offset;
	else
		return len;
}

static int __kvm_read_guest_page(struct kvm_memory_slot *slot, gfn_t gfn,
				 void *data, int offset, int len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva_memslot_prot(slot, gfn, NULL);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = __copy_from_user(data, (void __user *)addr + offset, len);
	if (r)
		return -EFAULT;
	return 0;
}

int kvm_read_guest_page(struct kvm *kvm, gfn_t gfn, void *data, int offset,
			int len)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	return __kvm_read_guest_page(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_read_guest_page);

int kvm_vcpu_read_guest_page(struct kvm_vcpu *vcpu, gfn_t gfn, void *data,
			     int offset, int len)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	return __kvm_read_guest_page(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_read_guest_page);

int kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_read_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_read_guest);

int kvm_vcpu_read_guest(struct kvm_vcpu *vcpu, gpa_t gpa, void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_vcpu_read_guest_page(vcpu, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_read_guest);

static int __kvm_read_guest_atomic(struct kvm_memory_slot *slot, gfn_t gfn,
			           void *data, int offset, unsigned long len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva_memslot_prot(slot, gfn, NULL);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	pagefault_disable();
	r = __copy_from_user_inatomic(data, (void __user *)addr + offset, len);
	pagefault_enable();
	if (r)
		return -EFAULT;
	return 0;
}

int kvm_read_guest_atomic(struct kvm *kvm, gpa_t gpa, void *data,
			  unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);
	int offset = offset_in_page(gpa);

	return __kvm_read_guest_atomic(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_read_guest_atomic);

int kvm_vcpu_read_guest_atomic(struct kvm_vcpu *vcpu, gpa_t gpa,
			       void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	int offset = offset_in_page(gpa);

	return __kvm_read_guest_atomic(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_read_guest_atomic);

static int __kvm_write_guest_page(struct kvm_memory_slot *memslot, gfn_t gfn,
			          const void *data, int offset, int len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva_memslot(memslot, gfn);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = __copy_to_user((void __user *)addr + offset, data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty_in_slot(memslot, gfn);
	return 0;
}

int kvm_write_guest_page(struct kvm *kvm, gfn_t gfn,
			 const void *data, int offset, int len)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	return __kvm_write_guest_page(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_write_guest_page);

int kvm_vcpu_write_guest_page(struct kvm_vcpu *vcpu, gfn_t gfn,
			      const void *data, int offset, int len)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	return __kvm_write_guest_page(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_write_guest_page);

int kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data,
		    unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_write_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_write_guest);

int kvm_vcpu_write_guest(struct kvm_vcpu *vcpu, gpa_t gpa, const void *data,
		         unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_vcpu_write_guest_page(vcpu, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_write_guest);

static int __kvm_gfn_to_hva_cache_init(struct kvm_memslots *slots,
				       struct gfn_to_hva_cache *ghc,
				       gpa_t gpa, unsigned long len)
{
	int offset = offset_in_page(gpa);
	gfn_t start_gfn = gpa >> PAGE_SHIFT;
	gfn_t end_gfn = (gpa + len - 1) >> PAGE_SHIFT;
	gfn_t nr_pages_needed = end_gfn - start_gfn + 1;
	gfn_t nr_pages_avail;

	ghc->gpa = gpa;
	ghc->generation = slots->generation;
	ghc->len = len;
	ghc->memslot = __gfn_to_memslot(slots, start_gfn);
	ghc->hva = gfn_to_hva_many(ghc->memslot, start_gfn, NULL);
	if (!kvm_is_error_hva(ghc->hva) && nr_pages_needed <= 1) {
		ghc->hva += offset;
	} else {
		/*
		 * If the requested region crosses two memslots, we still
		 * verify that the entire region is valid here.
		 */
		while (start_gfn <= end_gfn) {
			nr_pages_avail = 0;
			ghc->memslot = __gfn_to_memslot(slots, start_gfn);
			ghc->hva = gfn_to_hva_many(ghc->memslot, start_gfn,
						   &nr_pages_avail);
			if (kvm_is_error_hva(ghc->hva))
				return -EFAULT;
			start_gfn += nr_pages_avail;
		}
		/* Use the slow path for cross page reads and writes. */
		ghc->memslot = NULL;
	}
	return 0;
}

int kvm_gfn_to_hva_cache_init(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			      gpa_t gpa, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	return __kvm_gfn_to_hva_cache_init(slots, ghc, gpa, len);
}
EXPORT_SYMBOL_GPL(kvm_gfn_to_hva_cache_init);

int kvm_write_guest_offset_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, int offset, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int r;
	gpa_t gpa = ghc->gpa + offset;

	BUG_ON(len + offset > ghc->len);

	if (slots->generation != ghc->generation)
		__kvm_gfn_to_hva_cache_init(slots, ghc, ghc->gpa, ghc->len);

	if (unlikely(!ghc->memslot))
		return kvm_write_guest(kvm, gpa, data, len);

	if (kvm_is_error_hva(ghc->hva))
		return -EFAULT;

	r = __copy_to_user((void __user *)ghc->hva + offset, data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty_in_slot(ghc->memslot, gpa >> PAGE_SHIFT);

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_write_guest_offset_cached);

int kvm_write_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, unsigned long len)
{
	return kvm_write_guest_offset_cached(kvm, ghc, data, 0, len);
}
EXPORT_SYMBOL_GPL(kvm_write_guest_cached);

int kvm_read_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int r;

	BUG_ON(len > ghc->len);

	if (slots->generation != ghc->generation)
		__kvm_gfn_to_hva_cache_init(slots, ghc, ghc->gpa, ghc->len);

	if (unlikely(!ghc->memslot))
		return kvm_read_guest(kvm, ghc->gpa, data, len);

	if (kvm_is_error_hva(ghc->hva))
		return -EFAULT;

	r = __copy_from_user(data, (void __user *)ghc->hva, len);
	if (r)
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_read_guest_cached);

int kvm_clear_guest_page(struct kvm *kvm, gfn_t gfn, int offset, int len)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));

	return kvm_write_guest_page(kvm, gfn, zero_page, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_clear_guest_page);

int kvm_clear_guest(struct kvm *kvm, gpa_t gpa, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_clear_guest_page(kvm, gfn, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_clear_guest);

/*
 * vmx_handle_exit()
 *  vmx_flush_pml_buffer()
 *   kvm_vcpu_mark_page_dirty()
 *    mark_page_dirty_in_slot()
 */
static void mark_page_dirty_in_slot(struct kvm_memory_slot *memslot,
				    gfn_t gfn)
{
	if (memslot && memslot->dirty_bitmap) {
		unsigned long rel_gfn = gfn - memslot->base_gfn;

		set_bit_le(rel_gfn, memslot->dirty_bitmap);
	}
}

/*
 * x86不会调用到这个函数
 */
void mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	memslot = gfn_to_memslot(kvm, gfn);
	mark_page_dirty_in_slot(memslot, gfn);
}
EXPORT_SYMBOL_GPL(mark_page_dirty);

/*
 * vmx_handle_exit()
 *  vmx_flush_pml_buffer()
 *   kvm_vcpu_mark_page_dirty()
 */
void kvm_vcpu_mark_page_dirty(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	memslot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	mark_page_dirty_in_slot(memslot, gfn);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_mark_page_dirty);

void kvm_sigset_activate(struct kvm_vcpu *vcpu)
{
	if (!vcpu->sigset_active)
		return;

	/*
	 * This does a lockless modification of ->real_blocked, which is fine
	 * because, only current can change ->real_blocked and all readers of
	 * ->real_blocked don't care as long ->real_blocked is always a subset
	 * of ->blocked.
	 */
	sigprocmask(SIG_SETMASK, &vcpu->sigset, &current->real_blocked);
}

void kvm_sigset_deactivate(struct kvm_vcpu *vcpu)
{
	if (!vcpu->sigset_active)
		return;

	sigprocmask(SIG_SETMASK, &current->real_blocked, NULL);
	sigemptyset(&current->real_blocked);
}

static void grow_halt_poll_ns(struct kvm_vcpu *vcpu)
{
	unsigned int old, val, grow;

	old = val = vcpu->halt_poll_ns;
	grow = READ_ONCE(halt_poll_ns_grow);
	/* 10us base */
	if (val == 0 && grow)
		val = 10000;
	else
		val *= grow;

	if (val > halt_poll_ns)
		val = halt_poll_ns;

	vcpu->halt_poll_ns = val;
	trace_kvm_halt_poll_ns_grow(vcpu->vcpu_id, val, old);
}

static void shrink_halt_poll_ns(struct kvm_vcpu *vcpu)
{
	unsigned int old, val, shrink;

	old = val = vcpu->halt_poll_ns;
	shrink = READ_ONCE(halt_poll_ns_shrink);
	if (shrink == 0)
		val = 0;
	else
		val /= shrink;

	vcpu->halt_poll_ns = val;
	trace_kvm_halt_poll_ns_shrink(vcpu->vcpu_id, val, old);
}

static int kvm_vcpu_check_block(struct kvm_vcpu *vcpu)
{
	int ret = -EINTR;
	int idx = srcu_read_lock(&vcpu->kvm->srcu);

	if (kvm_arch_vcpu_runnable(vcpu)) {
		kvm_make_request(KVM_REQ_UNHALT, vcpu);
		goto out;
	}
	if (kvm_cpu_has_pending_timer(vcpu))
		goto out;
	if (signal_pending(current))
		goto out;

	ret = 0;
out:
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return ret;
}

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 *
 * kvm_vcpu_compat_ioctl()
 *  kvm_vcpu_ioctl()
 *   kvm_arch_vcpu_ioctl_run()
 *    kvm_vcpu_block()
 */
void kvm_vcpu_block(struct kvm_vcpu *vcpu)
{
	ktime_t start, cur;
	DECLARE_SWAITQUEUE(wait);
	bool waited = false;
	u64 block_ns;

	start = cur = ktime_get();
	if (vcpu->halt_poll_ns) {
		ktime_t stop = ktime_add_ns(ktime_get(), vcpu->halt_poll_ns);

		++vcpu->stat.halt_attempted_poll;
		do {
			/*
			 * This sets KVM_REQ_UNHALT if an interrupt
			 * arrives.
			 * halt状态被中断打断了
			 */
			if (kvm_vcpu_check_block(vcpu) < 0) { 
				++vcpu->stat.halt_successful_poll;
				if (!vcpu_valid_wakeup(vcpu))
					++vcpu->stat.halt_poll_invalid;
				goto out;
			}
			cur = ktime_get();
		} while (single_task_running() && ktime_before(cur, stop));
	}

	kvm_arch_vcpu_blocking(vcpu);

    //切换出去
	for (;;) {
		prepare_to_swait_exclusive(&vcpu->wq, &wait, TASK_INTERRUPTIBLE);

		if (kvm_vcpu_check_block(vcpu) < 0)
			break;

		waited = true;
		schedule();
	}

	finish_swait(&vcpu->wq, &wait);
	cur = ktime_get();

	kvm_arch_vcpu_unblocking(vcpu);
out:
	block_ns = ktime_to_ns(cur) - ktime_to_ns(start);

	if (!vcpu_valid_wakeup(vcpu))
		shrink_halt_poll_ns(vcpu);
	else if (halt_poll_ns) {
		
		if (block_ns <= vcpu->halt_poll_ns)
			;
		/* we had a long block, shrink polling */
		else if (vcpu->halt_poll_ns && block_ns > halt_poll_ns)
			shrink_halt_poll_ns(vcpu);//缩小halt时常
		/* we had a short halt and our poll time is too small */
		else if (vcpu->halt_poll_ns < halt_poll_ns &&
			block_ns < halt_poll_ns)
			grow_halt_poll_ns(vcpu); //增加halt时常
	} else
		vcpu->halt_poll_ns = 0;

	trace_kvm_vcpu_wakeup(block_ns, waited, vcpu_valid_wakeup(vcpu));
	kvm_arch_vcpu_block_finish(vcpu);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_block);

bool kvm_vcpu_wake_up(struct kvm_vcpu *vcpu)
{
	struct swait_queue_head *wqp;

	wqp = kvm_arch_vcpu_wq(vcpu);
	if (swq_has_sleeper(wqp)) {
		swake_up_one(wqp);
		++vcpu->stat.halt_wakeup;
		return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_wake_up);

#ifndef CONFIG_S390
/*
 * Kick a sleeping VCPU, or a guest VCPU in guest mode, into host kernel mode.
 *
 * 给vCPU发送一个ipi,到HOST中来
 *
 * 如果vcpu在休眠，就踢醒它,使其进入就绪队列，准备接受调度.
 * 如果vcpu运行在guest模式，则让它发生VM EXIT,到host中来
 */
void kvm_vcpu_kick(struct kvm_vcpu *vcpu)
{
	int me;
	int cpu = vcpu->cpu;

	if (kvm_vcpu_wake_up(vcpu))
		return;

	me = get_cpu();
	if (cpu != me && (unsigned)cpu < nr_cpu_ids && cpu_online(cpu))
		if (kvm_arch_vcpu_should_kick(vcpu))
			smp_send_reschedule(cpu);
		
	put_cpu();
}
EXPORT_SYMBOL_GPL(kvm_vcpu_kick);
#endif /* !CONFIG_S390 */

int kvm_vcpu_yield_to(struct kvm_vcpu *target)
{
	struct pid *pid;
	struct task_struct *task = NULL;
	int ret = 0;

	rcu_read_lock();
	pid = rcu_dereference(target->pid);
	if (pid)
		task = get_pid_task(pid, PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return ret;
	ret = yield_to(task, 1);
	put_task_struct(task);

	return ret;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_yield_to);

/*
 * Helper that checks whether a VCPU is eligible for directed yield.
 * Most eligible candidate to yield is decided by following heuristics:
 *
 *  (a) VCPU which has not done pl-exit or cpu relax intercepted recently
 *  (preempted lock holder), indicated by @in_spin_loop.
 *  Set at the beiginning and cleared at the end of interception/PLE handler.
 *
 *  (b) VCPU which has done pl-exit/ cpu relax intercepted but did not get
 *  chance last time (mostly it has become eligible now since we have probably
 *  yielded to lockholder in last iteration. This is done by toggling
 *  @dy_eligible each time a VCPU checked for eligibility.)
 *
 *  Yielding to a recently pl-exited/cpu relax intercepted VCPU before yielding
 *  to preempted lock-holder could result in wrong VCPU selection and CPU
 *  burning. Giving priority for a potential lock-holder increases lock
 *  progress.
 *
 *  Since algorithm is based on heuristics, accessing another VCPU data without
 *  locking does not harm. It may result in trying to yield to  same VCPU, fail
 *  and continue with next VCPU and so on.
 */
static bool kvm_vcpu_eligible_for_directed_yield(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT
	bool eligible;

	eligible = !vcpu->spin_loop.in_spin_loop ||
		    vcpu->spin_loop.dy_eligible;

	if (vcpu->spin_loop.in_spin_loop)
		kvm_vcpu_set_dy_eligible(vcpu, !vcpu->spin_loop.dy_eligible);

	return eligible;
#else
	return true;
#endif
}

void kvm_vcpu_on_spin(struct kvm_vcpu *me, bool yield_to_kernel_mode)
{
	struct kvm *kvm = me->kvm;
	struct kvm_vcpu *vcpu;
	int last_boosted_vcpu = me->kvm->last_boosted_vcpu;
	int yielded = 0;
	int try = 3;
	int pass;
	int i;

	kvm_vcpu_set_in_spin_loop(me, true);
	/*
	 * We boost the priority of a VCPU that is runnable but not
	 * currently running, because it got preempted by something
	 * else and called schedule in __vcpu_run.  Hopefully that
	 * VCPU is holding the lock that we need and will release it.
	 * We approximate round-robin by starting at the last boosted VCPU.
	 */
	for (pass = 0; pass < 2 && !yielded && try; pass++) {
		kvm_for_each_vcpu(i, vcpu, kvm) {
			if (!pass && i <= last_boosted_vcpu) {
				i = last_boosted_vcpu;
				continue;
			} else if (pass && i > last_boosted_vcpu)
				break;
			if (!READ_ONCE(vcpu->preempted))
				continue;
			if (vcpu == me)
				continue;
			if (swait_active(&vcpu->wq) && !kvm_arch_vcpu_runnable(vcpu))
				continue;
			if (yield_to_kernel_mode && !kvm_arch_vcpu_in_kernel(vcpu))
				continue;
			if (!kvm_vcpu_eligible_for_directed_yield(vcpu))
				continue;

			yielded = kvm_vcpu_yield_to(vcpu);
			if (yielded > 0) {
				kvm->last_boosted_vcpu = i;
				break;
			} else if (yielded < 0) {
				try--;
				if (!try)
					break;
			}
		}
	}
	kvm_vcpu_set_in_spin_loop(me, false);

	/* Ensure vcpu is not eligible during next spinloop */
	kvm_vcpu_set_dy_eligible(me, false);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_on_spin);

/*
 * qemu和KVM共享内存发生pagefault的时候,会调用这里
 */
static vm_fault_t kvm_vcpu_fault(struct vm_fault *vmf)
{
	struct kvm_vcpu *vcpu = vmf->vma->vm_file->private_data;
	struct page *page;

	//virt_to_page直接用pfn_to_page返回page

	if (vmf->pgoff == 0)
		page = virt_to_page(vcpu->run);
//有定义
#ifdef CONFIG_X86
	else if (vmf->pgoff == KVM_PIO_PAGE_OFFSET)
		page = virt_to_page(vcpu->arch.pio_data);
#endif
//有定义
#ifdef CONFIG_KVM_MMIO
	else if (vmf->pgoff == KVM_COALESCED_MMIO_PAGE_OFFSET)
		page = virt_to_page(vcpu->kvm->coalesced_mmio_ring);
#endif
	else
		return kvm_arch_vcpu_fault(vcpu, vmf);
	
	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct kvm_vcpu_vm_ops = {
	.fault = kvm_vcpu_fault,
};

/*
 * qemu的kvm_vcpu_fault会调用到这个函数
 */
static int kvm_vcpu_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &kvm_vcpu_vm_ops;
	return 0;
}

static int kvm_vcpu_release(struct inode *inode, struct file *filp)
{
	struct kvm_vcpu *vcpu = filp->private_data;

	debugfs_remove_recursive(vcpu->debugfs_dentry);
	kvm_put_kvm(vcpu->kvm);
	return 0;
}

static struct file_operations kvm_vcpu_fops = {
	.release        = kvm_vcpu_release,
	.unlocked_ioctl = kvm_vcpu_ioctl,
	.mmap           = kvm_vcpu_mmap,
	.llseek		= noop_llseek,
	KVM_COMPAT(kvm_vcpu_compat_ioctl),
};

/*
 * Allocates an inode for the vcpu.
 *
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_create_vcpu()
 *    create_vcpu_fd()
 */
static int create_vcpu_fd(struct kvm_vcpu *vcpu)
{
	char name[8 + 1 + ITOA_MAX_LEN + 1];

	snprintf(name, sizeof(name), "kvm-vcpu:%d", vcpu->vcpu_id);
	return anon_inode_getfd(name, &kvm_vcpu_fops, vcpu, O_RDWR | O_CLOEXEC);
}

/*
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_create_vcpu()
 *    kvm_create_vcpu_debugfs()
 */
static int kvm_create_vcpu_debugfs(struct kvm_vcpu *vcpu)
{
	char dir_name[ITOA_MAX_LEN * 2];
	int ret;

	if (!kvm_arch_has_vcpu_debugfs())
		return 0;

	if (!debugfs_initialized())
		return 0;

	snprintf(dir_name, sizeof(dir_name), "vcpu%d", vcpu->vcpu_id);
	vcpu->debugfs_dentry = debugfs_create_dir(dir_name,
								vcpu->kvm->debugfs_dentry);
	if (!vcpu->debugfs_dentry)
		return -ENOMEM;

	ret = kvm_arch_create_vcpu_debugfs(vcpu);
	if (ret < 0) {
		debugfs_remove_recursive(vcpu->debugfs_dentry);
		return ret;
	}

	return 0;
}

/*
 * Creates some virtual cpus.  Good luck creating more than one.
 *
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_vm_ioctl_create_vcpu()
 */
static int kvm_vm_ioctl_create_vcpu(struct kvm *kvm, u32 id)
{
	int r;
	struct kvm_vcpu *vcpu;

	if (id >= KVM_MAX_VCPU_ID)
		return -EINVAL;

	mutex_lock(&kvm->lock);
	
	if (kvm->created_vcpus == KVM_MAX_VCPUS) {//每个vm可以拥有的vcpu不能超额
		mutex_unlock(&kvm->lock);
		return -EINVAL;
	}

	kvm->created_vcpus++;
	mutex_unlock(&kvm->lock);

    /*
	 * 创建vCPU，设置tsc之类的
     * 
     */
	vcpu = kvm_arch_vcpu_create(kvm, id);
	if (IS_ERR(vcpu)) {
		r = PTR_ERR(vcpu);
		goto vcpu_decrement;
	}

	preempt_notifier_init(&vcpu->preempt_notifier, &kvm_preempt_ops);

    //根据ept的设置建立虚拟mmu, load vcpu
	r = kvm_arch_vcpu_setup(vcpu);
	if (r)
		goto vcpu_destroy;

    //  创建 /sys/kernel/debug/kvm/{pid-fd}/vcpu-{id}
	r = kvm_create_vcpu_debugfs(vcpu);
	if (r)
		goto vcpu_destroy;

	mutex_lock(&kvm->lock);
	
	if (kvm_get_vcpu_by_id(kvm, id)) {
		r = -EEXIST;
		goto unlock_vcpu_destroy;
	}

	BUG_ON(kvm->vcpus[atomic_read(&kvm->online_vcpus)]);

	/* Now it's all set up, let userspace reach it */
	kvm_get_kvm(kvm);

	//将vcpu和匿名inode关联起来，返回fd
	r = create_vcpu_fd(vcpu);
	if (r < 0) {
		kvm_put_kvm(kvm);
		goto unlock_vcpu_destroy;
	}

    //将vCPU放到VM中来
	kvm->vcpus[atomic_read(&kvm->online_vcpus)] = vcpu;

	/*
	 * Pairs with smp_rmb() in kvm_get_vcpu.  Write kvm->vcpus
	 * before kvm->online_vcpu's incremented value.
	 */
	smp_wmb();
	atomic_inc(&kvm->online_vcpus);

	mutex_unlock(&kvm->lock);
	kvm_arch_vcpu_postcreate(vcpu);
	return r;

unlock_vcpu_destroy:
	mutex_unlock(&kvm->lock);
	debugfs_remove_recursive(vcpu->debugfs_dentry);
vcpu_destroy:
	kvm_arch_vcpu_destroy(vcpu);
vcpu_decrement:
	mutex_lock(&kvm->lock);
	kvm->created_vcpus--;
	mutex_unlock(&kvm->lock);
	return r;
}

static int kvm_vcpu_ioctl_set_sigmask(struct kvm_vcpu *vcpu, sigset_t *sigset)
{
	if (sigset) {
		sigdelsetmask(sigset, sigmask(SIGKILL)|sigmask(SIGSTOP));
		vcpu->sigset_active = 1;
		vcpu->sigset = *sigset;
	} else
		vcpu->sigset_active = 0;
	return 0;
}

/*
 * kvm_vcpu_compat_ioctl()
 *  kvm_vcpu_ioctl()
 */ 
static long kvm_vcpu_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;
	struct kvm_fpu *fpu = NULL;
	struct kvm_sregs *kvm_sregs = NULL;

	if (vcpu->kvm->mm != current->mm)
		return -EIO;

	if (unlikely(_IOC_TYPE(ioctl) != KVMIO))
		return -EINVAL;

	/*
	 * Some architectures have vcpu ioctls that are asynchronous to vcpu
	 * execution; mutex_lock() would break them.
	 *
	 * x86跳过
	 */
	r = kvm_arch_vcpu_async_ioctl(filp, ioctl, arg);
	if (r != -ENOIOCTLCMD)
		return r;

	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;
	switch (ioctl) {
	case KVM_RUN: { //跑起vCPU
		struct pid *oldpid;
		r = -EINVAL;
		if (arg)
			goto out;
		oldpid = rcu_access_pointer(vcpu->pid);
		if (unlikely(oldpid != task_pid(current))) {
			/* The thread running this VCPU changed. */
			struct pid *newpid;

			r = kvm_arch_vcpu_run_pid_change(vcpu);
			if (r)
				break;

			newpid = get_task_pid(current, PIDTYPE_PID);
			rcu_assign_pointer(vcpu->pid, newpid);
			if (oldpid)
				synchronize_rcu();
			put_pid(oldpid);
		}
		//跑起
		r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
		trace_kvm_userspace_exit(vcpu->run->exit_reason, r);
		break;
	}
	case KVM_GET_REGS: { //获取vCPU的寄存器信息
		struct kvm_regs *kvm_regs;

		r = -ENOMEM;
		kvm_regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL);
		if (!kvm_regs)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_regs(vcpu, kvm_regs);
		if (r)
			goto out_free1;
		r = -EFAULT;
		//复制到用户空间去
		if (copy_to_user(argp, kvm_regs, sizeof(struct kvm_regs)))
			goto out_free1;
		r = 0;
out_free1:
		kfree(kvm_regs);
		break;
	}
	case KVM_SET_REGS: {//qemu在run kvm的vCPU之前，会调用这个
		struct kvm_regs *kvm_regs;

		r = -ENOMEM;
		kvm_regs = memdup_user(argp, sizeof(*kvm_regs));
		if (IS_ERR(kvm_regs)) {
			r = PTR_ERR(kvm_regs);
			goto out;
		}
		r = kvm_arch_vcpu_ioctl_set_regs(vcpu, kvm_regs);
		kfree(kvm_regs);
		break;
	}
	case KVM_GET_SREGS: {
		kvm_sregs = kzalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
		r = -ENOMEM;
		if (!kvm_sregs)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_sregs(vcpu, kvm_sregs);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, kvm_sregs, sizeof(struct kvm_sregs)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_SREGS: {//qemu在run kvm的vCPU之前，会调用这个
		kvm_sregs = memdup_user(argp, sizeof(*kvm_sregs));
		if (IS_ERR(kvm_sregs)) {
			r = PTR_ERR(kvm_sregs);
			kvm_sregs = NULL;
			goto out;
		}
		r = kvm_arch_vcpu_ioctl_set_sregs(vcpu, kvm_sregs);
		break;
	}
	case KVM_GET_MP_STATE: {
		struct kvm_mp_state mp_state;

		r = kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &mp_state);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &mp_state, sizeof(mp_state)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_MP_STATE: {
		struct kvm_mp_state mp_state;

		r = -EFAULT;
		if (copy_from_user(&mp_state, argp, sizeof(mp_state)))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &mp_state);
		break;
	}
	case KVM_TRANSLATE: { //将gva转成gpa
		struct kvm_translation tr;

		r = -EFAULT;
		if (copy_from_user(&tr, argp, sizeof(tr)))
			goto out;
		r = kvm_arch_vcpu_ioctl_translate(vcpu, &tr);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &tr, sizeof(tr)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_GUEST_DEBUG: {
		struct kvm_guest_debug dbg;

		r = -EFAULT;
		if (copy_from_user(&dbg, argp, sizeof(dbg)))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_guest_debug(vcpu, &dbg);
		break;
	}
	case KVM_SET_SIGNAL_MASK: { //给vCPU的线程设置signal
		struct kvm_signal_mask __user *sigmask_arg = argp;
		struct kvm_signal_mask kvm_sigmask;
		sigset_t sigset, *p;

		p = NULL;
		if (argp) {
			r = -EFAULT;
			if (copy_from_user(&kvm_sigmask, argp,
					   sizeof(kvm_sigmask)))
				goto out;
			r = -EINVAL;
			if (kvm_sigmask.len != sizeof(sigset))
				goto out;
			r = -EFAULT;
			if (copy_from_user(&sigset, sigmask_arg->sigset,
					   sizeof(sigset)))
				goto out;
			p = &sigset;
		}
		r = kvm_vcpu_ioctl_set_sigmask(vcpu, p);
		break;
	}
	case KVM_GET_FPU: {
		fpu = kzalloc(sizeof(struct kvm_fpu), GFP_KERNEL);
		r = -ENOMEM;
		if (!fpu)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_fpu(vcpu, fpu);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, fpu, sizeof(struct kvm_fpu)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_FPU: {
		fpu = memdup_user(argp, sizeof(*fpu));
		if (IS_ERR(fpu)) {
			r = PTR_ERR(fpu);
			fpu = NULL;
			goto out;
		}
		r = kvm_arch_vcpu_ioctl_set_fpu(vcpu, fpu);
		break;
	}
	default://这里还有很多
		r = kvm_arch_vcpu_ioctl(filp, ioctl, arg);
	}
out:
	mutex_unlock(&vcpu->mutex);
	kfree(fpu);
	kfree(kvm_sregs);
	return r;
}

//有定义
#ifdef CONFIG_KVM_COMPAT
static long kvm_vcpu_compat_ioctl(struct file *filp,
				  unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = compat_ptr(arg);
	int r;

	if (vcpu->kvm->mm != current->mm)
		return -EIO;

	switch (ioctl) {
	case KVM_SET_SIGNAL_MASK: {
		struct kvm_signal_mask __user *sigmask_arg = argp;
		struct kvm_signal_mask kvm_sigmask;
		sigset_t sigset;

		if (argp) {
			r = -EFAULT;
			if (copy_from_user(&kvm_sigmask, argp,
					   sizeof(kvm_sigmask)))
				goto out;
			r = -EINVAL;
			if (kvm_sigmask.len != sizeof(compat_sigset_t))
				goto out;
			r = -EFAULT;
			if (get_compat_sigset(&sigset, (void *)sigmask_arg->sigset))
				goto out;
			r = kvm_vcpu_ioctl_set_sigmask(vcpu, &sigset);
		} else
			r = kvm_vcpu_ioctl_set_sigmask(vcpu, NULL);
		break;
	}
	default:
		r = kvm_vcpu_ioctl(filp, ioctl, arg);
	}

out:
	return r;
}
#endif

static int kvm_device_ioctl_attr(struct kvm_device *dev,
				 int (*accessor)(struct kvm_device *dev,
						 struct kvm_device_attr *attr),
				 unsigned long arg)
{
	struct kvm_device_attr attr;

	if (!accessor)
		return -EPERM;

	if (copy_from_user(&attr, (void __user *)arg, sizeof(attr)))
		return -EFAULT;

	return accessor(dev, &attr);
}

static long kvm_device_ioctl(struct file *filp, unsigned int ioctl,
			     unsigned long arg)
{
	struct kvm_device *dev = filp->private_data;

	switch (ioctl) {
	case KVM_SET_DEVICE_ATTR:
		return kvm_device_ioctl_attr(dev, dev->ops->set_attr, arg);
	case KVM_GET_DEVICE_ATTR:
		return kvm_device_ioctl_attr(dev, dev->ops->get_attr, arg);
	case KVM_HAS_DEVICE_ATTR:
		return kvm_device_ioctl_attr(dev, dev->ops->has_attr, arg);
	default:
		if (dev->ops->ioctl)
			return dev->ops->ioctl(dev, ioctl, arg);

		return -ENOTTY;
	}
}

static int kvm_device_release(struct inode *inode, struct file *filp)
{
	struct kvm_device *dev = filp->private_data;
	struct kvm *kvm = dev->kvm;

	kvm_put_kvm(kvm);
	return 0;
}

static const struct file_operations kvm_device_fops = {
	.unlocked_ioctl = kvm_device_ioctl,
	.release = kvm_device_release,
	KVM_COMPAT(kvm_device_ioctl),
};

struct kvm_device *kvm_device_from_filp(struct file *filp)
{
	if (filp->f_op != &kvm_device_fops)
		return NULL;

	return filp->private_data;
}

/*
 * 似乎只有kvm_device_ops_table[KVM_DEV_TYPE_VFIO] == kvm_vfio_ops
 */
static struct kvm_device_ops *kvm_device_ops_table[KVM_DEV_TYPE_MAX] = {
//没有定义啊
#ifdef CONFIG_KVM_MPIC
	[KVM_DEV_TYPE_FSL_MPIC_20]	= &kvm_mpic_ops,
	[KVM_DEV_TYPE_FSL_MPIC_42]	= &kvm_mpic_ops,
#endif
};

/*
 * vmx_init()
 *  kvm_init(opaque==&vmx_x86_ops)
 *   kvm_vfio_ops_init()
 *    kvm_register_device_ops(ops=kvm_vfio_ops, KVM_DEV_TYPE_VFIO)
 *
 * x86只有kvm_vfio_ops_init这么一个地方调用到kvm_register_device_ops
 */
int kvm_register_device_ops(struct kvm_device_ops *ops, u32 type)
{
	if (type >= ARRAY_SIZE(kvm_device_ops_table))
		return -ENOSPC;

	if (kvm_device_ops_table[type] != NULL)
		return -EEXIST;

	kvm_device_ops_table[type] = ops;
	return 0;
}

void kvm_unregister_device_ops(u32 type)
{
	if (kvm_device_ops_table[type] != NULL)
		kvm_device_ops_table[type] = NULL;
}

/*
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_ioctl_create_device()
 *
 * 创建设备
 */
static int kvm_ioctl_create_device(struct kvm *kvm,
				   struct kvm_create_device *cd)
{
	struct kvm_device_ops *ops = NULL;
	struct kvm_device *dev;
	bool test = cd->flags & KVM_CREATE_DEVICE_TEST;
	int ret;

	if (cd->type >= ARRAY_SIZE(kvm_device_ops_table))
		return -ENODEV;

    // 
	ops = kvm_device_ops_table[cd->type];
	if (ops == NULL)
		return -ENODEV;

	if (test)
		return 0;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->ops = ops;
	dev->kvm = kvm;

	mutex_lock(&kvm->lock);
	// kvm_vfio_create
	ret = ops->create(dev, cd->type);
	if (ret < 0) {
		mutex_unlock(&kvm->lock);
		kfree(dev);
		return ret;
	}
	list_add(&dev->vm_node, &kvm->devices);
	mutex_unlock(&kvm->lock);

	if (ops->init)
		ops->init(dev);

	ret = anon_inode_getfd(ops->name, &kvm_device_fops, dev, O_RDWR | O_CLOEXEC);
	if (ret < 0) {
		mutex_lock(&kvm->lock);
		list_del(&dev->vm_node);
		mutex_unlock(&kvm->lock);
		ops->destroy(dev);
		return ret;
	}

	kvm_get_kvm(kvm);
	cd->fd = ret;
	return 0;
}

/* 
 * kvm_dev_ioctl()
 *  kvm_vm_ioctl_check_extension_generic()
 */
static long kvm_vm_ioctl_check_extension_generic(struct kvm *kvm, long arg)
{
	switch (arg) {
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
	case KVM_CAP_INTERNAL_ERROR_DATA:
		//有定义
#ifdef CONFIG_HAVE_KVM_MSI
	case KVM_CAP_SIGNAL_MSI:
#endif
#ifdef CONFIG_HAVE_KVM_IRQFD
	case KVM_CAP_IRQFD:
	case KVM_CAP_IRQFD_RESAMPLE:
#endif
	case KVM_CAP_IOEVENTFD_ANY_LENGTH:
	case KVM_CAP_CHECK_EXTENSION_VM:
		return 1;
#ifdef CONFIG_KVM_MMIO
	case KVM_CAP_COALESCED_MMIO:
		return KVM_COALESCED_MMIO_PAGE_OFFSET;
#endif
#ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
	case KVM_CAP_IRQ_ROUTING:
		return KVM_MAX_IRQ_ROUTES;
#endif
#if KVM_ADDRESS_SPACE_NUM > 1
	case KVM_CAP_MULTI_ADDRESS_SPACE:
		return KVM_ADDRESS_SPACE_NUM;
#endif
	case KVM_CAP_MAX_VCPU_ID:
		return KVM_MAX_VCPU_ID;
	default:
		break;
	}
	return kvm_vm_ioctl_check_extension(kvm, arg);
}

/*
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 */
static long kvm_vm_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;

	if (kvm->mm != current->mm)
		return -EIO;
	switch (ioctl) {
	case KVM_CREATE_VCPU://创建VCPU
		r = kvm_vm_ioctl_create_vcpu(kvm, arg);
		break;
	case KVM_SET_USER_MEMORY_REGION: {//创建qemu虚拟内存与vm物理内存的映射关系
		struct kvm_userspace_memory_region kvm_userspace_mem;

		r = -EFAULT;
		if (copy_from_user(&kvm_userspace_mem, argp,
						sizeof(kvm_userspace_mem)))
			goto out;

		r = kvm_vm_ioctl_set_memory_region(kvm, &kvm_userspace_mem);
		break;
	}
	case KVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;

		r = -EFAULT;
		if (copy_from_user(&log, argp, sizeof(log)))
			goto out;
		r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
		break;
	}
	//有定义
#ifdef CONFIG_KVM_MMIO
	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;

		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof(zone)))
			goto out;
		r = kvm_vm_ioctl_register_coalesced_mmio(kvm, &zone);
		break;
	}
	case KVM_UNREGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;

		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof(zone)))
			goto out;
		r = kvm_vm_ioctl_unregister_coalesced_mmio(kvm, &zone);
		break;
	}
#endif
	case KVM_IRQFD: { //irqfd 是用host主机通知vm的一种方式
		struct kvm_irqfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof(data)))
			goto out;
		r = kvm_irqfd(kvm, &data);
		break;
	}
	case KVM_IOEVENTFD: {//事件ioevent fd操作
	/*
	 * 这个命令字的功能是将一个eventfd绑定到一段客户机的地址空间，
	 * 这个空间可以是mmio，也可以是pio。当guest写这段地址空间时，
	 * 会触发EPT_MISCONFIGURATION缺页异常，
	 * KVM处理时如果发现这段地址落在了已注册的ioeventfd地址区间里，
	 * 会通过写关联eventfd通知qemu，从而节约一次内核态到用户态的切换开销
	 */
		struct kvm_ioeventfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof(data)))
			goto out;
		r = kvm_ioeventfd(kvm, &data);
		break;
	}
	//有定义
#ifdef CONFIG_HAVE_KVM_MSI 
	case KVM_SIGNAL_MSI: { // qemu 中kvm_irqchip_send_msi发起
		struct kvm_msi msi;

		r = -EFAULT;
		if (copy_from_user(&msi, argp, sizeof(msi)))
			goto out;
		r = kvm_send_userspace_msi(kvm, &msi);
		break;
	}
#endif
#ifdef __KVM_HAVE_IRQ_LINE
	case KVM_IRQ_LINE_STATUS:
	case KVM_IRQ_LINE: { //向VM(vCPU)注入中断
		struct kvm_irq_level irq_event;

		r = -EFAULT;
		if (copy_from_user(&irq_event, argp, sizeof(irq_event)))
			goto out;

		r = kvm_vm_ioctl_irq_line(kvm, &irq_event,
					ioctl == KVM_IRQ_LINE_STATUS);
		if (r)
			goto out;

		r = -EFAULT;
		if (ioctl == KVM_IRQ_LINE_STATUS) {
			if (copy_to_user(argp, &irq_event, sizeof(irq_event)))
				goto out;
		}

		r = 0;
		break;
	}
#endif

//有定义
#ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
	case KVM_SET_GSI_ROUTING: { //设置KVM中的IRQ ROUTING
		struct kvm_irq_routing routing;
		struct kvm_irq_routing __user *urouting;
		struct kvm_irq_routing_entry *entries = NULL;

		r = -EFAULT;
		if (copy_from_user(&routing, argp, sizeof(routing)))
			goto out;
		r = -EINVAL;
		
		if (!kvm_arch_can_set_irq_routing(kvm))
			goto out;
		
		if (routing.nr > KVM_MAX_IRQ_ROUTES)
			goto out;
		if (routing.flags)
			goto out;
		
		if (routing.nr) { //复制到内核中来
			r = -ENOMEM;
			entries = vmalloc(array_size(sizeof(*entries),
						     routing.nr));
			if (!entries)
				goto out;
			r = -EFAULT;
			urouting = argp;
			if (copy_from_user(entries, urouting->entries,
					   routing.nr * sizeof(*entries)))
				goto out_free_irq_routing;
		}
		//开始设置
		r = kvm_set_irq_routing(kvm, entries, routing.nr,
					routing.flags);
out_free_irq_routing:
		vfree(entries);
		break;
	}
#endif /* CONFIG_HAVE_KVM_IRQ_ROUTING */
	case KVM_CREATE_DEVICE: {//创建设备
		struct kvm_create_device cd;

		r = -EFAULT;
		if (copy_from_user(&cd, argp, sizeof(cd)))
			goto out;

		r = kvm_ioctl_create_device(kvm, &cd);
		if (r)
			goto out;

		r = -EFAULT;
		if (copy_to_user(argp, &cd, sizeof(cd)))
			goto out;

		r = 0;
		break;
	}
	case KVM_CHECK_EXTENSION:
		r = kvm_vm_ioctl_check_extension_generic(kvm, arg);
		break;
	default:
		r = kvm_arch_vm_ioctl(filp, ioctl, arg);
	}
out:
	return r;
}

#ifdef CONFIG_KVM_COMPAT
struct compat_kvm_dirty_log {
	__u32 slot;
	__u32 padding1;
	union {
		compat_uptr_t dirty_bitmap; /* one bit per page */
		__u64 padding2;
	};
};

/*
 * 控制VM的入口函数
 */
static long kvm_vm_compat_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	int r;

	if (kvm->mm != current->mm)
		return -EIO;
	switch (ioctl) {
	case KVM_GET_DIRTY_LOG: {//复制出kvm->memslots[]->dirty_bitmap
		struct compat_kvm_dirty_log compat_log;
		struct kvm_dirty_log log;

		if (copy_from_user(&compat_log, (void __user *)arg,
				   sizeof(compat_log)))
			return -EFAULT;
		log.slot	 = compat_log.slot;
		log.padding1	 = compat_log.padding1;
		log.padding2	 = compat_log.padding2;
		log.dirty_bitmap = compat_ptr(compat_log.dirty_bitmap);

		r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
		break;
	}
	default:
		r = kvm_vm_ioctl(filp, ioctl, arg);
	}
	return r;
}
#endif

static struct file_operations kvm_vm_fops = {
	.release        = kvm_vm_release,
	.unlocked_ioctl = kvm_vm_ioctl,
	.llseek		= noop_llseek,
	KVM_COMPAT(kvm_vm_compat_ioctl),
};

/*
 * kvm_dev_ioctl()
 *  kvm_dev_ioctl_create_vm()
 *
 * 创建vm
 */
static int kvm_dev_ioctl_create_vm(unsigned long type)
{
	int r;
	//kvm表示一个虚拟机对象
	struct kvm *kvm;
	struct file *file;

    //创建VM
	kvm = kvm_create_vm(type);
	if (IS_ERR(kvm))
		return PTR_ERR(kvm);
//有定义	
#ifdef CONFIG_KVM_MMIO
    //创建合并mmio的page
	r = kvm_coalesced_mmio_init(kvm);
	if (r < 0)
		goto put_kvm;
#endif

	r = get_unused_fd_flags(O_CLOEXEC);
	if (r < 0)
		goto put_kvm;

	file = anon_inode_getfile("kvm-vm", &kvm_vm_fops, kvm, O_RDWR);
	if (IS_ERR(file)) {
		put_unused_fd(r);
		r = PTR_ERR(file);
		goto put_kvm;
	}

	/*
	 * Don't call kvm_put_kvm anymore at this point; file->f_op is
	 * already set, with ->release() being kvm_vm_release().  In error
	 * cases it will be called by the final fput(file) and will take
	 * care of doing kvm_put_kvm(kvm).
	 *
	 * 在 /sys/kernel/debug/kvm/下创建一些目录和文件
	 */
	if (kvm_create_vm_debugfs(kvm, r) < 0) {
		put_unused_fd(r);
		fput(file);
		return -ENOMEM;
	}
	kvm_uevent_notify_change(KVM_EVENT_CREATE_VM, kvm);

	fd_install(r, file);
	return r;

put_kvm:
	kvm_put_kvm(kvm);
	return r;
}

/*
 * 字符设备文件/dev/kvm的操作
 */
static long kvm_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	long r = -EINVAL;

	switch (ioctl) {
	case KVM_GET_API_VERSION:
		if (arg)
			goto out;
		r = KVM_API_VERSION;
		break;
	case KVM_CREATE_VM://创建一个kvm对象
		r = kvm_dev_ioctl_create_vm(arg);
		break;
	case KVM_CHECK_EXTENSION:
		r = kvm_vm_ioctl_check_extension_generic(NULL, arg);
		break;
	case KVM_GET_VCPU_MMAP_SIZE: //返回QEMU和KVM共享内存的大小
		if (arg)
			goto out;
		r = PAGE_SIZE;     /* struct kvm_run */
#ifdef CONFIG_X86
		r += PAGE_SIZE;    /* pio data page */
#endif
#ifdef CONFIG_KVM_MMIO
		r += PAGE_SIZE;    /* coalesced mmio ring page */
#endif
		break;
	case KVM_TRACE_ENABLE:
	case KVM_TRACE_PAUSE:
	case KVM_TRACE_DISABLE:
		r = -EOPNOTSUPP;
		break;
	default: //这里有KVM_GETMSR_INDEX_LIST,KVM_GET_EMULATED_CPUID,KVM_X86_GET_MCE_CAP_SUPPORTED,KVM_GET_MSRS....
		return kvm_arch_dev_ioctl(filp, ioctl, arg);
	}
out:
	return r;
}

// 字符设备文件/dev/kvm的操作
static struct file_operations kvm_chardev_ops = {
	.unlocked_ioctl = kvm_dev_ioctl,
	.llseek		= noop_llseek,
	KVM_COMPAT(kvm_dev_ioctl),
};

// 设备 /dev/kvm
static struct miscdevice kvm_dev = {
	KVM_MINOR,
	"kvm",
	&kvm_chardev_ops,
};

/*
 * kvm_starting_cpu()
 *  hardware_enable_nolock()
 *
 * kvm_dev_ioctl()
 *  kvm_dev_ioctl_create_vm()
 *   kvm_create_vm()
 *    ...
 *     hardware_enable_nolock()
 */
static void hardware_enable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();
	int r;

	if (cpumask_test_cpu(cpu, cpus_hardware_enabled))
		return;

	cpumask_set_cpu(cpu, cpus_hardware_enabled);

	//设置vmxon
	r = kvm_arch_hardware_enable();

	if (r) {
		cpumask_clear_cpu(cpu, cpus_hardware_enabled);
		atomic_inc(&hardware_enable_failed);
		pr_info("kvm: enabling virtualization on CPU%d failed\n", cpu);
	}
}
/*
 * vmx_init()
 *  kvm_init(opaque==&vmx_x86_ops) vmx_x86_ops定义在vmx.c文件中
 *   cpuhp_setup_state_nocalls(CPUHP_AP_KVM_STARTING, "kvm/cpu:starting",
 *							  startup=kvm_starting_cpu, teardownkvm_dying_cpu)
 *    ......
 *     kvm_starting_cpu()
 */ 
static int kvm_starting_cpu(unsigned int cpu)
{
	raw_spin_lock(&kvm_count_lock);
	if (kvm_usage_count) //CR4.VMXE=ON, VMXON
		hardware_enable_nolock(NULL);
	
	raw_spin_unlock(&kvm_count_lock);
	return 0;
}

static void hardware_disable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();

	if (!cpumask_test_cpu(cpu, cpus_hardware_enabled))
		return;
	cpumask_clear_cpu(cpu, cpus_hardware_enabled);
	kvm_arch_hardware_disable();
}

static int kvm_dying_cpu(unsigned int cpu)
{
	raw_spin_lock(&kvm_count_lock);
	if (kvm_usage_count)
		hardware_disable_nolock(NULL);
	raw_spin_unlock(&kvm_count_lock);
	return 0;
}

static void hardware_disable_all_nolock(void)
{
	BUG_ON(!kvm_usage_count);

	kvm_usage_count--;
	if (!kvm_usage_count)
		on_each_cpu(hardware_disable_nolock, NULL, 1);
}

static void hardware_disable_all(void)
{
	raw_spin_lock(&kvm_count_lock);
	hardware_disable_all_nolock();
	raw_spin_unlock(&kvm_count_lock);
}

/*
 * kvm_dev_ioctl()
 *  kvm_dev_ioctl_create_vm()
 *   kvm_create_vm()
 *    hardware_enable_all()
 *
 * 所有的cpu都 vmxon
 */
static int hardware_enable_all(void)
{
	int r = 0;

	raw_spin_lock(&kvm_count_lock);

	kvm_usage_count++;
	if (kvm_usage_count == 1) {
		atomic_set(&hardware_enable_failed, 0);
		on_each_cpu(hardware_enable_nolock, NULL, 1);

		if (atomic_read(&hardware_enable_failed)) {
			hardware_disable_all_nolock();
			r = -EBUSY;
		}
	}

	raw_spin_unlock(&kvm_count_lock);

	return r;
}

static int kvm_reboot(struct notifier_block *notifier, unsigned long val,
		      void *v)
{
	/*
	 * Some (well, at least mine) BIOSes hang on reboot if
	 * in vmx root mode.
	 *
	 * And Intel TXT required VMX off for all cpu when system shutdown.
	 */
	pr_info("kvm: exiting hardware virtualization\n");
	kvm_rebooting = true;
	on_each_cpu(hardware_disable_nolock, NULL, 1);
	return NOTIFY_OK;
}

static struct notifier_block kvm_reboot_notifier = {
	.notifier_call = kvm_reboot,
	.priority = 0,
};

static void kvm_io_bus_destroy(struct kvm_io_bus *bus)
{
	int i;

	for (i = 0; i < bus->dev_count; i++) {
		struct kvm_io_device *pos = bus->range[i].dev;

		kvm_iodevice_destructor(pos);
	}
	kfree(bus);
}

static inline int kvm_io_bus_cmp(const struct kvm_io_range *r1,
				 const struct kvm_io_range *r2)
{
	gpa_t addr1 = r1->addr;
	gpa_t addr2 = r2->addr;

	if (addr1 < addr2)
		return -1;

	/* If r2->len == 0, match the exact address.  If r2->len != 0,
	 * accept any overlapping write.  Any order is acceptable for
	 * overlapping ranges, because kvm_io_bus_get_first_dev ensures
	 * we process all of them.
	 */
	if (r2->len) {
		addr1 += r1->len;
		addr2 += r2->len;
	}

	if (addr1 > addr2)
		return 1;

	return 0;
}

static int kvm_io_bus_sort_cmp(const void *p1, const void *p2)
{
	return kvm_io_bus_cmp(p1, p2);
}

static int kvm_io_bus_get_first_dev(struct kvm_io_bus *bus,
			     gpa_t addr, int len)
{
	struct kvm_io_range *range, key;
	int off;

	key = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	range = bsearch(&key, bus->range, bus->dev_count,
			sizeof(struct kvm_io_range), kvm_io_bus_sort_cmp);
	if (range == NULL)
		return -ENOENT;

	off = range - bus->range;

	while (off > 0 && kvm_io_bus_cmp(&key, &bus->range[off-1]) == 0)
		off--;

	return off;
}

/*
 * handle_io()
 *  ....
 *   kernel_pio()
 *    kvm_io_bus_write()
 *     __kvm_io_bus_write()
 *
 * handle_io()
 *  ...
 *   vcpu_mmio_write()
 *    kvm_io_bus_write()
 *     __kvm_io_bus_write()
 *
 */
static int __kvm_io_bus_write(struct kvm_vcpu *vcpu, struct kvm_io_bus *bus,
			      struct kvm_io_range *range, const void *val)
{
	int idx;

	idx = kvm_io_bus_get_first_dev(bus, range->addr, range->len);
	if (idx < 0)
		return -EOPNOTSUPP;

	while (idx < bus->dev_count &&
		kvm_io_bus_cmp(range, &bus->range[idx]) == 0) {//匹配上
		if (!kvm_iodevice_write(vcpu, bus->range[idx].dev, range->addr,
					range->len, val))
			return idx;
		idx++;
	}

	return -EOPNOTSUPP;
}

/*  
 *
 * handle_io()
 *  ....
 *   kernel_pio()
 *    kvm_io_bus_write()
 *
 * handle_io()
 *  ...
 *   vcpu_mmio_write()
 *    kvm_io_bus_write()
 *
 * kvm_io_bus_write - called under kvm->slots_lock .
 */
int kvm_io_bus_write(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx, gpa_t addr,
		     int len, const void *val)
{
	struct kvm_io_bus *bus;
	struct kvm_io_range range;
	int r;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(vcpu->kvm->buses[bus_idx], &vcpu->kvm->srcu);
	if (!bus)
		return -ENOMEM;
	r = __kvm_io_bus_write(vcpu, bus, &range, val);
	return r < 0 ? r : 0;
}

/* kvm_io_bus_write_cookie - called under kvm->slots_lock */
int kvm_io_bus_write_cookie(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx,
			    gpa_t addr, int len, const void *val, long cookie)
{
	struct kvm_io_bus *bus;
	struct kvm_io_range range;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(vcpu->kvm->buses[bus_idx], &vcpu->kvm->srcu);
	if (!bus)
		return -ENOMEM;

	/* First try the device referenced by cookie. */
	if ((cookie >= 0) && (cookie < bus->dev_count) &&
	    (kvm_io_bus_cmp(&range, &bus->range[cookie]) == 0))
		if (!kvm_iodevice_write(vcpu, bus->range[cookie].dev, addr, len,
					val))
			return cookie;

	/*
	 * cookie contained garbage; fall back to search and return the
	 * correct cookie value.
	 */
	return __kvm_io_bus_write(vcpu, bus, &range, val);
}

/*
 * kernel_pio()
 *  kvm_io_bus_read()
 *   __kvm_io_bus_read()
 */
static int __kvm_io_bus_read(struct kvm_vcpu *vcpu, struct kvm_io_bus *bus,
			     struct kvm_io_range *range, void *val)
{
	int idx;

	idx = kvm_io_bus_get_first_dev(bus, range->addr, range->len);
	if (idx < 0)
		return -EOPNOTSUPP;

	while (idx < bus->dev_count &&
		kvm_io_bus_cmp(range, &bus->range[idx]) == 0) {
		if (!kvm_iodevice_read(vcpu, bus->range[idx].dev, range->addr,
				       range->len, val))
			return idx;
		idx++;
	}

	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(kvm_io_bus_write);

/* kvm_io_bus_read - called under kvm->slots_lock 
 *
 * kernel_pio()
 *  kvm_io_bus_read()
 */
int kvm_io_bus_read(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx, gpa_t addr,
		    int len, void *val)
{
	struct kvm_io_bus *bus;
	struct kvm_io_range range;
	int r;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(vcpu->kvm->buses[bus_idx], &vcpu->kvm->srcu);
	if (!bus)
		return -ENOMEM;
	r = __kvm_io_bus_read(vcpu, bus, &range, val);
	return r < 0 ? r : 0;
}


/* Caller must hold slots_lock. 
 *
 * kvm_vm_compat_ioctl()
 *  kvm_vm_ioctl()
 *   kvm_ioeventfd()
 *    kvm_assign_ioeventfd()
 *     kvm_io_bus_register_dev()
 */
int kvm_io_bus_register_dev(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
			    int len, struct kvm_io_device *dev)
{
	int i;
	struct kvm_io_bus *new_bus, *bus;
	struct kvm_io_range range;

    //获取kvm->buses[bus_idx]
	bus = kvm_get_bus(kvm, bus_idx);
	if (!bus)
		return -ENOMEM;

	/* exclude ioeventfd which is limited by maximum fd */
	if (bus->dev_count - bus->ioeventfd_count > NR_IOBUS_DEVS - 1)
		return -ENOSPC;

	new_bus = kmalloc(sizeof(*bus) + ((bus->dev_count + 1) *
			  sizeof(struct kvm_io_range)), GFP_KERNEL);
	if (!new_bus)
		return -ENOMEM;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
		.dev = dev,
	};

	for (i = 0; i < bus->dev_count; i++)
		if (kvm_io_bus_cmp(&bus->range[i], &range) > 0)
			break;

    //将老的数据复制过来
	memcpy(new_bus, bus, sizeof(*bus) + i * sizeof(struct kvm_io_range));
	new_bus->dev_count++;
	new_bus->range[i] = range;
	//range填进去
	memcpy(new_bus->range + i + 1, bus->range + i,
		(bus->dev_count - i) * sizeof(struct kvm_io_range));

    //整个复制过来
	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
	kfree(bus);

	return 0;
}

/* Caller must hold slots_lock. */
void kvm_io_bus_unregister_dev(struct kvm *kvm, enum kvm_bus bus_idx,
			       struct kvm_io_device *dev)
{
	int i;
	struct kvm_io_bus *new_bus, *bus;

	bus = kvm_get_bus(kvm, bus_idx);
	if (!bus)
		return;

	for (i = 0; i < bus->dev_count; i++)
		if (bus->range[i].dev == dev) {
			break;
		}

	if (i == bus->dev_count)
		return;

	new_bus = kmalloc(sizeof(*bus) + ((bus->dev_count - 1) *
			  sizeof(struct kvm_io_range)), GFP_KERNEL);
	if (!new_bus)  {
		pr_err("kvm: failed to shrink bus, removing it completely\n");
		goto broken;
	}

	memcpy(new_bus, bus, sizeof(*bus) + i * sizeof(struct kvm_io_range));
	new_bus->dev_count--;
	memcpy(new_bus->range + i, bus->range + i + 1,
	       (new_bus->dev_count - i) * sizeof(struct kvm_io_range));

broken:
	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
	kfree(bus);
	return;
}

struct kvm_io_device *kvm_io_bus_get_dev(struct kvm *kvm, enum kvm_bus bus_idx,
					 gpa_t addr)
{
	struct kvm_io_bus *bus;
	int dev_idx, srcu_idx;
	struct kvm_io_device *iodev = NULL;

	srcu_idx = srcu_read_lock(&kvm->srcu);

	bus = srcu_dereference(kvm->buses[bus_idx], &kvm->srcu);
	if (!bus)
		goto out_unlock;

	dev_idx = kvm_io_bus_get_first_dev(bus, addr, 1);
	if (dev_idx < 0)
		goto out_unlock;

	iodev = bus->range[dev_idx].dev;

out_unlock:
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	return iodev;
}
EXPORT_SYMBOL_GPL(kvm_io_bus_get_dev);

static int kvm_debugfs_open(struct inode *inode, struct file *file,
			   int (*get)(void *, u64 *), int (*set)(void *, u64),
			   const char *fmt)
{
	struct kvm_stat_data *stat_data = (struct kvm_stat_data *)
					  inode->i_private;

	/* The debugfs files are a reference to the kvm struct which
	 * is still valid when kvm_destroy_vm is called.
	 * To avoid the race between open and the removal of the debugfs
	 * directory we test against the users count.
	 */
	if (!refcount_inc_not_zero(&stat_data->kvm->users_count))
		return -ENOENT;

	if (simple_attr_open(inode, file, get, set, fmt)) {
		kvm_put_kvm(stat_data->kvm);
		return -ENOMEM;
	}

	return 0;
}

static int kvm_debugfs_release(struct inode *inode, struct file *file)
{
	struct kvm_stat_data *stat_data = (struct kvm_stat_data *)
					  inode->i_private;

	simple_attr_release(inode, file);
	kvm_put_kvm(stat_data->kvm);

	return 0;
}

static int vm_stat_get_per_vm(void *data, u64 *val)
{
	struct kvm_stat_data *stat_data = (struct kvm_stat_data *)data;

	*val = *(ulong *)((void *)stat_data->kvm + stat_data->offset);

	return 0;
}

static int vm_stat_clear_per_vm(void *data, u64 val)
{
	struct kvm_stat_data *stat_data = (struct kvm_stat_data *)data;

	if (val)
		return -EINVAL;

	*(ulong *)((void *)stat_data->kvm + stat_data->offset) = 0;

	return 0;
}

static int vm_stat_get_per_vm_open(struct inode *inode, struct file *file)
{
	__simple_attr_check_format("%llu\n", 0ull);
	return kvm_debugfs_open(inode, file, vm_stat_get_per_vm,
				vm_stat_clear_per_vm, "%llu\n");
}

static const struct file_operations vm_stat_get_per_vm_fops = {
	.owner   = THIS_MODULE,
	.open    = vm_stat_get_per_vm_open,
	.release = kvm_debugfs_release,
	.read    = simple_attr_read,
	.write   = simple_attr_write,
	.llseek  = no_llseek,
};

static int vcpu_stat_get_per_vm(void *data, u64 *val)
{
	int i;
	struct kvm_stat_data *stat_data = (struct kvm_stat_data *)data;
	struct kvm_vcpu *vcpu;

	*val = 0;

	kvm_for_each_vcpu(i, vcpu, stat_data->kvm)
		*val += *(u64 *)((void *)vcpu + stat_data->offset);

	return 0;
}

static int vcpu_stat_clear_per_vm(void *data, u64 val)
{
	int i;
	struct kvm_stat_data *stat_data = (struct kvm_stat_data *)data;
	struct kvm_vcpu *vcpu;

	if (val)
		return -EINVAL;

	kvm_for_each_vcpu(i, vcpu, stat_data->kvm)
		*(u64 *)((void *)vcpu + stat_data->offset) = 0;

	return 0;
}

static int vcpu_stat_get_per_vm_open(struct inode *inode, struct file *file)
{
	__simple_attr_check_format("%llu\n", 0ull);
	return kvm_debugfs_open(inode, file, vcpu_stat_get_per_vm,
				 vcpu_stat_clear_per_vm, "%llu\n");
}

static const struct file_operations vcpu_stat_get_per_vm_fops = {
	.owner   = THIS_MODULE,
	.open    = vcpu_stat_get_per_vm_open,
	.release = kvm_debugfs_release,
	.read    = simple_attr_read,
	.write   = simple_attr_write,
	.llseek  = no_llseek,
};

static const struct file_operations *stat_fops_per_vm[] = {
	[KVM_STAT_VCPU] = &vcpu_stat_get_per_vm_fops,
	[KVM_STAT_VM]   = &vm_stat_get_per_vm_fops,
};

static int vm_stat_get(void *_offset, u64 *val)
{
	unsigned offset = (long)_offset;
	struct kvm *kvm;
	struct kvm_stat_data stat_tmp = {.offset = offset};
	u64 tmp_val;

	*val = 0;
	spin_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list) {
		stat_tmp.kvm = kvm;
		vm_stat_get_per_vm((void *)&stat_tmp, &tmp_val);
		*val += tmp_val;
	}
	spin_unlock(&kvm_lock);
	return 0;
}

static int vm_stat_clear(void *_offset, u64 val)
{
	unsigned offset = (long)_offset;
	struct kvm *kvm;
	struct kvm_stat_data stat_tmp = {.offset = offset};

	if (val)
		return -EINVAL;

	spin_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list) {
		stat_tmp.kvm = kvm;
		vm_stat_clear_per_vm((void *)&stat_tmp, 0);
	}
	spin_unlock(&kvm_lock);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(vm_stat_fops, vm_stat_get, vm_stat_clear, "%llu\n");

static int vcpu_stat_get(void *_offset, u64 *val)
{
	unsigned offset = (long)_offset;
	struct kvm *kvm;
	struct kvm_stat_data stat_tmp = {.offset = offset};
	u64 tmp_val;

	*val = 0;
	spin_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list) {
		stat_tmp.kvm = kvm;
		vcpu_stat_get_per_vm((void *)&stat_tmp, &tmp_val);
		*val += tmp_val;
	}
	spin_unlock(&kvm_lock);
	return 0;
}

static int vcpu_stat_clear(void *_offset, u64 val)
{
	unsigned offset = (long)_offset;
	struct kvm *kvm;
	struct kvm_stat_data stat_tmp = {.offset = offset};

	if (val)
		return -EINVAL;

	spin_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list) {
		stat_tmp.kvm = kvm;
		vcpu_stat_clear_per_vm((void *)&stat_tmp, 0);
	}
	spin_unlock(&kvm_lock);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(vcpu_stat_fops, vcpu_stat_get, vcpu_stat_clear,
			"%llu\n");

static const struct file_operations *stat_fops[] = {
	[KVM_STAT_VCPU] = &vcpu_stat_fops,
	[KVM_STAT_VM]   = &vm_stat_fops,
};

/*
 * 通知用户态程序
 */
static void kvm_uevent_notify_change(unsigned int type, struct kvm *kvm)
{
	struct kobj_uevent_env *env;
	unsigned long long created, active;

	if (!kvm_dev.this_device || !kvm)
		return;

	spin_lock(&kvm_lock);
	if (type == KVM_EVENT_CREATE_VM) {
		kvm_createvm_count++;
		kvm_active_vms++;
	} else if (type == KVM_EVENT_DESTROY_VM) {
		kvm_active_vms--;
	}
	created = kvm_createvm_count;
	active = kvm_active_vms;
	spin_unlock(&kvm_lock);

	env = kzalloc(sizeof(*env), GFP_KERNEL);
	if (!env)
		return;

	add_uevent_var(env, "CREATED=%llu", created);
	add_uevent_var(env, "COUNT=%llu", active);

	if (type == KVM_EVENT_CREATE_VM) {
		add_uevent_var(env, "EVENT=create");
		kvm->userspace_pid = task_pid_nr(current);
	} else if (type == KVM_EVENT_DESTROY_VM) {
		add_uevent_var(env, "EVENT=destroy");
	}
	add_uevent_var(env, "PID=%d", kvm->userspace_pid);

	if (kvm->debugfs_dentry) {
		char *tmp, *p = kmalloc(PATH_MAX, GFP_KERNEL);

		if (p) {
			tmp = dentry_path_raw(kvm->debugfs_dentry, p, PATH_MAX);
			if (!IS_ERR(tmp))
				add_uevent_var(env, "STATS_PATH=%s", tmp);
			kfree(p);
		}
	}
	/* no need for checks, since we are adding at most only 5 keys */
	env->envp[env->envp_idx++] = NULL;
	kobject_uevent_env(&kvm_dev.this_device->kobj, KOBJ_CHANGE, env->envp);
	kfree(env);
}

/*
 * vmx_init()
 *  kvm_init(opaque==&vmx_x86_ops) vmx_x86_ops定义在vmx.c文件中
 *   kvm_init_debug()
 */
static void kvm_init_debug(void)
{
	struct kvm_stats_debugfs_item *p;

	kvm_debugfs_dir = debugfs_create_dir("kvm", NULL);

	kvm_debugfs_num_entries = 0;
	for (p = debugfs_entries; p->name; ++p, kvm_debugfs_num_entries++) {
		debugfs_create_file(p->name, 0644, kvm_debugfs_dir,
				    (void *)(long)p->offset,
				    stat_fops[p->kind]);
	}
}

static int kvm_suspend(void)
{
	if (kvm_usage_count)
		hardware_disable_nolock(NULL);
	return 0;
}

static void kvm_resume(void)
{
	if (kvm_usage_count) {
		WARN_ON(raw_spin_is_locked(&kvm_count_lock));
		hardware_enable_nolock(NULL);
	}
}

static struct syscore_ops kvm_syscore_ops = {
	.suspend = kvm_suspend,
	.resume = kvm_resume,
};

static inline
struct kvm_vcpu *preempt_notifier_to_vcpu(struct preempt_notifier *pn)
{
	return container_of(pn, struct kvm_vcpu, preempt_notifier);
}

/*
 * schedule_tail()
 *  finish_task_switch()
 *   fire_sched_in_preempt_notifiers()
 *    __fire_sched_in_preempt_notifiers()
 *     kvm_sched_in()
 */
static void kvm_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct kvm_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	if (vcpu->preempted)
		vcpu->preempted = false;

	kvm_arch_sched_in(vcpu, cpu);

	kvm_arch_vcpu_load(vcpu, cpu);
}

static void kvm_sched_out(struct preempt_notifier *pn,
			  struct task_struct *next)
{
	struct kvm_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	if (current->state == TASK_RUNNING)
		vcpu->preempted = true;
	kvm_arch_vcpu_put(vcpu);
}

/*
 * vmx_init()
 *  kvm_init(opaque==&vmx_x86_ops) vmx_x86_ops定义在vmx.c文件中
 */
int kvm_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align,
		  struct module *module)
{
	int r;
	int cpu;

    /*
     * 检查是否支持vmx之类的
     * x86体系结构相关的初始化,比如开启CR4.VMXE(这个应该是在创建的哥VM的时候设置)
     */
	r = kvm_arch_init(opaque);
	if (r)
		goto out_fail;

	/*
	 * kvm_arch_init makes sure there's at most one caller
	 * for architectures that support multiple implementations,
	 * like intel and amd on x86.
	 * kvm_arch_init must be called before kvm_irqfd_init to avoid creating
	 * conflicts in case kvm is already setup for another implementation.
	 *
	 * 创建kvm-irqfd-cleanup队列
	 */
	r = kvm_irqfd_init();
	if (r)
		goto out_irqfd;

	if (!zalloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out_free_0;
	}

    //打开vmx功能
	r = kvm_arch_hardware_setup();
	if (r < 0)
		goto out_free_0a;

	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu,
				kvm_arch_check_processor_compat, //检查所有的cpu特性是否一致
				&r, 1);
		if (r < 0)
			goto out_free_1;
	}

	r = cpuhp_setup_state_nocalls(CPUHP_AP_KVM_STARTING, "kvm/cpu:starting",
				      kvm_starting_cpu, kvm_dying_cpu);
	if (r)
		goto out_free_2;
	
	register_reboot_notifier(&kvm_reboot_notifier);

	/* A kmem cache lets us meet the alignment requirements of fx_save. */
	if (!vcpu_align)
		vcpu_align = __alignof__(struct kvm_vcpu);
	
	kvm_vcpu_cache =
		kmem_cache_create_usercopy("kvm_vcpu", vcpu_size, vcpu_align,
					   SLAB_ACCOUNT,
					   offsetof(struct kvm_vcpu, arch),
					   sizeof_field(struct kvm_vcpu, arch),
					   NULL);
	if (!kvm_vcpu_cache) {
		r = -ENOMEM;
		goto out_free_3;
	}

	r = kvm_async_pf_init();
	if (r)
		goto out_free;

    //这三个file_operations->owner都是当前module
  	kvm_chardev_ops.owner = module;
	kvm_vm_fops.owner = module;
	kvm_vcpu_fops.owner = module;

	r = misc_register(&kvm_dev);
	if (r) {
		pr_err("kvm: misc device register failed\n");
		goto out_unreg;
	}

	register_syscore_ops(&kvm_syscore_ops);

	kvm_preempt_ops.sched_in = kvm_sched_in;
	kvm_preempt_ops.sched_out = kvm_sched_out;

	kvm_init_debug();

	r = kvm_vfio_ops_init();
	WARN_ON(r);

	return 0;

out_unreg:
	kvm_async_pf_deinit();
out_free:
	kmem_cache_destroy(kvm_vcpu_cache);
out_free_3:
	unregister_reboot_notifier(&kvm_reboot_notifier);
	cpuhp_remove_state_nocalls(CPUHP_AP_KVM_STARTING);
out_free_2:
out_free_1:
	kvm_arch_hardware_unsetup();
out_free_0a:
	free_cpumask_var(cpus_hardware_enabled);
out_free_0:
	kvm_irqfd_exit();
out_irqfd:
	kvm_arch_exit();
out_fail:
	return r;
}
EXPORT_SYMBOL_GPL(kvm_init);

void kvm_exit(void)
{
	debugfs_remove_recursive(kvm_debugfs_dir);
	misc_deregister(&kvm_dev);
	kmem_cache_destroy(kvm_vcpu_cache);
	kvm_async_pf_deinit();
	unregister_syscore_ops(&kvm_syscore_ops);
	unregister_reboot_notifier(&kvm_reboot_notifier);
	cpuhp_remove_state_nocalls(CPUHP_AP_KVM_STARTING);
	on_each_cpu(hardware_disable_nolock, NULL, 1);
	kvm_arch_hardware_unsetup();
	kvm_arch_exit();
	kvm_irqfd_exit();
	free_cpumask_var(cpus_hardware_enabled);
	kvm_vfio_ops_exit();
}
EXPORT_SYMBOL_GPL(kvm_exit);
