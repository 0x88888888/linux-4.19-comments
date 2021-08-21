/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_IO_APIC_H
#define __KVM_IO_APIC_H

#include <linux/kvm_host.h>

#include <kvm/iodev.h>

struct kvm;
struct kvm_vcpu;

#define IOAPIC_NUM_PINS  KVM_IOAPIC_NUM_PINS
#define MAX_NR_RESERVED_IOAPIC_PINS KVM_MAX_IRQ_ROUTES
#define IOAPIC_VERSION_ID 0x11	/* IOAPIC version */
#define IOAPIC_EDGE_TRIG  0
#define IOAPIC_LEVEL_TRIG 1

#define IOAPIC_DEFAULT_BASE_ADDRESS  0xfec00000
#define IOAPIC_MEM_LENGTH            0x100

/* Direct registers. */
#define IOAPIC_REG_SELECT  0x00
#define IOAPIC_REG_WINDOW  0x10

/* Indirect registers. */
#define IOAPIC_REG_APIC_ID 0x00	/* x86 IOAPIC only */
#define IOAPIC_REG_VERSION 0x01
#define IOAPIC_REG_ARB_ID  0x02	/* x86 IOAPIC only */

/*ioapic delivery mode*/
#define	IOAPIC_FIXED			0x0
#define	IOAPIC_LOWEST_PRIORITY		0x1
#define	IOAPIC_PMI			0x2
#define	IOAPIC_NMI			0x4
#define	IOAPIC_INIT			0x5
#define	IOAPIC_EXTINT			0x7

#ifdef CONFIG_X86
#define RTC_GSI 8
#else
#define RTC_GSI -1U
#endif

struct dest_map {
	/* vcpu bitmap where IRQ has been sent */
	DECLARE_BITMAP(map, KVM_MAX_VCPU_ID);

	/*
	 * Vector sent to a given vcpu, only valid when
	 * the vcpu's bit in map is set
	 */
	u8 vectors[KVM_MAX_VCPU_ID];
};


struct rtc_status {
	int pending_eoi;
	struct dest_map dest_map;
};

union kvm_ioapic_redirect_entry {
	u64 bits;
	struct {
		//中断对应的向量号
		u8 vector;
		//APIC_DM_LOWEST, APIC_DM_FIXED,APIC_DM_NMI
		u8 delivery_mode:3;
		//决定dest_id的含义,如果为0，表示dest_id为local apic id.
		u8 dest_mode:1;
		//表示中断状态,0，表示空闲,1表示发送被挂起了
		u8 delivery_status:1;
		//0表示高电平触发,1表示低电平触发
		u8 polarity:1;
		//用于level触发,当lapic接受中断后,这个值为1，当接受到eoi后，这个为0
		u8 remote_irr:1;
		//1表示level触发,0表示edge触发
		u8 trig_mode:1;
		//1表示屏蔽该中断
		u8 mask:1;
		u8 reserve:7;
		u8 reserved[4];
		/*
		 * LAPIC 的id,根据dest_mode来解释
		 * 1表示local apic id
		 * 0表示一组cpu 
		 */
		u8 dest_id;
	} fields;
};

/*
 * 模拟io apic中断控制器
 *
 * 在ioctl(KVM_CREATE_IRQCHIP)->kvm_ioapic_init中创建
 */
struct kvm_ioapic {
    //IO apic设备的 mmio 的地址,IOAPIC_DEFAULT_BASE_ADDRESS
	u64 base_address;
	u32 ioregsel;
	u32 id;
	u32 irr;
	u32 pad;
	/* 
	 * IO APIC重定向表,
	 * 与pic的中断号与中断向量是固定映射不同, IO APIC的每个中断号
	 * 都可以通过编程设置其对应的中断向量号,这里的redirtbl保存的就是24项中断重定向表
	 * 每一个kvm_ioapic_redirect_entry中有对应的中断向量号,触发模式,发送到Local APIC的id等
	 */
	union kvm_ioapic_redirect_entry redirtbl[IOAPIC_NUM_PINS];
	//中断线的状态
	unsigned long irq_states[IOAPIC_NUM_PINS];
	// I/O apic对应的设备,操作函数ioapic_mmio_ops
	struct kvm_io_device dev;
	//对应的虚拟机
	struct kvm *kvm;
	void (*ack_notifier)(void *opaque, int irq);
	spinlock_t lock;
	struct rtc_status rtc_status;
	//kvm_ioapic_eoi_inject_work
	struct delayed_work eoi_inject;
	u32 irq_eoi[IOAPIC_NUM_PINS];
	u32 irr_delivered;
};

#ifdef DEBUG
#define ASSERT(x)  							\
do {									\
	if (!(x)) {							\
		printk(KERN_EMERG "assertion failed %s: %d: %s\n",	\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else
#define ASSERT(x) do { } while (0)
#endif

static inline int ioapic_in_kernel(struct kvm *kvm)
{
	int mode = kvm->arch.irqchip_mode;

	/* Matches smp_wmb() when setting irqchip_mode */
	smp_rmb();
	return mode == KVM_IRQCHIP_KERNEL;
}

void kvm_rtc_eoi_tracking_restore_one(struct kvm_vcpu *vcpu);
bool kvm_apic_match_dest(struct kvm_vcpu *vcpu, struct kvm_lapic *source,
		int short_hand, unsigned int dest, int dest_mode);
int kvm_apic_compare_prio(struct kvm_vcpu *vcpu1, struct kvm_vcpu *vcpu2);
void kvm_ioapic_update_eoi(struct kvm_vcpu *vcpu, int vector,
			int trigger_mode);
int kvm_ioapic_init(struct kvm *kvm);
void kvm_ioapic_destroy(struct kvm *kvm);
int kvm_ioapic_set_irq(struct kvm_ioapic *ioapic, int irq, int irq_source_id,
		       int level, bool line_status);
void kvm_ioapic_clear_all(struct kvm_ioapic *ioapic, int irq_source_id);
int kvm_irq_delivery_to_apic(struct kvm *kvm, struct kvm_lapic *src,
			     struct kvm_lapic_irq *irq,
			     struct dest_map *dest_map);
void kvm_get_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state);
void kvm_set_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state);
void kvm_ioapic_scan_entry(struct kvm_vcpu *vcpu,
			   ulong *ioapic_handled_vectors);
void kvm_scan_ioapic_routes(struct kvm_vcpu *vcpu,
			    ulong *ioapic_handled_vectors);
#endif
