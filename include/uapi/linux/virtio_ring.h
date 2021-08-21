#ifndef _UAPI_LINUX_VIRTIO_RING_H
#define _UAPI_LINUX_VIRTIO_RING_H
/* An interface for efficient virtio implementation, currently for use by KVM,
 * but hopefully others soon.  Do NOT change this since it will
 * break existing servers and clients.
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright Rusty Russell IBM Corporation 2007. */
#ifndef __KERNEL__
#include <stdint.h>
#endif
#include <linux/types.h>
#include <linux/virtio_types.h>

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT	1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE	2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT	4

/* The Host uses this in used->flags to advise the Guest: don't kick me when
 * you add a buffer.  It's unreliable, so it's simply an optimization.  Guest
 * will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY	1
/* The Guest uses this in avail->flags to advise the Host: don't interrupt me
 * when you consume a buffer.  It's unreliable, so it's simply an
 * optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT	1

/* We support indirect buffer descriptors 
 *
 * 用在virtio_device->features
 */
#define VIRTIO_RING_F_INDIRECT_DESC	28

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX		29

/* Virtio ring descriptors: 16 bytes.  These can chain together via "next". 
 *
 * 如果数据是从guest(驱动)写给host(设备),就称这个vring_desc为out类型的
 * 如果数据是从host(设备)写给guest(驱动),就称这个vring_desc为in类型的
 *
 * 无论是读还是写，都是guest(驱动)负责管理存储区
 * virtqueue的管理也是由guest(驱动)负责
 * 即使是in类型的内存块，也是由guest(驱动)负责分配，host(设备)仅仅是向其中写入驱动需要的数据
 *
 *
 * 一个request包含多个 I/O request.
 * 一个 I/O request可能包含了多个不连续的内存块，每个内存块需要一个vring_desc来描述
 */
struct vring_desc {
	/* Address (guest-physical). 
	 *
	 * guest os 物理地址
     */
	__virtio64 addr;
	/* Length. */
	/*
	 * 对于in,out两个方向,len 有不同的意义
	 * 1.对于out方向,len表示驱动在这个内存块中准备了可供设备读取的数据量
	 * 2.对于in方向,len表示驱动为设备提供的空白的存储区域的尺寸以及设备至多可以向里面写入的数据量
	 */
	__virtio32 len;
	/* The flags as indicated above.  
	 *
	 * VRING_DESC_F_NEXT,
	 * VRING_DESC_F_WRITE, 对qemu(host os)侧的设备而言，只写
	 * VRING_DESC_F_INDIRECT,这段IO由不连续的的vring_desc构成
	 * 
	 * 
	 */
	__virtio16 flags;
	/* We chain unused descriptors via this, too 
	 * 指向下一个 vring_desc
	 */
	__virtio16 next;
};

/*
 * 看vring_virtqueue, vring_virtqueue包含了virtqueue和vring
 *
 * avail是从host(外设)的角度来取名
 */
struct vring_avail {
    /*
     * VRING_AVAIL_F_NO_INTERRUPT,
     */
	__virtio16 flags;
	/*
	 * 在驱动侧(guest os)下一个可以在vring_avail->ring[]数组中填写的索引
	 */
	__virtio16 idx;
	/*
	 * ring中的每一个元素记录的vring_desc链的第一个ring_desc的id，
	 * 这个id是描述符在描述符表中的索引
	 *
	 *vhost_virtqueue->last_avail_idx记录设备侧(host侧)可以消费vring_avail.ring[]的位置
	 *
	 * ring[]中数值是指在vring->desc[]当中的索引，然后由vring->desc[]中的vring_desc组成一个链表
	 *
	 * 驱动每次将I/O request转换成vring_desc后，就会在vring_avail->ring[]中增加一个元素,这里会用到idx
	 * 
	 */
	__virtio16 ring[];
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem {
	/* Index of start of used descriptor chain. 
	 *
	 * 指示vring->desc[]中的索引
     */
	__virtio32 id;
	/* Total length of the descriptor chain which was used (written to) */
	//记录设备侧(host)反馈给驱动侧(guest)的数据长度
	__virtio32 len;
};

struct vring_used {
	/*
     * VRING_USED_F_NO_NOTIFY,
	 */     
	__virtio16 flags;
	//和vring_avail->idx的作用类似,不过是在qemu(或者host os)中，有设备来填写
	__virtio16 idx;
	struct vring_used_elem ring[];
};

/*
 * 看vring_virtqueue, vring_virtqueue包含了virtqueue和vring
 *
 * 作为vring_virtqueue成员,在__vring_new_virtqueue中分配
 *
 * vring对象在vring_init中初始化
 *
 * virtio_pci_device->virtqueues->vq->vring
 */
struct vring {
    //avail->ring[]中有num个vring_desc
	unsigned int num;
    /*描述符数组*/
	struct vring_desc *desc;
    /*guest os virtio驱动设置的，供后端设备(在qemu或者host kernel)中使用的*/
	struct vring_avail *avail;//avail后面还会有一个used_event,2个字节
    /*
     *后端设备(在qemu或者host kernel中)设置，
     *这样前端驱动(guest os中的virtio驱动)可以知道哪些vring_desc被后端设备使用了
     */
	struct vring_used *used;//used后面还会有一个avail_event,2个字节
};

/* Alignment requirements for vring elements.
 * When using pre-virtio 1.0 layout, these fall out naturally.
 */
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE 4
#define VRING_DESC_ALIGN_SIZE 16

/* The standard layout for the ring is a continuous chunk of memory which looks
 * like this.  We assume num is a power of 2.
 *
 * struct vring
 * {
 *	// The actual descriptors (16 bytes each)
 *	struct vring_desc desc[num];
 *
 *	// A ring of available descriptor heads with free-running index.
 *	__virtio16 avail_flags;
 *	__virtio16 avail_idx;
 *	__virtio16 available[num];
 *	__virtio16 used_event_idx;
 *
 *	// Padding to the next align boundary.
 *	char pad[];
 *
 *	// A ring of used descriptor heads with free-running index.
 *	__virtio16 used_flags;
 *	__virtio16 used_idx;
 *	struct vring_used_elem used[num];
 *	__virtio16 avail_event_idx;
 * };
 */
/* We publish the used event index at the end of the available ring, and vice
 * versa. They are at the end for backwards compatibility. */
#define vring_used_event(vr) ((vr)->avail->ring[(vr)->num])
#define vring_avail_event(vr) (*(__virtio16 *)&(vr)->used->ring[(vr)->num])

/*
 * vring_create_virtqueue()
 *  vring_init()
 */
static inline void vring_init(struct vring *vr, unsigned int num, void *p,
			      unsigned long align)
{
	vr->num = num;
	vr->desc = p;
	//avail的起始地址，跳过vring_desc这个部分
	vr->avail = p + num*sizeof(struct vring_desc);
	//used的起始地址,跳过avail->ring[num]，然后对齐一下
	vr->used = (void *)(((uintptr_t)&vr->avail->ring[num] + sizeof(__virtio16)
		+ align-1) & ~(align - 1));
}

static inline unsigned vring_size(unsigned int num, unsigned long align)
{                                              /* 3个2字节是vring_avail->flags+vring_avail->idx+ used_event */
	return ((sizeof(struct vring_desc) * num + sizeof(__virtio16) * (3 + num)
		 + align - 1) & ~(align - 1))
		  /* 3个2字节是vring_used->flags+vring_used->idx+ avail_event */
		+ sizeof(__virtio16) * 3 + sizeof(struct vring_used_elem) * num;
}

/* The following is used with USED_EVENT_IDX and AVAIL_EVENT_IDX */
/* Assuming a given event_idx value from the other side, if
 * we have just incremented index from old to new_idx,
 * should we trigger an event? */
static inline int vring_need_event(__u16 event_idx, __u16 new_idx, __u16 old)
{
	/* Note: Xen has similar logic for notification hold-off
	 * in include/xen/interface/io/ring.h with req_event and req_prod
	 * corresponding to event_idx + 1 and new_idx respectively.
	 * Note also that req_event and req_prod in Xen start at 1,
	 * event indexes in virtio start at 0. */
	return (__u16)(new_idx - event_idx - 1) < (__u16)(new_idx - old);
}

#endif /* _UAPI_LINUX_VIRTIO_RING_H */
