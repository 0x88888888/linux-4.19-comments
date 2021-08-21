/* Virtio ring implementation.
 *
 *  Copyright 2007 Rusty Russell IBM Corporation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <linux/virtio.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_config.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/hrtimer.h>
#include <linux/dma-mapping.h>
#include <xen/xen.h>

#ifdef DEBUG
/* For development, we want to crash whenever the ring is screwed. */
#define BAD_RING(_vq, fmt, args...)				\
	do {							\
		dev_err(&(_vq)->vq.vdev->dev,			\
			"%s:"fmt, (_vq)->vq.name, ##args);	\
		BUG();						\
	} while (0)
/* Caller is supposed to guarantee no reentry. */
#define START_USE(_vq)						\
	do {							\
		if ((_vq)->in_use)				\
			panic("%s:in_use = %i\n",		\
			      (_vq)->vq.name, (_vq)->in_use);	\
		(_vq)->in_use = __LINE__;			\
	} while (0)
#define END_USE(_vq) \
	do { BUG_ON(!(_vq)->in_use); (_vq)->in_use = 0; } while(0)
#else
#define BAD_RING(_vq, fmt, args...)				\
	do {							\
		dev_err(&_vq->vq.vdev->dev,			\
			"%s:"fmt, (_vq)->vq.name, ##args);	\
		(_vq)->broken = true;				\
	} while (0)
#define START_USE(vq)
#define END_USE(vq)
#endif

struct vring_desc_state {
	void *data;			/* Data for callback. */
	struct vring_desc *indir_desc;	/* Indirect descriptor, if any. */
};

/*
 *  在__vring_new_virtqueue中分配
 *
 * 
 */
struct vring_virtqueue {
	struct virtqueue vq;

	/* Actual memory layout for this queue 
	 *
	 *用于存储数据的数据结构
	 */
	struct vring vring;

	/* Can we use weak barriers? */
	bool weak_barriers;

	/* Other side has made a mess, don't try any more. 
	 *
	 * 表示对端(virtio设备端,即qemu端或者host内核端)已经不是正常状态了
	 */
	bool broken;

	/* Host supports indirect buffers 
	 *
	 * 表示对端(virtio设备端,即qemu端或者host内核端)支持indirect方式
	 */
	bool indirect;

	/* Host publishes avail event idx 
	 *
	 * 表示对端是否使用了avail event index特性
	 */
	bool event;

	/* Head of free buffer list. 
	 * descriptor table中第一个可用项
	 */
	unsigned int free_head;
	/* Number we've added since last sync. 
	 *
	 * 上次通知对端之后增加的avail ring的个数
	 */
	unsigned int num_added;

	/* Last used index we've seen. 
	 *
	 * vring_virtqueue->last_used_idx表示当前guest(驱动)侧已经回收到的位置
	 * 这个值记录的是used ring的index,在驱动侧获取uesd ring的时候使用
	 */
	u16 last_used_idx;

	/* Last written value to avail->flags 
	 * 最后一次写入到avail->flags中的值
	 */
	u16 avail_flags_shadow;

	/* Last written value to avail->idx in guest byte order 
	 * 最后一次写入到avail->idx中的值
	 */
	u16 avail_idx_shadow;

	/* How to notify other side. FIXME: commonalize hcalls! 
	 * 通知对端的函数
	 * 这个函数应该是vp_notify()
	 */
	bool (*notify)(struct virtqueue *vq);

	/* DMA, allocation, and size information */
	bool we_own_ring;
	size_t queue_size_in_bytes;
	dma_addr_t queue_dma_addr;

#ifdef DEBUG
	/* They're supposed to lock for us. */
	unsigned int in_use;

	/* Figure out if their kicks are too delayed. */
	bool last_add_time_valid;
	ktime_t last_add_time;
#endif

	/* Per-descriptor state. */
	struct vring_desc_state desc_state[];
};

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

/*
 * Modern virtio devices have feature bits to specify whether they need a
 * quirk and bypass the IOMMU. If not there, just use the DMA API.
 *
 * If there, the interaction between virtio and DMA API is messy.
 *
 * On most systems with virtio, physical addresses match bus addresses,
 * and it doesn't particularly matter whether we use the DMA API.
 *
 * On some systems, including Xen and any system with a physical device
 * that speaks virtio behind a physical IOMMU, we must use the DMA API
 * for virtio DMA to work at all.
 *
 * On other systems, including SPARC and PPC64, virtio-pci devices are
 * enumerated as though they are behind an IOMMU, but the virtio host
 * ignores the IOMMU, so we must either pretend that the IOMMU isn't
 * there or somehow map everything as the identity.
 *
 * For the time being, we preserve historic behavior and bypass the DMA
 * API.
 *
 * TODO: install a per-device DMA ops structure that does the right thing
 * taking into account all the above quirks, and use the DMA API
 * unconditionally on data path.
 */

static bool vring_use_dma_api(struct virtio_device *vdev)
{
	if (!virtio_has_iommu_quirk(vdev))
		return true;

	/* Otherwise, we are left to guess. */
	/*
	 * In theory, it's possible to have a buggy QEMU-supposed
	 * emulated Q35 IOMMU and Xen enabled at the same time.  On
	 * such a configuration, virtio has never worked and will
	 * not work without an even larger kludge.  Instead, enable
	 * the DMA API if we're a Xen guest, which at least allows
	 * all of the sensible Xen configurations to work correctly.
	 */
	if (xen_domain())
		return true;

	return false;
}

/*
 * The DMA ops on various arches are rather gnarly right now, and
 * making all of the arch DMA ops work on the vring device itself
 * is a mess.  For now, we use the parent device for DMA ops.
 */
static inline struct device *vring_dma_dev(const struct vring_virtqueue *vq)
{
	return vq->vq.vdev->dev.parent;
}

/* Map one sg entry. */
static dma_addr_t vring_map_one_sg(const struct vring_virtqueue *vq,
				   struct scatterlist *sg,
				   enum dma_data_direction direction)
{
	if (!vring_use_dma_api(vq->vq.vdev))
		return (dma_addr_t)sg_phys(sg);

	/*
	 * We can't use dma_map_sg, because we don't use scatterlists in
	 * the way it expects (we don't guarantee that the scatterlist
	 * will exist for the lifetime of the mapping).
	 */
	return dma_map_page(vring_dma_dev(vq),
			    sg_page(sg), sg->offset, sg->length,
			    direction);
}

static dma_addr_t vring_map_single(const struct vring_virtqueue *vq,
				   void *cpu_addr, size_t size,
				   enum dma_data_direction direction)
{
	if (!vring_use_dma_api(vq->vq.vdev))
		return (dma_addr_t)virt_to_phys(cpu_addr);

	return dma_map_single(vring_dma_dev(vq),
			      cpu_addr, size, direction);
}

/*
 * virtqueue_get_buf()
 *  virtqueue_get_buf_ctx()
 *   detach_buf()
 *    vring_unmap_one()
 */
static void vring_unmap_one(const struct vring_virtqueue *vq,
			    struct vring_desc *desc)
{
	u16 flags;

	if (!vring_use_dma_api(vq->vq.vdev))
		return;

	flags = virtio16_to_cpu(vq->vq.vdev, desc->flags);

	if (flags & VRING_DESC_F_INDIRECT) {
		dma_unmap_single(vring_dma_dev(vq),
				 virtio64_to_cpu(vq->vq.vdev, desc->addr),
				 virtio32_to_cpu(vq->vq.vdev, desc->len),
				 (flags & VRING_DESC_F_WRITE) ?
				 DMA_FROM_DEVICE : DMA_TO_DEVICE);
	} else {
		dma_unmap_page(vring_dma_dev(vq),
			       virtio64_to_cpu(vq->vq.vdev, desc->addr),
			       virtio32_to_cpu(vq->vq.vdev, desc->len),
			       (flags & VRING_DESC_F_WRITE) ?
			       DMA_FROM_DEVICE : DMA_TO_DEVICE);
	}
}

static int vring_mapping_error(const struct vring_virtqueue *vq,
			       dma_addr_t addr)
{
	if (!vring_use_dma_api(vq->vq.vdev))
		return 0;

	return dma_mapping_error(vring_dma_dev(vq), addr);
}

/* 
 * virtqueue_add()
 *  alloc_indirect()
 *
 * 分配total_sg个vring_desc结构
 */
static struct vring_desc *alloc_indirect(struct virtqueue *_vq,
					 unsigned int total_sg, gfp_t gfp)
{
	struct vring_desc *desc;
	unsigned int i;

	/*
	 * We require lowmem mappings for the descriptors because
	 * otherwise virt_to_phys will give us bogus addresses in the
	 * virtqueue.
	 */
	gfp &= ~__GFP_HIGHMEM;

	desc = kmalloc_array(total_sg, sizeof(struct vring_desc), gfp);
	if (!desc)
		return NULL;

	for (i = 0; i < total_sg; i++)
		desc[i].next = cpu_to_virtio16(_vq->vdev, i + 1);
	return desc;
}

/* 
 *
 *
 * 向dscriptor table添加请求数据
 */
static inline int virtqueue_add(struct virtqueue *_vq, /* 要添加数据的 virtqueue*/
				struct scatterlist *sgs[], /* 数据 */
				unsigned int total_sg, /* sgs的长度 */
				unsigned int out_sgs, /* 驱动写入的数据 */
				unsigned int in_sgs, /* 驱动提供给设备的空间，即设备写这个空间 */
				void *data, //表示本次请求的上下文，通常用来表示具体的vitio设备,如virtio balloon设备
				void *ctx,
				gfp_t gfp)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct scatterlist *sg;
	struct vring_desc *desc;//会新分配一个vring_desc数组，用于存放数据
	unsigned int i, n, avail, descs_used/* 将要使用的descriptor个数 */, uninitialized_var(prev), err_idx;
	int head;
	bool indirect;

	START_USE(vq);

	BUG_ON(data == NULL);
	BUG_ON(ctx && vq->indirect);

    //对端不能处于不正常状态
	if (unlikely(vq->broken)) {
		END_USE(vq);
		return -EIO;
	}

#ifdef DEBUG
	{
		ktime_t now = ktime_get();

		/* No kick or get, with .1 second between?  Warn. */
		if (vq->last_add_time_valid)
			WARN_ON(ktime_to_ms(ktime_sub(now, vq->last_add_time))
					    > 100);
		vq->last_add_time = now;
		vq->last_add_time_valid = true;
	}
#endif

	BUG_ON(total_sg == 0);

	head = vq->free_head;

	/* If the host supports indirect descriptor tables, and we have multiple
	 * buffers, then go indirect. FIXME: tune this threshold */
	if (vq->indirect && total_sg > 1 && vq->vq.num_free)
		//分配total_sg个vring_desc
		desc = alloc_indirect(_vq, total_sg, gfp);
	else {
		desc = NULL;
		WARN_ON_ONCE(total_sg > vq->vring.num && !vq->indirect);
	}

	if (desc) {
		/* Use a single buffer which doesn't continue */
		indirect = true;
		/* Set up rest to use this indirect table. */
		i = 0;
		descs_used = 1;
	} else {
		indirect = false;
		desc = vq->vring.desc;
		i = head;
		descs_used = total_sg;
	}

    //要使用的vring_desc的数量，要比当前空闲的descriptor数量小才行
	if (vq->vq.num_free < descs_used) {
		pr_debug("Can't add buf len %i - avail = %i\n",
			 descs_used, vq->vq.num_free);
		/* FIXME: for historical reasons, we force a notify here if
		 * there are outgoing parts to the buffer.  Presumably the
		 * host should service the ring ASAP. */
		if (out_sgs)
			vq->notify(&vq->vq);
		
		if (indirect)//释放掉已经申请的descriptor的空间
			kfree(desc);
		END_USE(vq);
		return -ENOSPC;
	}

    //将out_sgs中的数据填写到vring_desc
	for (n = 0; n < out_sgs; n++) {
		for (sg = sgs[n]; sg; sg = sg_next(sg)) {
			//
			dma_addr_t addr = vring_map_one_sg(vq, sg, DMA_TO_DEVICE);
			if (vring_mapping_error(vq, addr))
				goto unmap_release;

            //还有下个vring_desc
			desc[i].flags = cpu_to_virtio16(_vq->vdev, VRING_DESC_F_NEXT);
			desc[i].addr = cpu_to_virtio64(_vq->vdev, addr);
			desc[i].len = cpu_to_virtio32(_vq->vdev, sg->length);
			prev = i;
			//下一个空闲的vring_desc
			i = virtio16_to_cpu(_vq->vdev, desc[i].next);
		}
	}

	//将in_sgs中的数据填写到vring_desc
	for (; n < (out_sgs + in_sgs); n++) {
		for (sg = sgs[n]; sg; sg = sg_next(sg)) {
			dma_addr_t addr = vring_map_one_sg(vq, sg, DMA_FROM_DEVICE);
			if (vring_mapping_error(vq, addr))
				goto unmap_release;

            //对端设备看到VRING_DESC_F_WRITE,知道，开始了in数据
			desc[i].flags = cpu_to_virtio16(_vq->vdev, VRING_DESC_F_NEXT | VRING_DESC_F_WRITE);
			desc[i].addr = cpu_to_virtio64(_vq->vdev, addr);
			desc[i].len = cpu_to_virtio32(_vq->vdev, sg->length);
			prev = i;
			i = virtio16_to_cpu(_vq->vdev, desc[i].next);
		}
	}
	/* Last one doesn't continue. 
	 * 结束了，清空掉VRING_DESC_F_NEXT，让对端知道数据已经结束
	 */
	desc[prev].flags &= cpu_to_virtio16(_vq->vdev, ~VRING_DESC_F_NEXT);

	if (indirect) {
		/* Now that the indirect table is filled in, map it. */
		dma_addr_t addr = vring_map_single(
			vq, desc, total_sg * sizeof(struct vring_desc),
			DMA_TO_DEVICE);
		if (vring_mapping_error(vq, addr))
			goto unmap_release;

		vq->vring.desc[head].flags = cpu_to_virtio16(_vq->vdev, VRING_DESC_F_INDIRECT);
		vq->vring.desc[head].addr = cpu_to_virtio64(_vq->vdev, addr);

		vq->vring.desc[head].len = cpu_to_virtio32(_vq->vdev, total_sg * sizeof(struct vring_desc));
	}

	/* We're using some buffers from the free list. */
	//剩余空闲的vring_desc的个数
	vq->vq.num_free -= descs_used;

	/* Update free pointer */
	if (indirect)
		vq->free_head = virtio16_to_cpu(_vq->vdev, vq->vring.desc[head].next);
	else
		vq->free_head = i;

	/* Store token and indirect buffer state. */
	vq->desc_state[head].data = data;
	if (indirect)
		vq->desc_state[head].indir_desc = desc;
	else
		vq->desc_state[head].indir_desc = ctx;

	/* Put entry in available array (but don't update avail->idx until they
	 * do sync). */
	avail = vq->avail_idx_shadow & (vq->vring.num - 1);
	//将第一个vring_desc的索引写到vq->vring.avail->ring[avail]中去
	vq->vring.avail->ring[avail] = cpu_to_virtio16(_vq->vdev, head);

	/* Descriptors and available array need to be set before we expose the
	 * new available array entries. */
	virtio_wmb(vq->weak_barriers);
	vq->avail_idx_shadow++;
	vq->vring.avail->idx = cpu_to_virtio16(_vq->vdev, vq->avail_idx_shadow);
	//
	vq->num_added++;

	pr_debug("Added buffer head %i to %p\n", head, vq);
	END_USE(vq);

	/* This is very unlikely, but theoretically possible.  Kick
	 * just in case. */
	if (unlikely(vq->num_added == (1 << 16) - 1))
		virtqueue_kick(_vq);

	return 0;

unmap_release:
	err_idx = i;
	i = head;

	for (n = 0; n < total_sg; n++) {
		if (i == err_idx)
			break;
		vring_unmap_one(vq, &desc[i]);
		i = virtio16_to_cpu(_vq->vdev, vq->vring.desc[i].next);
	}

	if (indirect)
		kfree(desc);

	END_USE(vq);
	return -EIO;
}

/**
 * virtqueue_add_sgs - expose buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sgs: array of terminated scatterlists.
 * @out_num: the number of scatterlists readable by other side
 * @in_num: the number of scatterlists which are writable (after readable ones)
 * @data: the token identifying the buffer.
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_sgs(struct virtqueue *_vq,
		      struct scatterlist *sgs[],
		      unsigned int out_sgs,
		      unsigned int in_sgs,
		      void *data,
		      gfp_t gfp)
{
	unsigned int i, total_sg = 0;

	/* Count them first. 
	 * sgs中的scatterlist个数
	 */
	for (i = 0; i < out_sgs + in_sgs; i++) {
		struct scatterlist *sg;
		for (sg = sgs[i]; sg; sg = sg_next(sg))
			total_sg++;
	}
	return virtqueue_add(_vq, sgs, total_sg, out_sgs, in_sgs,
			     data, NULL, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_sgs);

/**
 * virtqueue_add_outbuf - expose output buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg readable by other side
 * @data: the token identifying the buffer.
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_outbuf(struct virtqueue *vq,
			 struct scatterlist *sg, unsigned int num,
			 void *data,
			 gfp_t gfp)
{
	return virtqueue_add(vq, &sg, num, 1, 0, data, NULL, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_outbuf);

/**
 * virtqueue_add_inbuf - expose input buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg writable by other side
 * @data: the token identifying the buffer.
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_inbuf(struct virtqueue *vq,
			struct scatterlist *sg, unsigned int num,
			void *data,
			gfp_t gfp)
{
	return virtqueue_add(vq, &sg, num, 0, 1, data, NULL, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_inbuf);

/**
 * virtqueue_add_inbuf_ctx - expose input buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg writable by other side
 * @data: the token identifying the buffer.
 * @ctx: extra context for the token
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_inbuf_ctx(struct virtqueue *vq,
			struct scatterlist *sg, unsigned int num,
			void *data,
			void *ctx,
			gfp_t gfp)
{
	return virtqueue_add(vq, &sg, num, 0, 1, data, ctx, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_inbuf_ctx);

/**
 * virtqueue_kick_prepare - first half of split virtqueue_kick call.
 * @vq: the struct virtqueue
 *
 * Instead of virtqueue_kick(), you can do:
 *	if (virtqueue_kick_prepare(vq))
 *		virtqueue_notify(vq);
 *
 * This is sometimes useful because the virtqueue_kick_prepare() needs
 * to be serialized, but the actual virtqueue_notify() call does not.
 *
 * virtqueue_kick()
 *  virtqueue_kick_prepare()
 */
bool virtqueue_kick_prepare(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 new, old;
	bool needs_kick;

	START_USE(vq);
	/* We need to expose available array entries before checking avail
	 * event. */
	virtio_mb(vq->weak_barriers);

	old = vq->avail_idx_shadow - vq->num_added;
	new = vq->avail_idx_shadow;
	vq->num_added = 0;

#ifdef DEBUG
	if (vq->last_add_time_valid) {
		WARN_ON(ktime_to_ms(ktime_sub(ktime_get(),
					      vq->last_add_time)) > 100);
	}
	vq->last_add_time_valid = false;
#endif

    //对端是否使用了 avail event index特性
	if (vq->event) {
		needs_kick = vring_need_event(virtio16_to_cpu(_vq->vdev, vring_avail_event(&vq->vring)),
					      new, old);
	} else {
		needs_kick = !(vq->vring.used->flags & cpu_to_virtio16(_vq->vdev, VRING_USED_F_NO_NOTIFY));
	}
	END_USE(vq);
	return needs_kick;
}
EXPORT_SYMBOL_GPL(virtqueue_kick_prepare);

/**
 * virtqueue_notify - second half of split virtqueue_kick call.
 * @vq: the struct virtqueue
 *
 * This does not need to be serialized.
 *
 * Returns false if host notify failed or queue is broken, otherwise true.
 */
bool virtqueue_notify(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (unlikely(vq->broken))
		return false;

	/* Prod other side to tell it about changes. */
	if (!vq->notify(_vq)) {
		vq->broken = true;
		return false;
	}
	return true;
}
EXPORT_SYMBOL_GPL(virtqueue_notify);

/**
 * virtqueue_kick - update after add_buf
 * @vq: the struct virtqueue
 *
 * After one or more virtqueue_add_* calls, invoke this to kick
 * the other side.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 *
 * Returns false if kick failed, otherwise true.
 */
bool virtqueue_kick(struct virtqueue *vq)
{
	if (virtqueue_kick_prepare(vq)) //判断是否需要通知
		return virtqueue_notify(vq);// 调用vq->notify()进行通知对端
	return true;
}
EXPORT_SYMBOL_GPL(virtqueue_kick);

/*
 * virtqueue_get_buf()
 *  virtqueue_get_buf_ctx()
 *   detach_buf()
 *
 * 回收从head开始的vring_desc
 */
static void detach_buf(struct vring_virtqueue *vq, unsigned int head,
		       void **ctx)
{
	unsigned int i, j;
	__virtio16 nextflag = cpu_to_virtio16(vq->vq.vdev, VRING_DESC_F_NEXT);

	/* Clear data ptr. */
	vq->desc_state[head].data = NULL;

	/* Put back on free list: unmap first-level descriptors and find end */
	i = head;

	while (vq->vring.desc[i].flags & nextflag) {
		//回收掉(unmap掉内存)
		vring_unmap_one(vq, &vq->vring.desc[i]);
		i = virtio16_to_cpu(vq->vq.vdev, vq->vring.desc[i].next);
	    //空闲的vring_desc数量增加
		vq->vq.num_free++;
	}

	vring_unmap_one(vq, &vq->vring.desc[i]);
	//所有空闲的vring_desc链接起来
	vq->vring.desc[i].next = cpu_to_virtio16(vq->vq.vdev, vq->free_head);
	//从新设置可分配的vring_desc
	vq->free_head = head;

	/* Plus final descriptor */
	vq->vq.num_free++;

	if (vq->indirect) {
		struct vring_desc *indir_desc = vq->desc_state[head].indir_desc;
		u32 len;

		/* Free the indirect table, if any, now that it's unmapped. */
		if (!indir_desc)
			return;

		len = virtio32_to_cpu(vq->vq.vdev, vq->vring.desc[head].len);

		BUG_ON(!(vq->vring.desc[head].flags &
			 cpu_to_virtio16(vq->vq.vdev, VRING_DESC_F_INDIRECT)));
		BUG_ON(len == 0 || len % sizeof(struct vring_desc));

		for (j = 0; j < len / sizeof(struct vring_desc); j++)
			vring_unmap_one(vq, &indir_desc[j]);

		kfree(indir_desc);
		vq->desc_state[head].indir_desc = NULL;
	} else if (ctx) {
		*ctx = vq->desc_state[head].indir_desc;
	}
}

static inline bool more_used(const struct vring_virtqueue *vq)
{
	return vq->last_used_idx != virtio16_to_cpu(vq->vq.vdev, vq->vring.used->idx);
}

/**
 * virtqueue_get_buf - get the next used buffer
 * @vq: the struct virtqueue we're talking about.
 * @len: the length written into the buffer
 *
 * If the device wrote data into the buffer, @len will be set to the
 * amount written.  This means you don't need to clear the buffer
 * beforehand to ensure there's no data leakage in the case of short
 * writes.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 *
 * Returns NULL if there are no used buffers, or the "data" token
 * handed to virtqueue_add_*().
 *
 * virtqueue_get_buf()
 *  virtqueue_get_buf_ctx()
 */
void *virtqueue_get_buf_ctx(struct virtqueue *_vq, unsigned int *len,
			    void **ctx)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	void *ret;
	unsigned int i;
	u16 last_used;

	START_USE(vq);

	if (unlikely(vq->broken)) {
		END_USE(vq);
		return NULL;
	}

    //判断该队列的used ring的idx是否在上一次的基础上增加了
	if (!more_used(vq)) {
		pr_debug("No more buffers in queue\n");
		END_USE(vq);
		return NULL;
	}

	/* Only get used array entries after they have been exposed by host. */
	virtio_rmb(vq->weak_barriers);

    /*
     * 保存本次要使用的used ring 的index
     */
	last_used = (vq->last_used_idx & (vq->vring.num - 1));
	//从used ring[]中取出guest os中填写的vring_desc table中的索引i和长度
	i = virtio32_to_cpu(_vq->vdev, vq->vring.used->ring[last_used].id);
	*len = virtio32_to_cpu(_vq->vdev, vq->vring.used->ring[last_used].len);

	if (unlikely(i >= vq->vring.num)) {
		BAD_RING(vq, "id %u out of range\n", i);
		return NULL;
	}
	if (unlikely(!vq->desc_state[i].data)) {
		BAD_RING(vq, "id %u is not a head!\n", i);
		return NULL;
	}

	/* detach_buf clears data, so grab it now. */
	ret = vq->desc_state[i].data;
	//将从i开始的几个vring_desc回收回来
	detach_buf(vq, i, ctx);
	vq->last_used_idx++;
	/* If we expect an interrupt for the next entry, tell host
	 * by writing event index and flush out the write before
	 * the read in the next get_buf call.
	 *
	 * 设置avail event index为vq->last_used_idx
	 */
	if (!(vq->avail_flags_shadow & VRING_AVAIL_F_NO_INTERRUPT))
		virtio_store_mb(vq->weak_barriers,
				&vring_used_event(&vq->vring),
				cpu_to_virtio16(_vq->vdev, vq->last_used_idx));

#ifdef DEBUG
	vq->last_add_time_valid = false;
#endif

	END_USE(vq);
	return ret;
}
EXPORT_SYMBOL_GPL(virtqueue_get_buf_ctx);

void *virtqueue_get_buf(struct virtqueue *_vq, unsigned int *len)
{
	return virtqueue_get_buf_ctx(_vq, len, NULL);
}
EXPORT_SYMBOL_GPL(virtqueue_get_buf);
/**
 * virtqueue_disable_cb - disable callbacks
 * @vq: the struct virtqueue we're talking about.
 *
 * Note that this is not necessarily synchronous, hence unreliable and only
 * useful as an optimization.
 *
 * Unlike other operations, this need not be serialized.
 */
void virtqueue_disable_cb(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (!(vq->avail_flags_shadow & VRING_AVAIL_F_NO_INTERRUPT)) {
		vq->avail_flags_shadow |= VRING_AVAIL_F_NO_INTERRUPT;
		if (!vq->event)
			vq->vring.avail->flags = cpu_to_virtio16(_vq->vdev, vq->avail_flags_shadow);
	}

}
EXPORT_SYMBOL_GPL(virtqueue_disable_cb);

/**
 * virtqueue_enable_cb_prepare - restart callbacks after disable_cb
 * @vq: the struct virtqueue we're talking about.
 *
 * This re-enables callbacks; it returns current queue state
 * in an opaque unsigned value. This value should be later tested by
 * virtqueue_poll, to detect a possible race between the driver checking for
 * more work, and enabling callbacks.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 */
unsigned virtqueue_enable_cb_prepare(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 last_used_idx;

	START_USE(vq);

	/* We optimistically turn back on interrupts, then check if there was
	 * more to do. */
	/* Depending on the VIRTIO_RING_F_EVENT_IDX feature, we need to
	 * either clear the flags bit or point the event index at the next
	 * entry. Always do both to keep code simple. */
	if (vq->avail_flags_shadow & VRING_AVAIL_F_NO_INTERRUPT) {
		vq->avail_flags_shadow &= ~VRING_AVAIL_F_NO_INTERRUPT;
		if (!vq->event)
			vq->vring.avail->flags = cpu_to_virtio16(_vq->vdev, vq->avail_flags_shadow);
	}
	vring_used_event(&vq->vring) = cpu_to_virtio16(_vq->vdev, last_used_idx = vq->last_used_idx);
	END_USE(vq);
	return last_used_idx;
}
EXPORT_SYMBOL_GPL(virtqueue_enable_cb_prepare);

/**
 * virtqueue_poll - query pending used buffers
 * @vq: the struct virtqueue we're talking about.
 * @last_used_idx: virtqueue state (from call to virtqueue_enable_cb_prepare).
 *
 * Returns "true" if there are pending used buffers in the queue.
 *
 * This does not need to be serialized.
 */
bool virtqueue_poll(struct virtqueue *_vq, unsigned last_used_idx)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	virtio_mb(vq->weak_barriers);
	return (u16)last_used_idx != virtio16_to_cpu(_vq->vdev, vq->vring.used->idx);
}
EXPORT_SYMBOL_GPL(virtqueue_poll);

/**
 * virtqueue_enable_cb - restart callbacks after disable_cb.
 * @vq: the struct virtqueue we're talking about.
 *
 * This re-enables callbacks; it returns "false" if there are pending
 * buffers in the queue, to detect a possible race between the driver
 * checking for more work, and enabling callbacks.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 */
bool virtqueue_enable_cb(struct virtqueue *_vq)
{
	unsigned last_used_idx = virtqueue_enable_cb_prepare(_vq);
	return !virtqueue_poll(_vq, last_used_idx);
}
EXPORT_SYMBOL_GPL(virtqueue_enable_cb);

/**
 * virtqueue_enable_cb_delayed - restart callbacks after disable_cb.
 * @vq: the struct virtqueue we're talking about.
 *
 * This re-enables callbacks but hints to the other side to delay
 * interrupts until most of the available buffers have been processed;
 * it returns "false" if there are many pending buffers in the queue,
 * to detect a possible race between the driver checking for more work,
 * and enabling callbacks.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 */
bool virtqueue_enable_cb_delayed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 bufs;

	START_USE(vq);

	/* We optimistically turn back on interrupts, then check if there was
	 * more to do. */
	/* Depending on the VIRTIO_RING_F_USED_EVENT_IDX feature, we need to
	 * either clear the flags bit or point the event index at the next
	 * entry. Always update the event index to keep code simple. */
	if (vq->avail_flags_shadow & VRING_AVAIL_F_NO_INTERRUPT) {
		vq->avail_flags_shadow &= ~VRING_AVAIL_F_NO_INTERRUPT;
		if (!vq->event)
			vq->vring.avail->flags = cpu_to_virtio16(_vq->vdev, vq->avail_flags_shadow);
	}
	/* TODO: tune this threshold */
	bufs = (u16)(vq->avail_idx_shadow - vq->last_used_idx) * 3 / 4;

	virtio_store_mb(vq->weak_barriers,
			&vring_used_event(&vq->vring),
			cpu_to_virtio16(_vq->vdev, vq->last_used_idx + bufs));

	if (unlikely((u16)(virtio16_to_cpu(_vq->vdev, vq->vring.used->idx) - vq->last_used_idx) > bufs)) {
		END_USE(vq);
		return false;
	}

	END_USE(vq);
	return true;
}
EXPORT_SYMBOL_GPL(virtqueue_enable_cb_delayed);

/**
 * virtqueue_detach_unused_buf - detach first unused buffer
 * @vq: the struct virtqueue we're talking about.
 *
 * Returns NULL or the "data" token handed to virtqueue_add_*().
 * This is not valid on an active queue; it is useful only for device
 * shutdown.
 */
void *virtqueue_detach_unused_buf(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	unsigned int i;
	void *buf;

	START_USE(vq);

	for (i = 0; i < vq->vring.num; i++) {
		if (!vq->desc_state[i].data)
			continue;
		/* detach_buf clears data, so grab it now. */
		buf = vq->desc_state[i].data;
		detach_buf(vq, i, NULL);
		vq->avail_idx_shadow--;
		vq->vring.avail->idx = cpu_to_virtio16(_vq->vdev, vq->avail_idx_shadow);
		END_USE(vq);
		return buf;
	}
	/* That should have freed everything. */
	BUG_ON(vq->vq.num_free != vq->vring.num);

	END_USE(vq);
	return NULL;
}
EXPORT_SYMBOL_GPL(virtqueue_detach_unused_buf);

/*
 * vp_interrupt()
 *  vp_vring_interrupt()
 *   vring_interrupt()
 */
irqreturn_t vring_interrupt(int irq, void *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (!more_used(vq)) {
		pr_debug("virtqueue interrupt with no work for %p\n", vq);
		return IRQ_NONE;
	}

	if (unlikely(vq->broken))
		return IRQ_HANDLED;

	pr_debug("virtqueue callback for %p (%p)\n", vq, vq->vq.callback);
	if (vq->vq.callback)
		vq->vq.callback(&vq->vq);

	return IRQ_HANDLED;
}
EXPORT_SYMBOL_GPL(vring_interrupt);

/*
 * vring_create_virtqueue()
 *  __vring_new_virtqueue()
 */
struct virtqueue *__vring_new_virtqueue(unsigned int index,
					struct vring vring,
					struct virtio_device *vdev,
					bool weak_barriers,
					bool context,
					bool (*notify)(struct virtqueue *), /* 用来通知virtio设备的函数 */
					void (*callback)(struct virtqueue *), /* virtio设备使用了descriptor      table之后virtio驱动会调用的函数 */
					const char *name)
{
	unsigned int i;
	struct vring_virtqueue *vq;

    //分配vring_virtqueue对象
	vq = kmalloc(sizeof(*vq) + vring.num * sizeof(struct vring_desc_state),
		     GFP_KERNEL);
	if (!vq)
		return NULL;

    //复制过来
	vq->vring = vring;
	vq->vq.callback = callback;
	vq->vq.vdev = vdev;
	vq->vq.name = name;
	vq->vq.num_free = vring.num;
	vq->vq.index = index;
	vq->we_own_ring = false;
	vq->queue_dma_addr = 0;
	vq->queue_size_in_bytes = 0;
	vq->notify = notify;
	vq->weak_barriers = weak_barriers;
	vq->broken = false;
	vq->last_used_idx = 0;
	vq->avail_flags_shadow = 0;
	vq->avail_idx_shadow = 0;
	vq->num_added = 0;

	//每个virtio_device可以有多个virtqueue对象
	list_add_tail(&vq->vq.list, &vdev->vqs);
	
#ifdef DEBUG
	vq->in_use = false;
	vq->last_add_time_valid = false;
#endif

	vq->indirect = virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC) &&
		!context;
	vq->event = virtio_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX);

	/* No callback?  Tell other side not to bother us. */
	if (!callback) {
		vq->avail_flags_shadow |= VRING_AVAIL_F_NO_INTERRUPT;
		if (!vq->event)
			vq->vring.avail->flags = cpu_to_virtio16(vdev, vq->avail_flags_shadow);
	}

	/* Put everything in free lists. */
	vq->free_head = 0;
	//给desc建立链表啊
	for (i = 0; i < vring.num-1; i++)
		vq->vring.desc[i].next = cpu_to_virtio16(vdev, i + 1);
	
	memset(vq->desc_state, 0, vring.num * sizeof(struct vring_desc_state));

	return &vq->vq;
}
EXPORT_SYMBOL_GPL(__vring_new_virtqueue);

static void *vring_alloc_queue(struct virtio_device *vdev, size_t size,
			      dma_addr_t *dma_handle, gfp_t flag)
{
	if (vring_use_dma_api(vdev)) {
		return dma_alloc_coherent(vdev->dev.parent, size,
					  dma_handle, flag);
	} else {
		void *queue = alloc_pages_exact(PAGE_ALIGN(size), flag);
		if (queue) {
			phys_addr_t phys_addr = virt_to_phys(queue);
			*dma_handle = (dma_addr_t)phys_addr;

			/*
			 * Sanity check: make sure we dind't truncate
			 * the address.  The only arches I can find that
			 * have 64-bit phys_addr_t but 32-bit dma_addr_t
			 * are certain non-highmem MIPS and x86
			 * configurations, but these configurations
			 * should never allocate physical pages above 32
			 * bits, so this is fine.  Just in case, throw a
			 * warning and abort if we end up with an
			 * unrepresentable address.
			 */
			if (WARN_ON_ONCE(*dma_handle != phys_addr)) {
				free_pages_exact(queue, PAGE_ALIGN(size));
				return NULL;
			}
		}
		return queue;
	}
}

static void vring_free_queue(struct virtio_device *vdev, size_t size,
			     void *queue, dma_addr_t dma_handle)
{
	if (vring_use_dma_api(vdev)) {
		dma_free_coherent(vdev->dev.parent, size, queue, dma_handle);
	} else {
		free_pages_exact(queue, PAGE_ALIGN(size));
	}
}

/*
 * vm_find_vqs()
 *  vm_setup_vq()
 *   vring_create_virtqueue()
 *
 * kernel_init()
 *  kernel_init_freeable()
 *   do_basic_setup()
 *	  do_initcalls()
 *	   ...
 *	    virtballoon_probe()
 *		 init_vqs()
 *		  virtio_find_vqs()
 *		   vp_modern_find_vqs()
 *		    vp_find_vqs()
 *			 vp_find_vqs_intx()
 *            vp_setup_vq()
 *             setup_vq() 
 *              vring_create_virtqueue()
 */
struct virtqueue *vring_create_virtqueue(
	unsigned int index,
	unsigned int num,
	unsigned int vring_align,
	struct virtio_device *vdev,
	bool weak_barriers,
	bool may_reduce_num,
	bool context,
	bool (*notify)(struct virtqueue *),/* 用来通知virtio设备的函数 */
	void (*callback)(struct virtqueue *), /* virtio设备使用了descriptor      table之后virtio驱动会调用的函数 */
	const char *name)
{
	struct virtqueue *vq;
	//queue就是vring_desc数组,vring->avail,vring->desc,vring->used都指向这个
	void *queue = NULL;
	dma_addr_t dma_addr;
	size_t queue_size_in_bytes;
	struct vring vring;

	/* We assume num is a power of 2. */
	if (num & (num - 1)) {
		dev_warn(&vdev->dev, "Bad virtqueue length %u\n", num);
		return NULL;
	}

	/* TODO: allocate each queue chunk individually */
	for (; num && vring_size(num, vring_align) > PAGE_SIZE; num /= 2) {
		queue = vring_alloc_queue(vdev, vring_size(num, vring_align),
					  &dma_addr,
					  GFP_KERNEL|__GFP_NOWARN|__GFP_ZERO);
		if (queue)
			break;
	}

	if (!num)//num为0了
		return NULL;

	if (!queue) { //前面分配失败，再一次尝试分配
		/* Try to get a single page. You are my only hope! */
		queue = vring_alloc_queue(vdev, vring_size(num, vring_align),
					  &dma_addr, GFP_KERNEL|__GFP_ZERO);
	}
	if (!queue)
		return NULL;

	queue_size_in_bytes = vring_size(num, vring_align);

	//queue作为vring->desc
	vring_init(&vring, num, queue, vring_align);

    /*
     * 创建一个virt_virtqueue
     */
	vq = __vring_new_virtqueue(index, vring, vdev, weak_barriers, context,
				   notify, callback, name);
	if (!vq) {
		vring_free_queue(vdev, queue_size_in_bytes, queue,
				 dma_addr);
		return NULL;
	}

	to_vvq(vq)->queue_dma_addr = dma_addr;
	to_vvq(vq)->queue_size_in_bytes = queue_size_in_bytes;
	to_vvq(vq)->we_own_ring = true;

	return vq;
}
EXPORT_SYMBOL_GPL(vring_create_virtqueue);

struct virtqueue *vring_new_virtqueue(unsigned int index,
				      unsigned int num,
				      unsigned int vring_align,
				      struct virtio_device *vdev,
				      bool weak_barriers,
				      bool context,
				      void *pages,
				      bool (*notify)(struct virtqueue *vq),
				      void (*callback)(struct virtqueue *vq),
				      const char *name)
{
	struct vring vring;
	vring_init(&vring, num, pages, vring_align);
	return __vring_new_virtqueue(index, vring, vdev, weak_barriers, context,
				     notify, callback, name);
}
EXPORT_SYMBOL_GPL(vring_new_virtqueue);

void vring_del_virtqueue(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->we_own_ring) {
		vring_free_queue(vq->vq.vdev, vq->queue_size_in_bytes,
				 vq->vring.desc, vq->queue_dma_addr);
	}
	list_del(&_vq->list);
	kfree(vq);
}
EXPORT_SYMBOL_GPL(vring_del_virtqueue);

/* Manipulates transport-specific feature bits. */
void vring_transport_features(struct virtio_device *vdev)
{
	unsigned int i;

	for (i = VIRTIO_TRANSPORT_F_START; i < VIRTIO_TRANSPORT_F_END; i++) {
		switch (i) {
		case VIRTIO_RING_F_INDIRECT_DESC:
			break;
		case VIRTIO_RING_F_EVENT_IDX:
			break;
		case VIRTIO_F_VERSION_1:
			break;
		case VIRTIO_F_IOMMU_PLATFORM:
			break;
		default:
			/* We don't understand this bit. */
			__virtio_clear_bit(vdev, i);
		}
	}
}
EXPORT_SYMBOL_GPL(vring_transport_features);

/**
 * virtqueue_get_vring_size - return the size of the virtqueue's vring
 * @vq: the struct virtqueue containing the vring of interest.
 *
 * Returns the size of the vring.  This is mainly used for boasting to
 * userspace.  Unlike other operations, this need not be serialized.
 */
unsigned int virtqueue_get_vring_size(struct virtqueue *_vq)
{

	struct vring_virtqueue *vq = to_vvq(_vq);

	return vq->vring.num;
}
EXPORT_SYMBOL_GPL(virtqueue_get_vring_size);

bool virtqueue_is_broken(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	return vq->broken;
}
EXPORT_SYMBOL_GPL(virtqueue_is_broken);

/*
 * This should prevent the device from being used, allowing drivers to
 * recover.  You may need to grab appropriate locks to flush.
 */
void virtio_break_device(struct virtio_device *dev)
{
	struct virtqueue *_vq;

	list_for_each_entry(_vq, &dev->vqs, list) {
		struct vring_virtqueue *vq = to_vvq(_vq);
		vq->broken = true;
	}
}
EXPORT_SYMBOL_GPL(virtio_break_device);

dma_addr_t virtqueue_get_desc_addr(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	BUG_ON(!vq->we_own_ring);

	return vq->queue_dma_addr;
}
EXPORT_SYMBOL_GPL(virtqueue_get_desc_addr);

dma_addr_t virtqueue_get_avail_addr(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	BUG_ON(!vq->we_own_ring);

	return vq->queue_dma_addr +
		((char *)vq->vring.avail - (char *)vq->vring.desc);
}
EXPORT_SYMBOL_GPL(virtqueue_get_avail_addr);

dma_addr_t virtqueue_get_used_addr(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	BUG_ON(!vq->we_own_ring);

	return vq->queue_dma_addr +
		((char *)vq->vring.used - (char *)vq->vring.desc);
}
EXPORT_SYMBOL_GPL(virtqueue_get_used_addr);

const struct vring *virtqueue_get_vring(struct virtqueue *vq)
{
	return &to_vvq(vq)->vring;
}
EXPORT_SYMBOL_GPL(virtqueue_get_vring);

MODULE_LICENSE("GPL");
