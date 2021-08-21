/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_H
#define _LINUX_VIRTIO_H
/* Everything a virtio driver needs to work with any particular virtio
 * implementation. */
#include <linux/types.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include <linux/gfp.h>
#include <linux/vringh.h>

/**
 * virtqueue - a queue to register buffers for sending or receiving.
 * @list: the chain of virtqueues for this device
 * @callback: the function to call when buffers are consumed (can be NULL).
 * @name: the name of this virtqueue (mainly for debugging)
 * @vdev: the virtio device this queue was created for.
 * @priv: a pointer for the virtqueue implementation to use.
 * @index: the zero-based ordinal number for this queue.
 * @num_free: number of elements we expect to be able to fit.
 *
 * A note on @num_free: with indirect buffers, each buffer needs one
 * element in the queue, otherwise a buffer will need one element per
 * sg element.
 *
 * 看vring_virtqueue, vring_virtqueue包含了virtqueue和vring
 *
 * 作为vring_virtqueue成员,在__vring_new_virtqueue中分配
 */
struct virtqueue {
    /*
     * 链接virtqueue
     *
     * 链接到virtio_pci_device->vdev->vqs->vqs
     */
	struct list_head list;
	/*
	 * 当buffer被使用后调用这个callback函数进行通知
	 */
	void (*callback)(struct virtqueue *vq);
	const char *name;
	/*
	 * virtqueue所属的virtio_device
	 */
	struct virtio_device *vdev;
	/* 
	 * 将index写入到保存在virtqueue->private这个地址,产生VM exit
	 */
	unsigned int index;
	unsigned int num_free;
	/*私有指针,看vp_notify() ,virtqueue->index 写到priv,通知对端*/
	void *priv;
};

int virtqueue_add_outbuf(struct virtqueue *vq,
			 struct scatterlist sg[], unsigned int num,
			 void *data,
			 gfp_t gfp);

int virtqueue_add_inbuf(struct virtqueue *vq,
			struct scatterlist sg[], unsigned int num,
			void *data,
			gfp_t gfp);

int virtqueue_add_inbuf_ctx(struct virtqueue *vq,
			    struct scatterlist sg[], unsigned int num,
			    void *data,
			    void *ctx,
			    gfp_t gfp);

int virtqueue_add_sgs(struct virtqueue *vq,
		      struct scatterlist *sgs[],
		      unsigned int out_sgs,
		      unsigned int in_sgs,
		      void *data,
		      gfp_t gfp);

bool virtqueue_kick(struct virtqueue *vq);

bool virtqueue_kick_prepare(struct virtqueue *vq);

bool virtqueue_notify(struct virtqueue *vq);

void *virtqueue_get_buf(struct virtqueue *vq, unsigned int *len);

void *virtqueue_get_buf_ctx(struct virtqueue *vq, unsigned int *len,
			    void **ctx);

void virtqueue_disable_cb(struct virtqueue *vq);

bool virtqueue_enable_cb(struct virtqueue *vq);

unsigned virtqueue_enable_cb_prepare(struct virtqueue *vq);

bool virtqueue_poll(struct virtqueue *vq, unsigned);

bool virtqueue_enable_cb_delayed(struct virtqueue *vq);

void *virtqueue_detach_unused_buf(struct virtqueue *vq);

unsigned int virtqueue_get_vring_size(struct virtqueue *vq);

bool virtqueue_is_broken(struct virtqueue *vq);

const struct vring *virtqueue_get_vring(struct virtqueue *vq);
dma_addr_t virtqueue_get_desc_addr(struct virtqueue *vq);
dma_addr_t virtqueue_get_avail_addr(struct virtqueue *vq);
dma_addr_t virtqueue_get_used_addr(struct virtqueue *vq);

/*
 * Legacy accessors -- in almost all cases, these are the wrong functions
 * to use.
 */
static inline void *virtqueue_get_desc(struct virtqueue *vq)
{
	return virtqueue_get_vring(vq)->desc;
}
static inline void *virtqueue_get_avail(struct virtqueue *vq)
{
	return virtqueue_get_vring(vq)->avail;
}
static inline void *virtqueue_get_used(struct virtqueue *vq)
{
	return virtqueue_get_vring(vq)->used;
}

/**
 * virtio_device - representation of a device using virtio
 * @index: unique position on the virtio bus
 * @failed: saved value for VIRTIO_CONFIG_S_FAILED bit (for restore)
 * @config_enabled: configuration change reporting enabled
 * @config_change_pending: configuration change reported while disabled
 * @config_lock: protects configuration change reporting
 * @dev: underlying device.
 * @id: the device type identification (used to match it with a driver).
 * @config: the configuration ops for this device.
 * @vringh_config: configuration ops for host vrings.
 * @vqs: the list of virtqueues for this device.
 * @features: the features supported by both driver and device.
 * @priv: private pointer for the driver's use.
 *
 * 作为virtio_pci_device->vdev成员
 */
struct virtio_device {
	/*virtio bus中的唯一表示*/
	int index;
	bool failed;
	bool config_enabled;
	bool config_change_pending;
	spinlock_t config_lock;
	/*设备对象*/
	struct device dev;
	/*设备类型唯一标识，用于识别设备driver*/
	struct virtio_device_id id;
	/*设备配置操作函数指针
	 *
	 * virtio_pci_config_ops
	 */
	const struct virtio_config_ops *config;
	const struct vringh_config_ops *vringh_config;
	/*
	 * 本virtio_device的virtio_queue，一个设备可以多个，用于数据传输
	 *
	 * 在__vring_new_virtqueue()中设置
	 *
	 * 链接到virtqueue->list
	 */
	struct list_head vqs;
	/*设备和driver支持的特性*/
	u64 features;
	/*供driver使用的私有指针*/
	void *priv;
};

static inline struct virtio_device *dev_to_virtio(struct device *_dev)
{
	return container_of(_dev, struct virtio_device, dev);
}

void virtio_add_status(struct virtio_device *dev, unsigned int status);
int register_virtio_device(struct virtio_device *dev);
void unregister_virtio_device(struct virtio_device *dev);

void virtio_break_device(struct virtio_device *dev);

void virtio_config_changed(struct virtio_device *dev);
void virtio_config_disable(struct virtio_device *dev);
void virtio_config_enable(struct virtio_device *dev);
int virtio_finalize_features(struct virtio_device *dev);
#ifdef CONFIG_PM_SLEEP
int virtio_device_freeze(struct virtio_device *dev);
int virtio_device_restore(struct virtio_device *dev);
#endif

#define virtio_device_for_each_vq(vdev, vq) \
	list_for_each_entry(vq, &vdev->vqs, list)

/**
 * virtio_driver - operations for a virtio I/O driver
 * @driver: underlying device driver (populate name and owner).
 * @id_table: the ids serviced by this driver.
 * @feature_table: an array of feature numbers supported by this driver.
 * @feature_table_size: number of entries in the feature table array.
 * @feature_table_legacy: same as feature_table but when working in legacy mode.
 * @feature_table_size_legacy: number of entries in feature table legacy array.
 * @probe: the function to call when a device is found.  Returns 0 or -errno.
 * @scan: optional function to call after successful probe; intended
 *    for virtio-scsi to invoke a scan.
 * @remove: the function to call when a device is removed.
 * @config_changed: optional function to call when the device configuration
 *    changes; may be called in interrupt context.
 * @freeze: optional function to call during suspend/hibernation.
 * @restore: optional function to call on resume.
 *
 * ,
 */
struct virtio_driver {
    /*driver对象*/
	struct device_driver driver;
	/*driver id*/
	const struct virtio_device_id *id_table;
	/*这个设备支持的特性列表，以数组形式存在这个表中*/
	const unsigned int *feature_table;
	/*特性表长度*/
	unsigned int feature_table_size;
	
	const unsigned int *feature_table_legacy;
	unsigned int feature_table_size_legacy;
	int (*validate)(struct virtio_device *dev);
	/*设备发现时调用，0成功，-errono错误*/
	int (*probe)(struct virtio_device *dev);
	void (*scan)(struct virtio_device *dev);
	/*设备删除时调用*/
	void (*remove)(struct virtio_device *dev);
	/*在设备配置发生改变时调用*/
	void (*config_changed)(struct virtio_device *dev);
#ifdef CONFIG_PM
	int (*freeze)(struct virtio_device *dev);
	int (*restore)(struct virtio_device *dev);
#endif
};

static inline struct virtio_driver *drv_to_virtio(struct device_driver *drv)
{
	return container_of(drv, struct virtio_driver, driver);
}

int register_virtio_driver(struct virtio_driver *drv);
void unregister_virtio_driver(struct virtio_driver *drv);

/* module_virtio_driver() - Helper macro for drivers that don't do
 * anything tes a lot of
 * boilerplate.  Each module may only use this macro once, and
 * calling it replaces module_init() and module_exit()
 */
#define module_virtio_driver(__virtio_driver) \
	module_driver(__virtio_driver, register_virtio_driver, \
			unregister_virtio_driver)
#endif /* _LINUX_VIRTIO_H */
