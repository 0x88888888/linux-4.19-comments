/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __KVM_IODEV_H__
#define __KVM_IODEV_H__

#include <linux/kvm_types.h>
#include <linux/errno.h>

struct kvm_io_device;
struct kvm_vcpu;

/**
 * kvm_io_device_ops are called under kvm slots_lock.
 * read and write handlers return 0 if the transaction has been handled,
 * or non-zero to have it passed to the next device.
 *
 * coalesced_mmio_ops,
 * ioeventfd_ops,
 * pit_dev_ops,
 * speaker_dev_ops,
 * picdev_master_ops,
 * picdev_slave_ops,
 * picdev_eclr_ops,
 * ioapic_mmio_ops,
 * apic_mmio_ops,
 * mpic_mmio_ops,
 * kvm_io_gic_ops
 *
 * 这些函数在 kvm_iodevice_read(),kvm_iodevice_write中调用
 **/
struct kvm_io_device_ops {
	int (*read)(struct kvm_vcpu *vcpu,
		    struct kvm_io_device *this,
		    gpa_t addr,
		    int len,
		    void *val);
	int (*write)(struct kvm_vcpu *vcpu,
		     struct kvm_io_device *this,
		     gpa_t addr,
		     int len,
		     const void *val);
	void (*destructor)(struct kvm_io_device *this);
};


struct kvm_io_device {
	/*
	 * ioeventfd_ops,pit_dev_ops
	 * picdev_master_ops,picdev_slave_ops,picdev_eclr_ops
	 * ioapic_mmio_ops,apic_mmio_ops
	 *
	 * 这些函数在kvm_iodevice_read(),kvm_iodevice_write中调用
	 */
	const struct kvm_io_device_ops *ops;
};

static inline void kvm_iodevice_init(struct kvm_io_device *dev,
				     const struct kvm_io_device_ops *ops)
{
	dev->ops = ops;
}

/*
 * kernel_pio()
 *  kvm_io_bus_read()
 *   __kvm_io_bus_read()
 *    kvm_iodevice_read()
 */
static inline int kvm_iodevice_read(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev, gpa_t addr,
				    int l, void *v)
{
   /*
    * ioeventfd_ops.read == NULL
    */
	return dev->ops->read ? dev->ops->read(vcpu, dev, addr, l, v)
				: -EOPNOTSUPP;
}

/*
 * handle_io()
 *  ....
 *   kernel_pio()
 *    kvm_io_bus_write()
 * 	   __kvm_io_bus_write()
 *      kvm_iodevice_write()
 *
 * handle_io()
 *  ...
 *   vcpu_mmio_write()
 *    kvm_io_bus_write()
 * 	   __kvm_io_bus_write()
 *      kvm_iodevice_write()
 */
static inline int kvm_iodevice_write(struct kvm_vcpu *vcpu,
				     struct kvm_io_device *dev, gpa_t addr,
				     int l, const void *v)
{
    /*
     * ioeventfd_ops.write==ioeventfd_write
     */
	return dev->ops->write ? dev->ops->write(vcpu, dev, addr, l, v)
				 : -EOPNOTSUPP;
}

static inline void kvm_iodevice_destructor(struct kvm_io_device *dev)
{
	if (dev->ops->destructor)
		dev->ops->destructor(dev);
}

#endif /* __KVM_IODEV_H__ */
