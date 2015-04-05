/*
 * LIRC base driver
 *
 * by Artur Lipowski <alipowski@interia.pl>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/unistd.h>
#include <linux/kthread.h>
#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/smp_lock.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "lirc.h"
#include "lirc_dev.h"

static int debug;
#define dprintk(fmt, args...)					\
	do {							\
		if (debug)					\
			printk(KERN_DEBUG fmt, ## args);	\
	} while (0)

#define IRCTL_DEV_NAME    "BaseRemoteCtl"
#define NOPLUG            -1
#define LOGHEAD           "lirc_dev (%s[%d]): "

static dev_t lirc_base_dev;

struct irctl {
	struct lirc_driver d;
	int attached;
	int open;

	struct mutex buffer_lock;
	struct lirc_buffer *buf;
	unsigned int chunk_size;

	struct task_struct *task;
	long jiffies_to_wait;

	struct cdev cdev;
};

static DEFINE_MUTEX(lirc_dev_lock);

static struct irctl *irctls[MAX_IRCTL_DEVICES];

/* Only used for sysfs but defined to void otherwise */
static struct class *lirc_class;

/*  helper function
 *  initializes the irctl structure
 */
static void init_irctl(struct irctl *ir)
{
	dprintk(LOGHEAD "initializing irctl\n", ir->d.name, ir->d.minor);
	mutex_init(&ir->buffer_lock);
	ir->d.minor = NOPLUG;
}

static void cleanup(struct irctl *ir)
{
	dprintk(LOGHEAD "cleaning up\n", ir->d.name, ir->d.minor);

	device_destroy(lirc_class, MKDEV(MAJOR(lirc_base_dev), ir->d.minor));

	if (ir->buf != ir->d.rbuf) {
		lirc_buffer_free(ir->buf);
		kfree(ir->buf);
	}
	ir->buf = NULL;
}

/*  helper function
 *  reads key codes from driver and puts them into buffer
 *  returns 0 on success
 */
static int add_to_buf(struct irctl *ir)
{
	if (ir->d.add_to_buf) {
		int res = -ENODATA;
		int got_data = 0;

		/*
		 * service the device as long as it is returning
		 * data and we have space
		 */
get_data:
		res = ir->d.add_to_buf(ir->d.data, ir->buf);
		if (res == 0) {
			got_data++;
			goto get_data;
		}

		if (res == -ENODEV)
			kthread_stop(ir->task);

		return got_data ? 0 : res;
	}

	return 0;
}

/* main function of the polling thread
 */
static int lirc_thread(void *irctl)
{
	struct irctl *ir = irctl;

	dprintk(LOGHEAD "poll thread started\n", ir->d.name, ir->d.minor);

	do {
		if (ir->open) {
			if (ir->jiffies_to_wait) {
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(ir->jiffies_to_wait);
			}
			if (kthread_should_stop())
				break;
			if (!add_to_buf(ir))
				wake_up_interruptible(&ir->buf->wait_poll);
		} else {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
		}
	} while (!kthread_should_stop());

	dprintk(LOGHEAD "poll thread ended\n", ir->d.name, ir->d.minor);

	return 0;
}


static struct file_operations fops = {
	.owner		= THIS_MODULE,
	.read		= lirc_dev_fop_read,
	.write		= lirc_dev_fop_write,
	.poll		= lirc_dev_fop_poll,
	.ioctl		= lirc_dev_fop_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= lirc_dev_fop_compat_ioctl,
#endif
	.open		= lirc_dev_fop_open,
	.release	= lirc_dev_fop_close,
};

static int lirc_cdev_add(struct irctl *ir)
{
	int retval;
	struct lirc_driver *d = &ir->d;

	if (d->fops) {
		cdev_init(&ir->cdev, d->fops);
		ir->cdev.owner = d->owner;
	} else {
		cdev_init(&ir->cdev, &fops);
		ir->cdev.owner = THIS_MODULE;
	}
	kobject_set_name(&ir->cdev.kobj, "lirc%d", d->minor);

	retval = cdev_add(&ir->cdev, MKDEV(MAJOR(lirc_base_dev), d->minor), 1);
	if (retval)
		kobject_put(&ir->cdev.kobj);

	return retval;
}

int lirc_register_driver(struct lirc_driver *d)
{
	struct irctl *ir;
	int minor;
	int bytes_in_key;
	unsigned int chunk_size;
	unsigned int buffer_size;
	int err;

	if (!d) {
		printk(KERN_ERR "lirc_dev: lirc_register_driver: "
		       "driver pointer must be not NULL!\n");
		err = -EBADRQC;
		goto out;
	}

	if (MAX_IRCTL_DEVICES <= d->minor) {
		printk(KERN_ERR "lirc_dev: lirc_register_driver: "
		       "\"minor\" must be between 0 and %d (%d)!\n",
		       MAX_IRCTL_DEVICES-1, d->minor);
		err = -EBADRQC;
		goto out;
	}

	if (1 > d->code_length || (BUFLEN * 8) < d->code_length) {
		printk(KERN_ERR "lirc_dev: lirc_register_driver: "
		       "code length in bits for minor (%d) "
		       "must be less than %d!\n",
		       d->minor, BUFLEN * 8);
		err = -EBADRQC;
		goto out;
	}

	printk(KERN_INFO "lirc_dev: lirc_register_driver: sample_rate: %d\n",
		d->sample_rate);
	if (d->sample_rate) {
		if (2 > d->sample_rate || HZ < d->sample_rate) {
			printk(KERN_ERR "lirc_dev: lirc_register_driver: "
			       "sample_rate must be between 2 and %d!\n", HZ);
			err = -EBADRQC;
			goto out;
		}
		if (!d->add_to_buf) {
			printk(KERN_ERR "lirc_dev: lirc_register_driver: "
			       "add_to_buf cannot be NULL when "
			       "sample_rate is set\n");
			err = -EBADRQC;
			goto out;
		}
	} else if (!(d->fops && d->fops->read) && !d->rbuf) {
		printk(KERN_ERR "lirc_dev: lirc_register_driver: "
		       "fops->read and rbuf "
		       "cannot all be NULL!\n");
		err = -EBADRQC;
		goto out;
	} else if (!d->rbuf) {
		if (!(d->fops && d->fops->read && d->fops->poll &&
		      d->fops->ioctl)) {
			printk(KERN_ERR "lirc_dev: lirc_register_driver: "
			       "neither read, poll nor ioctl can be NULL!\n");
			err = -EBADRQC;
			goto out;
		}
	}

	mutex_lock(&lirc_dev_lock);

	minor = d->minor;

	if (minor < 0) {
		/* find first free slot for driver */
		for (minor = 0; minor < MAX_IRCTL_DEVICES; minor++)
			if (!irctls[minor])
				break;
		if (MAX_IRCTL_DEVICES == minor) {
			printk(KERN_ERR "lirc_dev: lirc_register_driver: "
			       "no free slots for drivers!\n");
			err = -ENOMEM;
			goto out_lock;
		}
	} else if (irctls[minor]) {
		printk(KERN_ERR "lirc_dev: lirc_register_driver: "
		       "minor (%d) just registered!\n", minor);
		err = -EBUSY;
		goto out_lock;
	}

	ir = kzalloc(sizeof(struct irctl), GFP_KERNEL);
	if (!ir) {
		err = -ENOMEM;
		goto out_lock;
	}
	init_irctl(ir);
	irctls[minor] = ir;
	d->minor = minor;

	if (d->sample_rate) {
		ir->jiffies_to_wait = HZ / d->sample_rate;
	} else {
		/* it means - wait for external event in task queue */
		ir->jiffies_to_wait = 0;
	}

	/* some safety check 8-) */
	d->name[sizeof(d->name)-1] = '\0';

	bytes_in_key = BITS_TO_LONGS(d->code_length) +
			(d->code_length % 8 ? 1 : 0);
	buffer_size = d->buffer_size ? d->buffer_size : BUFLEN / bytes_in_key;
	chunk_size  = d->chunk_size  ? d->chunk_size  : bytes_in_key;

	if (d->rbuf) {
		ir->buf = d->rbuf;
	} else {
		ir->buf = kmalloc(sizeof(struct lirc_buffer), GFP_KERNEL);
		if (!ir->buf) {
			err = -ENOMEM;
			goto out_lock;
		}
		err = lirc_buffer_init(ir->buf, chunk_size, buffer_size);
		if (err) {
			kfree(ir->buf);
			goto out_lock;
		}
	}
	ir->chunk_size = ir->buf->chunk_size;

	if (d->features == 0)
		d->features = (d->code_length > 8) ?
			LIRC_CAN_REC_LIRCCODE : LIRC_CAN_REC_CODE;

	ir->d = *d;
	ir->d.minor = minor;

	device_create(lirc_class, ir->d.dev,
		      MKDEV(MAJOR(lirc_base_dev), ir->d.minor), NULL,
		      "lirc%u", ir->d.minor);

	if (d->sample_rate) {
		/* try to fire up polling thread */
		ir->task = kthread_run(lirc_thread, (void *)ir, "lirc_dev");
		if (IS_ERR(ir->task)) {
			printk(KERN_ERR "lirc_dev: lirc_register_driver: "
			       "cannot run poll thread for minor = %d\n",
			       d->minor);
			err = -ECHILD;
			goto out_sysfs;
		}
	}

	err = lirc_cdev_add(ir);
	if (err)
		goto out_sysfs;

	ir->attached = 1;
	mutex_unlock(&lirc_dev_lock);

	dprintk("lirc_dev: driver %s registered at minor number = %d\n",
		ir->d.name, ir->d.minor);
	return minor;

out_sysfs:
	device_destroy(lirc_class, MKDEV(MAJOR(lirc_base_dev), ir->d.minor));
out_lock:
	mutex_unlock(&lirc_dev_lock);
out:
	return err;
}
EXPORT_SYMBOL(lirc_register_driver);

int lirc_unregister_driver(int minor)
{
	struct irctl *ir;

	if (minor < 0 || minor >= MAX_IRCTL_DEVICES) {
		printk(KERN_ERR "lirc_dev: lirc_unregister_driver: "
		       "\"minor (%d)\" must be between 0 and %d!\n",
		       minor, MAX_IRCTL_DEVICES-1);
		return -EBADRQC;
	}

	ir = irctls[minor];

	mutex_lock(&lirc_dev_lock);

	if (ir->d.minor != minor) {
		printk(KERN_ERR "lirc_dev: lirc_unregister_driver: "
		       "minor (%d) device not registered!", minor);
		mutex_unlock(&lirc_dev_lock);
		return -ENOENT;
	}

	/* end up polling thread */
	if (ir->task)
		kthread_stop(ir->task);

	dprintk("lirc_dev: driver %s unregistered from minor number = %d\n",
		ir->d.name, ir->d.minor);

	ir->attached = 0;
	if (ir->open) {
		dprintk(LOGHEAD "releasing opened driver\n",
			ir->d.name, ir->d.minor);
		wake_up_interruptible(&ir->buf->wait_poll);
		mutex_lock(&ir->buffer_lock);
		ir->d.set_use_dec(ir->d.data);
		module_put(ir->d.owner);
		mutex_unlock(&ir->buffer_lock);
		cdev_del(&ir->cdev);
	} else {
		cleanup(ir);
		cdev_del(&ir->cdev);
		kfree(ir);
		irctls[minor] = NULL;
	}

	mutex_unlock(&lirc_dev_lock);

	return 0;
}
EXPORT_SYMBOL(lirc_unregister_driver);

int lirc_dev_fop_open(struct inode *inode, struct file *file)
{
	struct irctl *ir;
	int retval = 0;

	if (iminor(inode) >= MAX_IRCTL_DEVICES) {
		dprintk("lirc_dev [%d]: open result = -ENODEV\n",
			iminor(inode));
		return -ENODEV;
	}

	if (mutex_lock_interruptible(&lirc_dev_lock))
		return -ERESTARTSYS;

	ir = irctls[iminor(inode)];
	if (!ir) {
		retval = -ENODEV;
		goto error;
	}

	dprintk(LOGHEAD "open called\n", ir->d.name, ir->d.minor);

	if (ir->d.minor == NOPLUG) {
		retval = -ENODEV;
		goto error;
	}

	if (ir->open) {
		retval = -EBUSY;
		goto error;
	}

	if (try_module_get(ir->d.owner)) {
		++ir->open;
		retval = ir->d.set_use_inc(ir->d.data);

		if (retval) {
			module_put(ir->d.owner);
			--ir->open;
		} else {
			lirc_buffer_clear(ir->buf);
		}
		if (ir->task)
			wake_up_process(ir->task);
	}

error:
	if (ir)
		dprintk(LOGHEAD "open result = %d\n", ir->d.name, ir->d.minor,
			retval);

	mutex_unlock(&lirc_dev_lock);

	return retval;
}
EXPORT_SYMBOL(lirc_dev_fop_open);

int lirc_dev_fop_close(struct inode *inode, struct file *file)
{
	struct irctl *ir = irctls[iminor(inode)];

	dprintk(LOGHEAD "close called\n", ir->d.name, ir->d.minor);

	WARN_ON(mutex_lock_killable(&lirc_dev_lock));

	--ir->open;
	if (ir->attached) {
		ir->d.set_use_dec(ir->d.data);
		module_put(ir->d.owner);
	} else {
		cleanup(ir);
		irctls[ir->d.minor] = NULL;
		kfree(ir);
	}

	mutex_unlock(&lirc_dev_lock);

	return 0;
}
EXPORT_SYMBOL(lirc_dev_fop_close);

unsigned int lirc_dev_fop_poll(struct file *file, poll_table *wait)
{
	struct irctl *ir = irctls[iminor(file->f_dentry->d_inode)];
	unsigned int ret;

	dprintk(LOGHEAD "poll called\n", ir->d.name, ir->d.minor);

	if (!ir->attached) {
		mutex_unlock(&ir->buffer_lock);
		return POLLERR;
	}

	poll_wait(file, &ir->buf->wait_poll, wait);

	if (ir->buf)
		if (lirc_buffer_empty(ir->buf))
			ret = 0;
		else
			ret = POLLIN | POLLRDNORM;
	else
		ret = POLLERR;

	dprintk(LOGHEAD "poll result = %d\n",
		ir->d.name, ir->d.minor, ret);

	return ret;
}
EXPORT_SYMBOL(lirc_dev_fop_poll);

int lirc_dev_fop_ioctl(struct inode *inode, struct file *file,
		       unsigned int cmd, unsigned long arg)
{
	unsigned long mode;
	int result = 0;
	struct irctl *ir = irctls[iminor(inode)];

	dprintk(LOGHEAD "ioctl called (0x%x)\n",
		ir->d.name, ir->d.minor, cmd);

	if (ir->d.minor == NOPLUG || !ir->attached) {
		dprintk(LOGHEAD "ioctl result = -ENODEV\n",
			ir->d.name, ir->d.minor);
		return -ENODEV;
	}

	switch (cmd) {
	case LIRC_GET_FEATURES:
		result = put_user(ir->d.features, (unsigned long *)arg);
		break;
	case LIRC_GET_REC_MODE:
		if (!(ir->d.features & LIRC_CAN_REC_MASK))
			return -ENOSYS;

		result = put_user(LIRC_REC2MODE
				  (ir->d.features & LIRC_CAN_REC_MASK),
				  (unsigned long *)arg);
		break;
	case LIRC_SET_REC_MODE:
		if (!(ir->d.features & LIRC_CAN_REC_MASK))
			return -ENOSYS;

		result = get_user(mode, (unsigned long *)arg);
		if (!result && !(LIRC_MODE2REC(mode) & ir->d.features))
			result = -EINVAL;
		/*
		 * FIXME: We should actually set the mode somehow but
		 * for now, lirc_serial doesn't support mode changing either
		 */
		break;
	case LIRC_GET_LENGTH:
		result = put_user(ir->d.code_length, (unsigned long *)arg);
		break;
	default:
		result = -EINVAL;
	}

	dprintk(LOGHEAD "ioctl result = %d\n",
		ir->d.name, ir->d.minor, result);

	return result;
}
EXPORT_SYMBOL(lirc_dev_fop_ioctl);

#ifdef CONFIG_COMPAT
#define LIRC_GET_FEATURES_COMPAT32     _IOR('i', 0x00000000, __u32)

#define LIRC_GET_SEND_MODE_COMPAT32    _IOR('i', 0x00000001, __u32)
#define LIRC_GET_REC_MODE_COMPAT32     _IOR('i', 0x00000002, __u32)

#define LIRC_GET_LENGTH_COMPAT32       _IOR('i', 0x0000000f, __u32)

#define LIRC_SET_SEND_MODE_COMPAT32    _IOW('i', 0x00000011, __u32)
#define LIRC_SET_REC_MODE_COMPAT32     _IOW('i', 0x00000012, __u32)

long lirc_dev_fop_compat_ioctl(struct file *file,
			       unsigned int cmd32,
			       unsigned long arg)
{
	mm_segment_t old_fs;
	int ret;
	unsigned long val;
	unsigned int cmd;

	switch (cmd32) {
	case LIRC_GET_FEATURES_COMPAT32:
	case LIRC_GET_SEND_MODE_COMPAT32:
	case LIRC_GET_REC_MODE_COMPAT32:
	case LIRC_GET_LENGTH_COMPAT32:
	case LIRC_SET_SEND_MODE_COMPAT32:
	case LIRC_SET_REC_MODE_COMPAT32:
		/*
		 * These commands expect (unsigned long *) arg
		 * but the 32-bit app supplied (__u32 *).
		 * Conversion is required.
		 */
		if (get_user(val, (__u32 *)compat_ptr(arg)))
			return -EFAULT;
		lock_kernel();
		/*
		 * tell lirc_dev_fop_ioctl that it's safe to use the pointer
		 * to val which is in kernel address space and not in
		 * user address space.
		 */
		old_fs = get_fs();
		set_fs(KERNEL_DS);

		cmd = _IOC(_IOC_DIR(cmd32), _IOC_TYPE(cmd32), _IOC_NR(cmd32),
		(_IOC_TYPECHECK(unsigned long)));
		ret = lirc_dev_fop_ioctl(file->f_path.dentry->d_inode, file,
					 cmd, (unsigned long)(&val));

		set_fs(old_fs);
		unlock_kernel();
	switch (cmd) {
	case LIRC_GET_FEATURES:
	case LIRC_GET_SEND_MODE:
	case LIRC_GET_REC_MODE:
	case LIRC_GET_LENGTH:
		if (!ret && put_user(val, (__u32 *)compat_ptr(arg)))
			return -EFAULT;
		break;
	}
	return ret;

	case LIRC_GET_SEND_CARRIER:
	case LIRC_GET_REC_CARRIER:
	case LIRC_GET_SEND_DUTY_CYCLE:
	case LIRC_GET_REC_DUTY_CYCLE:
	case LIRC_GET_REC_RESOLUTION:
	case LIRC_SET_SEND_CARRIER:
	case LIRC_SET_REC_CARRIER:
	case LIRC_SET_SEND_DUTY_CYCLE:
	case LIRC_SET_REC_DUTY_CYCLE:
	case LIRC_SET_TRANSMITTER_MASK:
	case LIRC_SET_REC_DUTY_CYCLE_RANGE:
	case LIRC_SET_REC_CARRIER_RANGE:
		/*
		 * These commands expect (unsigned int *)arg
		 * so no problems here. Just handle the locking.
		 */
		lock_kernel();
		cmd = cmd32;
		ret = lirc_dev_fop_ioctl(file->f_path.dentry->d_inode,
					 file, cmd, arg);
		unlock_kernel();
		return ret;
	default:
		/* unknown */
		printk(KERN_ERR "lirc_dev: %s(%s:%d): Unknown cmd %08x\n",
		       __func__, current->comm, current->pid, cmd32);
		return -ENOIOCTLCMD;
	}
}
EXPORT_SYMBOL(lirc_dev_fop_compat_ioctl);
#endif


ssize_t lirc_dev_fop_read(struct file *file,
			  char *buffer,
			  size_t length,
			  loff_t *ppos)
{
	struct irctl *ir = irctls[iminor(file->f_dentry->d_inode)];
	unsigned char buf[ir->chunk_size];
	int ret = 0, written = 0;
	DECLARE_WAITQUEUE(wait, current);

	dprintk(LOGHEAD "read called\n", ir->d.name, ir->d.minor);

	if (mutex_lock_interruptible(&ir->buffer_lock))
		return -ERESTARTSYS;
	if (!ir->attached) {
		mutex_unlock(&ir->buffer_lock);
		return -ENODEV;
	}

	if (length % ir->chunk_size) {
		dprintk(LOGHEAD "read result = -EINVAL\n",
			ir->d.name, ir->d.minor);
		mutex_unlock(&ir->buffer_lock);
		return -EINVAL;
	}

	/*
	 * we add ourselves to the task queue before buffer check
	 * to avoid losing scan code (in case when queue is awaken somewhere
	 * between while condition checking and scheduling)
	 */
	add_wait_queue(&ir->buf->wait_poll, &wait);
	set_current_state(TASK_INTERRUPTIBLE);

	/*
	 * while we didn't provide 'length' bytes, device is opened in blocking
	 * mode and 'copy_to_user' is happy, wait for data.
	 */
	while (written < length && ret == 0) {
		if (lirc_buffer_empty(ir->buf)) {
			/* According to the read(2) man page, 'written' can be
			 * returned as less than 'length', instead of blocking
			 * again, returning -EWOULDBLOCK, or returning
			 * -ERESTARTSYS */
			if (written)
				break;
			if (file->f_flags & O_NONBLOCK) {
				ret = -EWOULDBLOCK;
				break;
			}
			if (signal_pending(current)) {
				ret = -ERESTARTSYS;
				break;
			}

			mutex_unlock(&ir->buffer_lock);
			schedule();
			set_current_state(TASK_INTERRUPTIBLE);

			if (mutex_lock_interruptible(&ir->buffer_lock)) {
				ret = -ERESTARTSYS;
				break;
			}

			if (!ir->attached) {
				ret = -ENODEV;
				break;
			}
		} else {
			lirc_buffer_read(ir->buf, buf);
			ret = copy_to_user((void *)buffer+written, buf,
					   ir->buf->chunk_size);
			written += ir->buf->chunk_size;
		}
	}

	remove_wait_queue(&ir->buf->wait_poll, &wait);
	set_current_state(TASK_RUNNING);
	mutex_unlock(&ir->buffer_lock);

	dprintk(LOGHEAD "read result = %s (%d)\n",
		ir->d.name, ir->d.minor, ret ? "-EFAULT" : "OK", ret);

	return ret ? ret : written;
}
EXPORT_SYMBOL(lirc_dev_fop_read);

void *lirc_get_pdata(struct file *file)
{
	void *data = NULL;

	if (file && file->f_dentry && file->f_dentry->d_inode &&
	    file->f_dentry->d_inode->i_rdev) {
		struct irctl *ir;
		ir = irctls[iminor(file->f_dentry->d_inode)];
		data = ir->d.data;
	}

	return data;
}
EXPORT_SYMBOL(lirc_get_pdata);


ssize_t lirc_dev_fop_write(struct file *file, const char *buffer,
			   size_t length, loff_t *ppos)
{
	struct irctl *ir = irctls[iminor(file->f_dentry->d_inode)];

	dprintk(LOGHEAD "write called\n", ir->d.name, ir->d.minor);

	if (!ir->attached)
		return -ENODEV;

	return -EINVAL;
}
EXPORT_SYMBOL(lirc_dev_fop_write);


static int __init lirc_dev_init(void)
{
	int retval;

	lirc_class = class_create(THIS_MODULE, "lirc");
	if (IS_ERR(lirc_class)) {
		retval = PTR_ERR(lirc_class);
		printk(KERN_ERR "lirc_dev: class_create failed\n");
		goto error;
	}

	retval = alloc_chrdev_region(&lirc_base_dev, 0, MAX_IRCTL_DEVICES, IRCTL_DEV_NAME);
	if (retval) {
		class_destroy(lirc_class);
		printk(KERN_ERR "lirc_dev: alloc_chrdev_region failed\n");
		goto error;
	}


	printk(KERN_INFO "lirc_dev: IR Remote Control driver registered, "
	       "major %d \n", MAJOR(lirc_base_dev));

error:
	return retval;
}



static void __exit lirc_dev_exit(void)
{
	class_destroy(lirc_class);
	unregister_chrdev_region(lirc_base_dev, MAX_IRCTL_DEVICES);
	dprintk("lirc_dev: module unloaded\n");
}

module_init(lirc_dev_init);
module_exit(lirc_dev_exit);

MODULE_DESCRIPTION("LIRC base driver module");
MODULE_AUTHOR("Artur Lipowski");
MODULE_LICENSE("GPL");

module_param(debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Enable debugging messages");
