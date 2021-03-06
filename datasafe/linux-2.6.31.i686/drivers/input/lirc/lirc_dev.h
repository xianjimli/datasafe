/*
 * LIRC base driver
 *
 * by Artur Lipowski <alipowski@interia.pl>
 *        This code is licensed under GNU GPL
 *
 */

#ifndef _LINUX_LIRC_DEV_H
#define _LINUX_LIRC_DEV_H

#define MAX_IRCTL_DEVICES 4
#define BUFLEN            16

#define mod(n, div) ((n) % (div))

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/poll.h>
#include <linux/kfifo.h>

struct lirc_buffer {
	wait_queue_head_t wait_poll;
	spinlock_t lock;
	unsigned int chunk_size;
	unsigned int size; /* in chunks */
	/* Using chunks instead of bytes pretends to simplify boundary checking
	 * And should allow for some performance fine tunning later */
	struct kfifo *fifo;
};
static inline void lirc_buffer_clear(struct lirc_buffer *buf)
{
	if (buf->fifo)
		kfifo_reset(buf->fifo);
	else
		WARN(1, "calling lirc_buffer_clear on an uninitialized lirc_buffer\n");
}
static inline int lirc_buffer_init(struct lirc_buffer *buf,
				    unsigned int chunk_size,
				    unsigned int size)
{
	init_waitqueue_head(&buf->wait_poll);
	spin_lock_init(&buf->lock);
	buf->chunk_size = chunk_size;
	buf->size = size;
	buf->fifo = kfifo_alloc(size*chunk_size, GFP_KERNEL, &buf->lock);
	if (!buf->fifo)
		return -ENOMEM;
	return 0;
}
static inline void lirc_buffer_free(struct lirc_buffer *buf)
{
	if (buf->fifo)
		kfifo_free(buf->fifo);
	else
		WARN(1, "calling lirc_buffer_free on an uninitialized lirc_buffer\n");
}
static inline int lirc_buffer_full(struct lirc_buffer *buf)
{
	return kfifo_len(buf->fifo) == buf->size * buf->chunk_size;
}
static inline int lirc_buffer_empty(struct lirc_buffer *buf)
{
	return !kfifo_len(buf->fifo);
}
static inline int lirc_buffer_available(struct lirc_buffer *buf)
{
	return buf->size - (kfifo_len(buf->fifo) / buf->chunk_size);
}

static inline void lirc_buffer_read(struct lirc_buffer *buf,
			       unsigned char *dest)
{
	if (kfifo_len(buf->fifo) >= buf->chunk_size)
		kfifo_get(buf->fifo, dest, buf->chunk_size);
}
static inline void lirc_buffer_write(struct lirc_buffer *buf,
				unsigned char *orig)
{
	kfifo_put(buf->fifo, orig, buf->chunk_size);
}

struct lirc_driver {
	char name[40];
	int minor;
	unsigned long code_length;
	unsigned int buffer_size; /* in chunks holding one code each */
	int sample_rate;
	unsigned long features;

	unsigned int chunk_size;

	void *data;
	int (*add_to_buf) (void *data, struct lirc_buffer *buf);
	struct lirc_buffer *rbuf;
	int (*set_use_inc) (void *data);
	void (*set_use_dec) (void *data);
	struct file_operations *fops;
	struct device *dev;
	struct module *owner;
};
/* name:
 * this string will be used for logs
 *
 * minor:
 * indicates minor device (/dev/lirc) number for registered driver
 * if caller fills it with negative value, then the first free minor
 * number will be used (if available)
 *
 * code_length:
 * length of the remote control key code expressed in bits
 *
 * sample_rate:
 *
 * data:
 * it may point to any driver data and this pointer will be passed to
 * all callback functions
 *
 * add_to_buf:
 * add_to_buf will be called after specified period of the time or
 * triggered by the external event, this behavior depends on value of
 * the sample_rate this function will be called in user context. This
 * routine should return 0 if data was added to the buffer and
 * -ENODATA if none was available. This should add some number of bits
 * evenly divisible by code_length to the buffer
 *
 * rbuf:
 * if not NULL, it will be used as a read buffer, you will have to
 * write to the buffer by other means, like irq's (see also
 * lirc_serial.c).
 *
 * set_use_inc:
 * set_use_inc will be called after device is opened
 *
 * set_use_dec:
 * set_use_dec will be called after device is closed
 *
 * fops:
 * file_operations for drivers which don't fit the current driver model.
 *
 * Some ioctl's can be directly handled by lirc_dev if the driver's
 * ioctl function is NULL or if it returns -ENOIOCTLCMD (see also
 * lirc_serial.c).
 *
 * owner:
 * the module owning this struct
 *
 */


/* following functions can be called ONLY from user context
 *
 * returns negative value on error or minor number
 * of the registered device if success
 * contents of the structure pointed by p is copied
 */
extern int lirc_register_driver(struct lirc_driver *d);

/* returns negative value on error or 0 if success
*/
extern int lirc_unregister_driver(int minor);

/* Returns the private data stored in the lirc_driver
 * associated with the given device file pointer.
 */
void *lirc_get_pdata(struct file *file);

/* default file operations
 * used by drivers if they override only some operations
 */
int lirc_dev_fop_open(struct inode *inode, struct file *file);
int lirc_dev_fop_close(struct inode *inode, struct file *file);
unsigned int lirc_dev_fop_poll(struct file *file, poll_table *wait);
int lirc_dev_fop_ioctl(struct inode *inode, struct file *file,
		       unsigned int cmd, unsigned long arg);
ssize_t lirc_dev_fop_read(struct file *file, char *buffer, size_t length,
			  loff_t *ppos);
ssize_t lirc_dev_fop_write(struct file *file, const char *buffer, size_t length,
			   loff_t *ppos);
long lirc_dev_fop_compat_ioctl(struct file *file, unsigned int cmd32,
			       unsigned long arg);

#endif
