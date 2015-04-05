/**
 * History:
 *  2010-04-15 Li XianJing <xianjimli@hotmail.com> created.
 *
 */

#include <linux/kernel.h>	
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include "policy_dev.h"
#include <linux/proc_fs.h>
#include <linux/file.h>
#include "datasafe/data_safe.h"
#include "data_safe_policy.h"

#define SUCCESS 0
#define BUF_LEN 80
static int Device_Open = 0;

static int policy_dev_open(struct inode *inode, struct file *file)
{
	char digits[33] = {0};
	struct mm_struct *mm = get_task_mm(current);
	struct file* exe_file = get_mm_exe_file(mm);

	mmput(mm);
	md5sum_filp(exe_file, 0xffffffff, digits);
	fput(exe_file);

	printk(KERN_INFO"%s: %s\n", __func__, digits);

	/* 
	 * We don't want to talk to two processes at the same time 
	 */
	if (Device_Open)
		return -EBUSY;

	Device_Open++;
	try_module_get(THIS_MODULE);

	return SUCCESS;
}

static int policy_dev_release(struct inode *inode, struct file *file)
{
	Device_Open--;
	module_put(THIS_MODULE);

	return SUCCESS;
}

static ssize_t policy_dev_read(struct file *file,	/* see include/linux/fs.h   */
			   char __user * buffer,	/* buffer to be
							 * filled with data */
			   size_t length,	/* length of the buffer     */
			   loff_t * offset)
{
	return 0;
}

static ssize_t
policy_dev_write(struct file *file,
	     const char __user * buffer, size_t length, loff_t * offset)
{
	return 0;
}

int policy_dev_ioctl(struct inode *inode,	/* see include/linux/fs.h */
		 struct file *file,	/* ditto */
		 unsigned int ioctl_num,	/* number and param for ioctl */
		 unsigned long ioctl_param)
{
	char* src = (char *)ioctl_param;
	
	printk(KERN_INFO"ioctl_num=%x ioctl_param=%p\n", ioctl_num, (void*)ioctl_param);
	/* 
	 * Switch according to the ioctl called 
	 */
	switch (ioctl_num) 
	{
		case IOCTL_RESET:
		{
			int len = 0;
			int size = sizeof(DataSafePolicyInfo);
			DataSafePolicyInfo* info = kmalloc(size, GFP_KERNEL);
			if(info != NULL)
			{
				char passwd[DATA_SAFE_PASSWD_LENGTH+1] = {0};
				len = copy_from_user(info, src, size);
				data_safe_decrypt((u8*)info, (u8*)info, 
					8, size>>3, data_safe_get_trans_passwd(passwd)); 
				data_safe_policy_reset();
				data_safe_policy_set_passwd(info->passwd);
				data_safe_policy_parse(info->policy);
				kfree(info);
			}

			break;
		}
		default:break;
	}

	return SUCCESS;
}

/* Module Declarations */

struct file_operations Fops = {
	.read = policy_dev_read,
	.write = policy_dev_write,
	.ioctl = policy_dev_ioctl,
	.open = policy_dev_open,
	.release = policy_dev_release,	/* a.k.a. close */
};

/* 
 * Initialize the module - Register the character device 
 */

static int __init policy_dev_init(void)
{
	int ret_val = 0;
	ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &Fops);

	if (ret_val < 0) 
	{
		printk(KERN_ALERT "%s failed with %d\n",
		       "Sorry, registering the character device ", ret_val);
		return ret_val;
	}

	return 0;
}

static void __exit policy_dev_exit(void)
{
	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
	printk(KERN_INFO "cleanup_module.\n");

	return;
}

module_init(policy_dev_init);
module_exit(policy_dev_exit);

MODULE_LICENSE("GPL");
