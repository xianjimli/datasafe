/**
 * History:
 *  2010-04-15 Li XianJing <xianjimli@hotmail.com> created.
 *
 */

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/smp_lock.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/audit.h>
#include <linux/tracehook.h>
#include <linux/crypto.h>
#include "linux/mount.h"
#include <linux/scatterlist.h>
#include "data_safe_policy.h"
#include <datasafe/data_safe.h>

#define go_to_if_fail(p, label) if(!(p)) {printk(KERN_INFO"%s:%d\n", __func__, __LINE__); goto label;}

static const char* md5sum_str(const char* str, char digits[33]);

static int digit_to_hex(const char* in, char* out)
{
	int i = 0;
	char str[3] = {0};

	for (i = 0; i < 16; i++)
	{
		unsigned int v = (in[i] >> 4) & 0x0F;
		str[0] = (v >= 0 && v <= 9) ? v + '0' : (v - 10 + 'a');

		v = in[i] & 0x0F;
		str[1] = (v >= 0 && v <= 9) ? v + '0' : (v - 10 + 'a');

		out[i << 1] = str[0];
		out[(i << 1) + 1] = str[1];
	}

	return 0;
}

void hash_test(const char* buf, size_t len)
{
	char digits_bin[32] = {0};
	char digits_hex[33] = {0};
	struct scatterlist sg;
	struct hash_desc ahash_desc = {0};
	ahash_desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

	sg_init_one(&sg, buf, len);
	crypto_hash_init(&ahash_desc);	
	crypto_hash_update(&ahash_desc, &sg, len);
	crypto_hash_update(&ahash_desc, &sg, len);

	crypto_hash_final(&ahash_desc, digits_bin);
	crypto_free_hash(ahash_desc.tfm);
	digit_to_hex(digits_bin, digits_hex);

	return;
}

static const char* md5sum_str(const char* str, char digits[33])
{
	int len = 0;
	struct scatterlist sg;
	char digits_bin[32] = {0};
	struct hash_desc ahash_desc = {0};
	
	if(str == NULL || digits == NULL) return NULL;

	len = strlen(str);
	ahash_desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	crypto_hash_init(&ahash_desc);	

	sg_init_one(&sg, str, len);
	crypto_hash_update(&ahash_desc, &sg, len);
	
	crypto_hash_final(&ahash_desc, digits_bin);
	crypto_free_hash(ahash_desc.tfm);
	digit_to_hex(digits_bin, digits);

	return digits;
}


int md5sum_filp(struct file* filp, size_t max_len, char digits[33])
{
	int  len = 0;
	int  ret = -1;
	char* buf = NULL;
	size_t total = 0;	
	struct scatterlist sg;
	char digits_bin[32] = {0};
	struct hash_desc ahash_desc = {0};

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

	if (filp != NULL) 
	{
		loff_t pos = 0;
		buf = (char*)get_zeroed_page(GFP_KERNEL);
		ahash_desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
		crypto_hash_init(&ahash_desc);	

		do
	  	{
			len = vfs_read(filp, (char __user*)buf, PAGE_SIZE, &pos);
			if(len > 0)
			{
				total += len;
				sg_init_one(&sg, buf, len);
				crypto_hash_update(&ahash_desc, &sg, len);
			}

			if(total >= max_len)
			{
				break;
			}
		}while(len > 0);

		crypto_hash_final(&ahash_desc, digits_bin);
		crypto_free_hash(ahash_desc.tfm);
		digit_to_hex(digits_bin, digits);
    	ret = 0;
    	free_page((unsigned long)buf);
	}
	set_fs(old_fs);

	return ret;
}
EXPORT_SYMBOL(md5sum_filp);

int md5sum_file(const char *filename, char digits[33])
{
	struct file* filp = NULL;

	filp = do_filp_open(AT_FDCWD, filename, O_RDONLY, 0, 0);
	if(!IS_ERR(filp))
	{
		md5sum_filp(filp, 0xffffffff, digits);
		fput(filp);
	}
	else
	{
		printk(KERN_INFO"%s: open %s failed.\n", __func__, filename);
	}

	return 0;
}
EXPORT_SYMBOL(md5sum_file);

int md5sum_file_len(const char *filename, size_t max_len, char digits[33])
{
	struct file* filp = NULL;

	filp = do_filp_open(AT_FDCWD, filename, O_RDONLY, 0, 0);
	if(!IS_ERR(filp))
	{
		md5sum_filp(filp, max_len, digits);
		fput(filp);
	}
	else
	{
		printk(KERN_INFO"%s: open %s failed.\n", __func__, filename);
	}

	return 0;
}
EXPORT_SYMBOL(md5sum_file_len);

#define DATA_SAFE_ALGO "ecb(blowfish)"

static int encrypt_scatterlist(struct crypto_blkcipher *tfm,
			       struct scatterlist *dest_sg,
			       struct scatterlist *src_sg, int size, const char* key)
{
	int rc = -1;
	char key_md5[33] = {0};
	struct blkcipher_desc desc = {
		.tfm   = tfm,
	};

	md5sum_str(key, key_md5);
	rc = crypto_blkcipher_setkey(tfm, key_md5, strlen(key_md5));
	if (rc) 
	{
		printk(KERN_ALERT"%s: crypto_blkcipher_setkey fail\n", __func__);
		rc = -EINVAL;
		goto out;
	}
	rc = crypto_blkcipher_encrypt(&desc, dest_sg, src_sg, size);
	if (rc) 
	{
		printk(KERN_ALERT"%s: crypto_blkcipher_encrypt fail\n", __func__);
		goto out;
	}
	rc = 0;
out:

	return rc;
}

static int decrypt_scatterlist(struct crypto_blkcipher *tfm,
			       struct scatterlist *dest_sg,
			       struct scatterlist *src_sg, int size, const char* key)
{
	int rc = -1;
	char key_md5[33] = {0};
	struct blkcipher_desc desc = 
	{
		.tfm   = tfm,
	};

	md5sum_str(key, key_md5);
	rc = crypto_blkcipher_setkey(tfm, key_md5, strlen(key_md5));
	if (rc) 
	{
		printk(KERN_ALERT"%s: crypto_blkcipher_setkey fail\n", __func__);
		rc = -EINVAL;
		goto out;
	}
	
	rc = crypto_blkcipher_decrypt(&desc, dest_sg, src_sg, size);
	if (rc) 
	{
		printk(KERN_ALERT"%s: crypto_blkcipher_decrypt fail\n", __func__);
		goto out;
	}
	rc = 0;
out:

	return rc;
}

int data_safe_encrypt(u8 *out, const u8 *in, size_t blk_size, size_t blk_nr, const char* key)
{
	int ret = 0;
	struct scatterlist in_sg[1];
	struct scatterlist out_sg[1];
	size_t total = blk_size * blk_nr;
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(DATA_SAFE_ALGO, 0, 0);

	if(IS_ERR(tfm))
	{
		printk(KERN_INFO"no %s found\n", DATA_SAFE_ALGO);

		return -1;
	}
	sg_init_one(in_sg, in, total);
	sg_init_one(out_sg, out, total);
	
	ret = encrypt_scatterlist(tfm, in_sg, out_sg, total, key); 

	crypto_free_blkcipher(tfm);

	return ret;
}

int data_safe_decrypt(u8 *out, const u8 *in, size_t blk_size, size_t blk_nr, const char* key)
{
	int ret = 0;
	struct scatterlist in_sg[1];
	struct scatterlist out_sg[1];
	size_t total = blk_size * blk_nr;
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(DATA_SAFE_ALGO, 0, 0);

	if(IS_ERR(tfm))
	{
		printk(KERN_INFO"no %s found\n", DATA_SAFE_ALGO);

		return -1;
	}

	sg_init_one(in_sg, in, total);
	sg_init_one(out_sg, out, total);
	
	ret = decrypt_scatterlist(tfm, in_sg, out_sg, total, key); 

	crypto_free_blkcipher(tfm);

	return ret;
}

int data_safe_on_exec(const char* filename)
{
	char* basename = NULL;
	AppPolicy* policy = NULL;

	task_set_debugable(current, 1);
	policy = data_safe_policy_find_by_name(filename);
	if(policy == NULL)
	{
		//printk(KERN_INFO"not find policy for %s\n", filename);

		return 0;
	}

	task_set_debugable(current, 0);
	if(data_safe_policy_is_file_changed(policy))
	{
		printk(KERN_INFO"%s is changed for some reasons.\n", filename);

		return 0;
	}

	current->encrypt_flags = 0;
	if(policy->policy & DATA_SAFE_READ_DE)
	{
		current->encrypt_flags |= TASK_R_DECRYPT;
	}

	if(policy->policy & TASK_W_ENCRYPT)
	{
		current->encrypt_flags |= TASK_W_ENCRYPT;
	}

	basename = strrchr(filename, '/');
	if(basename != NULL && strstr(basename, "brn-") != NULL)
	{
		TASK_SET_ENABLE_NETWORK(current);
	}

	printk(KERN_INFO"find policy for %s %s %d %02x.\n", 
		policy->name, policy->md5sum, policy->policy, current->encrypt_flags);

	return 0;
}
EXPORT_SYMBOL(data_safe_on_exec);

int data_safe_is_normal_file(struct file* file)
{
	struct inode* inode = NULL;

	if(file == NULL)
	{
		return 0;
	}

	if(file->f_path.dentry == NULL 	|| file->f_path.dentry->d_inode == NULL)
	{
		return 0;
	}
	
	if(file->f_path.dentry == NULL || file->f_path.mnt->mnt_sb == NULL)
	{
		return 0;
	}

	if(file->f_path.mnt->mnt_sb->s_type == NULL)
	{
		return 0;
	}

	if((inode = file->f_path.dentry->d_inode) == NULL)
	{
		return 0;
	}

	if((inode->i_mode & S_IFMT) != S_IFREG)
	{
		return 0;
	}

	return file->f_path.mnt->mnt_sb->s_type->fs_flags & FS_REQUIRES_DEV;
}
EXPORT_SYMBOL(data_safe_is_normal_file);

void data_safe_save_encrypt_flags(struct file* file)
{
	struct inode* inode = NULL;

	if(!data_safe_is_normal_file(file))
	{
		return;
	}
	
	if(!(current->encrypt_flags & TASK_W_ENCRYPT))
	{
		return;
	}

	inode = file->f_path.dentry->d_inode;
	if(!inode->i_encrypt_flags)
	{
		return;
	}
	
	if(inode->i_op != NULL && inode->i_op->setxattr != NULL)
	{
		int error = 0;
		int flags = inode->i_encrypt_flags;
		error = inode->i_op->setxattr(file->f_path.dentry, "user.encrypted", &flags, sizeof(flags), 0);
		if(error > 0)
		{
			printk(KERN_INFO"%s: setxattr return %d\n", __func__, error);
		}	
	}

	return;
}
EXPORT_SYMBOL(data_safe_save_encrypt_flags);

void data_safe_load_encrypt_flags(struct file* file)
{
	struct inode* inode = NULL;

	if(!data_safe_is_normal_file(file))
	{
		return;
	}
	
	if(!(current->encrypt_flags & TASK_R_DECRYPT))
	{
		return;
	}

	inode = file->f_path.dentry->d_inode;
	if(inode->i_op != NULL && inode->i_op->getxattr != NULL)
	{
		int flags = 0;
		int error = 0;
		mutex_lock(&inode->i_mutex);
		error = inode->i_op->getxattr(file->f_path.dentry, "user.encrypted", &flags, sizeof(flags));
		if(error > 0)
		{
			inode->i_encrypt_flags = flags;
		}
		mutex_unlock(&inode->i_mutex);
//		printk(KERN_INFO"%s: pid=%d i_mode=%o i_encrypt_flags=%d.\n", 
//			file->f_path.dentry->d_name.name, current->pid, inode->i_mode, inode->i_encrypt_flags);
	}

	return;
}
EXPORT_SYMBOL(data_safe_load_encrypt_flags);

int file_need_decrypt(struct file* file)
{
	struct inode* inode = NULL;
	if(!data_safe_is_normal_file(file))
	{
		return 0;
	}

	inode = file->f_path.dentry->d_inode;
	if(inode->i_encrypt_flags)
	{
		return current->encrypt_flags & TASK_R_DECRYPT;
	}
	
	return 0;
}
EXPORT_SYMBOL(file_need_decrypt);

int file_need_encrypt(struct file* file)
{
	struct inode* inode = NULL;

	if(!data_safe_is_normal_file(file))
	{
		return 0;
	}

	inode = file->f_path.dentry->d_inode;
	if(inode->i_encrypt_flags)
	{
		return 1;
	}

	if(current->encrypt_flags & TASK_W_ENCRYPT)
	{
		inode->i_encrypt_flags = 1;

//		printk(KERN_INFO"%s: pid=%d i_mode=%o i_encrypt_flags=%d.\n", 
//			file->f_path.dentry->d_name.name, current->pid, inode->i_mode, inode->i_encrypt_flags);
		return inode->i_encrypt_flags;
	}

	return 0;
}
EXPORT_SYMBOL(file_need_encrypt);

static inline loff_t file_pos_read(struct file *file)
{
	return file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos)
{
	file->f_pos = pos;
}

int sys_read_normal(struct file *file, char __user * buf, size_t count)
{
	ssize_t ret = -EBADF;
	loff_t pos = file_pos_read(file);
	ret = vfs_read(file, buf, count, &pos);
	file_pos_write(file, pos);

	return ret;
}
EXPORT_SYMBOL(sys_read_normal);

static int kernel_fread(struct file *file, char* buf, size_t count, loff_t* pos)
{
	int result;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	result = vfs_read(file, (void __user *)buf, count, pos);
	set_fs(old_fs);

	return result;
}

static int kernel_fread_page(struct file *file, char* buf, loff_t* pos)
{
	int ret = 0;
	ret = kernel_fread(file, buf, PAGE_SIZE, pos);

	if(ret > 0)
	{
		int len = ret;
		data_safe_decrypt(buf, buf, 8, len>>3, data_safe_policy_get_passwd());
	}

	return ret;
}

int sys_read_decrypt(struct file *file, char __user * buf, size_t count)
{
	size_t len  = 0;
	ssize_t ret = -EBADF;
	ssize_t ret_total = 0;
	long leave  = count;
	loff_t pos  = file_pos_read(file);
	loff_t new_pos = pos;
	loff_t i_offset = 0;
	loff_t o_offset = 0;

	char* kbuf = (char*)get_zeroed_page(GFP_KERNEL);

	if(kbuf != NULL)
	{
		while(leave > 0)
		{
			i_offset = pos & (~PAGE_CACHE_MASK);
			pos = pos & PAGE_CACHE_MASK;

			ret = kernel_fread_page(file, kbuf, &pos);
			if(ret <= i_offset)
			{
				ret = 0;
				break;
			}

			len = ret - i_offset;
			len = len < leave ? len : leave;
			copy_to_user(buf + o_offset, kbuf + i_offset, len);
			leave    -= len;
			new_pos  += len;
			o_offset += len;
			ret_total = (ret_total < 0) ? ret : (ret_total + ret);
			if(ret < PAGE_SIZE) break;
		}
		free_page((unsigned long)kbuf);
	}

	file_pos_write(file, new_pos);

	return ret_total;
}
EXPORT_SYMBOL(sys_read_decrypt);

int sys_write_normal(struct file *file, const char __user * buf, size_t count)
{
	ssize_t ret = -EBADF;
	loff_t pos = file_pos_read(file);
	ret = vfs_write(file, buf, count, &pos);
	file_pos_write(file, pos);

	return ret;
}
EXPORT_SYMBOL(sys_write_normal);

static int kernel_fwrite(struct file *file, char* buf, size_t count, loff_t* pos)
{
	int result;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(get_ds());
	result = vfs_write(file, (void __user *)buf, count, pos);
	set_fs(old_fs);

	return result;
}

static int kernel_write_page(struct file *file, char* buf, size_t count, loff_t* pos)
{
	int ret = 0;
	int len = count; 

	data_safe_encrypt(buf, buf, 8, len>>3, data_safe_policy_get_passwd());
	ret = kernel_fwrite(file, buf, len, pos);

	return ret;
}

int sys_write_encrypt(struct file *file, const char __user * buf, size_t count)
{
	size_t  len  = 0;
	long leave  = count;
	ssize_t ret = -EBADF;
	ssize_t ret_total = 0;
	loff_t pos  = file_pos_read(file);
	loff_t new_pos  = pos;
	loff_t save_pos = pos;
	loff_t i_offset = 0;
	loff_t o_offset = 0;

	char* kbuf = (char*)get_zeroed_page(GFP_KERNEL);
	if(kbuf != NULL)
	{
		file->f_mode |= FMODE_READ;
		while(leave > 0)
		{
			o_offset = pos & (~PAGE_CACHE_MASK);
			pos = pos & PAGE_CACHE_MASK;
			save_pos = pos;
			ret = kernel_fread_page(file, kbuf, &pos);
			if(ret < o_offset)
			{
				break;
			}

			len = PAGE_SIZE - o_offset;
			len = len < leave ? len : leave;
			copy_from_user(kbuf + o_offset, buf + i_offset, len);
			leave    -= len;
			new_pos  += len;
			i_offset += len;
			pos = save_pos;
			len = o_offset + len;
			ret = kernel_write_page(file, kbuf, len, &pos);
			if(ret < len)
			{
				break;
			}
			ret_total = (ret_total < 0) ? ret : (ret_total + ret);
		}
		free_page((unsigned long)kbuf);
	}

	file_pos_write(file, new_pos);

	return ret_total;
}
EXPORT_SYMBOL(sys_write_encrypt);

