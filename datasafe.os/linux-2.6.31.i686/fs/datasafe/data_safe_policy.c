/**
 * History:
 *  2010-04-15 Li XianJing <xianjimli@hotmail.com> created.
 *
 */

#ifdef TEST
#include <string.h>
#include <stdio.h>
#else
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
#include <linux/scatterlist.h>
#endif

#include "policy_dev.h"
#include <datasafe/data_safe.h>
#include "data_safe_policy.h"

#define MAX_APPS 256
#define HEADER_SIZE (PAGE_SIZE << 2)

static int data_safe_nr;
static AppPolicy data_safe_policy[MAX_APPS + 1];
static char data_safe_passwd[DATA_SAFE_PASSWD_LENGTH + 1];

int         data_safe_policy_set_passwd(const char* passwd)
{
	if(passwd == NULL) return -1;

	strncpy(data_safe_passwd, passwd, sizeof(data_safe_passwd));

	return 0;
}

const char* data_safe_policy_get_passwd(void)
{
	return data_safe_passwd;
}

int         data_safe_policy_reset(void)
{
	data_safe_nr = 0;

	return 0;
}

int         data_safe_policy_total(void)
{
	return data_safe_nr;
}

typedef enum _PolicyState
{
	STAT_IN_NAME     = 0,
	STAT_IN_MD5SUM   = 1,
	STAT_IN_READ_DE  = 2 ,
	STAT_IN_WRITE_EN = 3
}PolicyState;

int         data_safe_policy_parse(const char* data)
{
	int i = 0;
	AppPolicy policy;
	const char* p = data;
	PolicyState state = STAT_IN_NAME;
	if(p == NULL || *p == '\0') return -1;

	memset(&policy, 0x00, sizeof(policy));
	for(; *p; p++)
	{
		if(*p == '\n')
		{
			i = 0;
			if(policy.name[0] && policy.md5sum[0])
			{
				data_safe_policy_add(&policy);
			}
			memset(&policy, 0x00, sizeof(policy));
			state = STAT_IN_NAME;

			continue;
		}

		if(*p == ';')
		{
			i = 0;
			state++;
			continue;
		}

		switch(state)
		{
			case STAT_IN_NAME:
			{
				if(i < sizeof(policy.name))
				{
					policy.name[i] = *p;
				}
				break;
			}
			case STAT_IN_MD5SUM:
			{
				if(i < sizeof(policy.md5sum))
				{
					policy.md5sum[i] = *p;
				}
				break;
			}
			case STAT_IN_READ_DE:
			{
				if(*p != '0')
				{
					policy.policy |= DATA_SAFE_READ_DE;
				}
				break;
			}
			case STAT_IN_WRITE_EN:
			{
				if(*p != '0')
				{
					policy.policy |= DATA_SAFE_WRITE_EN;
				}
				break;
			}
			default:break;
		}
		i++;
	}

	return 0;
}

int kernel_fstat(const char* filename, struct kstat* st)
{
	int ret = 0;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_stat((char __user *)filename, st);	
	set_fs(old_fs);

	return ret;
}

int data_safe_policy_is_file_changed(AppPolicy* policy)
{
	int ret = 0;
	char md5sum[33] = {0};

	md5sum_file_len(policy->name, HEADER_SIZE, md5sum);
	if(strcmp(md5sum, policy->header_md5sum) != 0)
	{
		ret = 1;
	}

	return ret;
}

int data_safe_policy_init_file_info(AppPolicy* policy, const char* filename)
{
	int ret = 0;
	struct kstat st = {0};

	ret = kernel_fstat(filename, &st);
	if(ret == 0)
	{
		policy->size  = st.size;
		policy->mtime = st.mtime.tv_sec;
	}

	return ret;
}

int         data_safe_policy_add(AppPolicy* policy)
{
	char digits[33] = {0};
	
	if(data_safe_nr >= MAX_APPS || policy == NULL) return -1;

	md5sum_file(policy->name, digits);

	if(strcmp(digits, policy->md5sum) == 0)
	{
		md5sum_file_len(policy->name, HEADER_SIZE, policy->header_md5sum);
		data_safe_policy_init_file_info(policy, policy->name);
		memcpy(data_safe_policy+data_safe_nr, policy, sizeof(AppPolicy));
		data_safe_nr++;
		printk(KERN_INFO"%s: add %s  %s %s\n", __func__, policy->md5sum, policy->name, policy->header_md5sum);
	}
	else
	{
		printk(KERN_INFO"%s: %s != %s for %s\n", __func__, digits, policy->md5sum, policy->name);
	}

	return 0;
}

AppPolicy*  data_safe_policy_get(int index)
{
	if(index >= data_safe_nr) return NULL;

	return data_safe_policy+index;
}

AppPolicy*  data_safe_policy_find_by_md5(const char* md5sum)
{
	int i = 0;
	if(md5sum == NULL || data_safe_nr == 0) return NULL;

	for(i = 0; i < data_safe_nr; i++)
	{
		if(strcmp(md5sum, data_safe_policy[i].md5sum) == 0)
		{
			return data_safe_policy+i;
		}
	}

	return NULL;
}

AppPolicy*  data_safe_policy_find_by_name(const char* name)
{
	int i = 0;
	if(name == NULL || data_safe_nr == 0) return NULL;

	for(i = 0; i < data_safe_nr; i++)
	{
		if(strcmp(name, data_safe_policy[i].name) == 0)
		{
			return data_safe_policy+i;
		}
	}
	
	return NULL;
}

#ifdef TEST
#include <assert.h>
#define STR_POLICY "vim;e446aae508408d1dfea7264fd26292ef;1;1\ngcc;974ef917db876089a940127eabd17d0d;1;0\n"

void data_safe_policy_dump()
{
	int i = 0;
	AppPolicy* policy = NULL;

	for(i = 0; i < data_safe_policy_total(); i++)
	{
		policy = data_safe_policy_get(i);
		printf("%s;%s;%d\n", policy->name, policy->md5sum, policy->policy);
	}

	return;
}

int main(int argc, char* argv[])
{
	int i = 0;
	AppPolicy policy;

	assert(data_safe_policy_reset() == 0);
	assert(data_safe_policy_total() == 0);

	for(i = 0; i <  MAX_APPS; i++)
	{
		snprintf(policy.name, sizeof(policy.name), "name%d", i);
		snprintf(policy.md5sum, sizeof(policy.md5sum), "md5sum%d", i);
		policy.policy = i;
		assert(data_safe_policy_add(&policy) == 0);
	}
	
	for(i = 0; i <  MAX_APPS; i++)
	{
		snprintf(policy.name, sizeof(policy.name), "name%d", i);
		snprintf(policy.md5sum, sizeof(policy.md5sum), "md5sum%d", i);
		assert(data_safe_policy_find_by_md5(policy.md5sum) == data_safe_policy_get(i));
		assert(data_safe_policy_find_by_name(policy.name) == data_safe_policy_get(i));
	}
	assert(data_safe_policy_reset() == 0);
	assert(data_safe_policy_total() == 0);

	assert(data_safe_policy_parse(STR_POLICY) == 0);
	assert(data_safe_policy_total() == 2);
	data_safe_policy_dump();

	assert(data_safe_policy_set_passwd("12345678") == 0);
	assert(strcmp(data_safe_policy_get_passwd(), "12345678") == 0);

	printf("test pass.\n");

	return 0;
}
#endif/*TEST*/

