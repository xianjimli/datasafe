/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "policy_dev.h"
#include "data_safe_policy_lib.h"

static int    policy_fd;
static int    policy_buffer_len = 0;
static char   policy_passwd[DATA_SAFE_PASSWD_LENGTH+1];
static char   policy_buffer[POLICY_BUFFER_LEN+1];

static char* simple_encode_buffer(char* buffer)
{
	int i = 0;
	for(; buffer[i]; i++)
	{
		buffer[i] += 0x10;
	}

	return;
}

Ret  data_safe_policy_open(void)
{
	char filename[260] = {0};

	if(policy_fd > 0)
	{
		return RET_OK;
	}

	snprintf(filename, sizeof(filename), "/dev/%s", DEVICE_NAME);
	policy_fd = open(filename, O_WRONLY, 0700);

	if(policy_fd < 0)
	{
		perror("open");
	}

	return policy_fd > 0 ? RET_OK : RET_IO_ERR;
}

Ret  data_safe_policy_set_passwd(const char* passwd)
{
	if(policy_fd <= 0 || passwd == NULL)
	{
		return RET_FAIL;
	}

	strncpy(policy_passwd, passwd, DATA_SAFE_PASSWD_LENGTH);

	return RET_OK;
}

Ret  data_safe_policy_add(const char* name, const char* md5sum, int r_de, int w_en)
{
	int len = 0;

	if(policy_fd <= 0 || name == NULL || md5sum == NULL)
	{
		return RET_FAIL;
	}

	len = snprintf(policy_buffer + policy_buffer_len, 
			POLICY_BUFFER_LEN - policy_buffer_len,
			"%s;%s;%d;%d\n", name, md5sum, r_de, w_en);
			
	if(len > 0)
	{
		policy_buffer_len += len;
	}

	return len > 0 ? RET_OK : RET_FAIL;
}

Ret  data_safe_policy_set_policy(const char* policy)
{
	if(policy != NULL)
	{
		strncpy(policy_buffer, policy, sizeof(policy_buffer));
		policy_buffer_len = strlen(policy_buffer);
	}

	return RET_OK;
}

Ret  data_safe_policy_flush(void)
{
	int ret = 0;
	int len = 0;
	DataSafePolicyInfo info = {0};
	char passwd[DATA_SAFE_PASSWD_LENGTH+1] = {0};

	if(policy_fd <= 0)
	{
		return RET_FAIL;
	}

	memset(&info, 0x00, sizeof(info));
	memset(info.magic, '0', sizeof(info.magic));
	strcpy(info.passwd, policy_passwd);
	strcpy(info.policy, policy_buffer);

//#ifdef TEST
	printf("=============================\n");
	printf("%s", policy_buffer);
//#endif

	len = (sizeof(info) >> 3) << 3;
	data_safe_encrypt_buff((char*)&info, len, data_safe_get_trans_passwd(passwd));

	if((ret = ioctl(policy_fd, IOCTL_RESET, &info, sizeof(info))) != 0)
	{
		perror("IOCTL_RESET: ");
		return RET_FAIL;
	}
	data_safe_decrypt_buff((char*)&info, len, data_safe_get_trans_passwd(passwd));
	
	return RET_OK;
}

void data_safe_policy_close(void)
{
	if(policy_fd <= 0)
	{
		return;
	}

	close(policy_fd);

	policy_fd = 0;
	policy_buffer_len = 0;
	memset(policy_passwd, 0x00, sizeof(policy_passwd));
	memset(policy_buffer, 0x00, sizeof(policy_buffer));

	return;
}

#ifdef TEST
#include <assert.h>

#define MY_ASSERT(p) p
int main(int argc, char* argv[])
{
	MY_ASSERT(data_safe_policy_open() == RET_OK);
	MY_ASSERT(data_safe_policy_set_passwd("1234abcd") == RET_OK);
	#include "policy.c"
	MY_ASSERT(data_safe_policy_flush() == RET_OK);
	data_safe_policy_close();

	return 0;
}

#endif


