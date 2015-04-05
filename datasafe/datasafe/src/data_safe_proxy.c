/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include "data_safe_proxy.h"
#include "data_safe_policy_lib.h"

int data_safe_proxy(DataSafeCmd* proxy, int sock, int argc, char* argv[])
{
	Ret ret = RET_FAIL;
	char cmd[260] = {0};
	struct stat st = {0};
	char* policy = NULL;
	char* passwd = NULL;
	char magic[DATA_SAFE_MAGIC_LENGTH + 1] = {0};
	DataSafeClientInfo info = {0};
	data_safe_get_proxy_magic(magic);
	data_safe_client_info_init(&info, sock, "broncho", magic);

	if(geteuid() != 0)
	{
		printf("Only root can run this programs.\n");

		return 0;
	}

	if(stat("/dev/policy", &st) != 0)
	{
		mknod("/dev/policy", 0700|S_IFCHR, makedev(200, 0));
		sleep(1);
	}
	
	if(stat("/dev/policy", &st) != 0)
	{
		assert(!"data_safe_proxy");
		return 0;
	}

   	if(argc < 2)
   	{
   		printf("Run as a deamon.\n");
   		if(fork() != 0)
   		{
   			exit(0);
   		}
   	}

	strcpy(info.magic, magic);
	ret = data_safe_cmd_check(proxy, &info);

	if(CHECK_IS_OK(ret))
	{
		char* filename = NULL;
		ret = data_safe_cmd_get_passwd(proxy, &passwd);
		ret = data_safe_cmd_get_policy(proxy, &policy);
		ret = data_safe_cmd_get_app_pkg(proxy, &filename);

		snprintf(cmd, sizeof(cmd), "tar xvf %s -C /", filename);
		system(cmd);

		if(data_safe_policy_open() == RET_OK)
		{
			data_safe_policy_set_passwd(passwd);
			data_safe_policy_set_policy(policy);
			data_safe_policy_flush();
			data_safe_policy_close();
		}
		free(policy);
		free(passwd);
		free(filename);
	}
	else
	{
		printf("Authentication failed(%d), the action is logged.\n", ret);
	}
	data_safe_cmd_destroy(proxy);

	unlink("/dev/policy");

	while(1)
	{
		sleep(3600);
	}

	return 0;
}

