/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include "data_safe_crypto.h"

static Ret crypto_file(const char* filename, void* ctx)
{
	const char* passwd = ctx;

#ifdef DATA_SAFE_ENCRYPT
	if(!data_safe_get_tag(filename))
	{
		data_safe_encrypt_file(filename, passwd);
		data_safe_set_tag(filename, 1);
		printf("%s done.\n", filename);
	}
	else
	{
		printf("skip %s\n", filename);
	}
#else
	if(data_safe_get_tag(filename))
	{
		data_safe_set_tag(filename, 0);
		data_safe_decrypt_file(filename, passwd);
		printf("%s done.\n", filename);
	}
	else
	{
		printf("skip %s\n", filename);
	}
#endif

	return RET_OK;
}

int data_safe_crypto(DataSafeCmd* proxy, int sock, int argc, char* argv[])
{
	int i = 0;
	Ret ret = RET_FAIL;
	char* user = NULL;
	char* passwd = NULL;
	char* filename = NULL;
	DataSafeClientInfo info = {0};
	char magic[DATA_SAFE_MAGIC_LENGTH+1] = {0};

#ifdef DATA_SAFE_ENCRYPT
	if(argc != 2)
	{
		printf("=====================================================================\n");
		printf("Usage: %s file|path\n", argv[0]);
		printf("=====================================================================\n");

		return 0;
	}
	data_safe_get_proxy_magic(magic);
	user = "broncho";
	passwd = magic;
#else
	if(argc != 4)
	{
		printf("=====================================================================\n");
		printf("Usage: %s --user=xxx --passwd=yyy file|path\n", argv[0]);
		printf("=====================================================================\n");

		return 0;
	}
	data_safe_get_crypto_tool_magic(magic);
#endif
	for(i = 1; i < argc; i++)
	{
		if(strncmp(argv[i], "--user=", strlen("--user=")) == 0)
		{
			user = argv[i] + strlen("--user=");
			continue;
		}
		
		if(strncmp(argv[i], "--passwd=", strlen("--passwd=")) == 0)
		{
			passwd = argv[i] + strlen("--passwd=");
			continue;
		}

		if(argv[i][0] != '-')
		{
			filename = argv[i];
			continue;
		}
	}

	data_safe_client_info_init(&info, sock, user, passwd);
	strcpy(info.magic, magic);

	ret = data_safe_cmd_check(proxy, &info);
	if(!CHECK_IS_OK(ret))
	{
		printf("Authentication failed(%d), the action is logged.\n", ret);
		data_safe_cmd_destroy(proxy);
		exit(0);
	}

	passwd = NULL;
	ret = data_safe_cmd_get_passwd(proxy, &passwd);
	data_safe_cmd_destroy(proxy);

	if(passwd != NULL)
	{
		data_safe_foreach_file(filename, crypto_file, passwd);
		free(passwd);
	}

	return 0;
}


