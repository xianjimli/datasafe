/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include "data_safe_admin.h"

int data_safe_admin(DataSafeCmd* proxy, int sock, int argc, char* argv[])
{
	int i = 0;
	Ret ret = RET_FAIL;
	char* str = NULL;
	char* args = NULL;
	char* passwd = NULL;
	char* action = NULL;
	char magic[DATA_SAFE_MAGIC_LENGTH+1] = {0};
	DataSafeClientInfo info = {0};

	data_safe_get_admin_tool_magic(magic);
	if(argc < 3)
	{
		printf("=====================================================================\n");
		printf("Usage: %s --passwd=yyy --action=action --args=args\n", argv[0]);
		printf("  actions := adduser|deluser|changepasswd|getpolicy|setpolicy|getusers|getmacaddrs|setmacaddrs\n");
		printf("  args    := user|user:passwd|policy_file\n");
		printf("  examples:\n");
		printf("  %s --action=adduser --args=lixianjing\n", argv[0]);
		printf("  %s --action=deluser --args=lixianjing\n", argv[0]);
		printf("  %s --action=changepasswd --args=lixianjing:12345678\n", argv[0]);
		printf("  %s --action=getpolicy   --args=none\n", argv[0]);
		printf("  %s --action=setpolicy   --args=policy.txt\n", argv[0]);
		printf("  %s --action=getusers    --args=none\n", argv[0]);
		printf("  %s --action=getmacaddrs --args=none\n", argv[0]);
		printf("  %s --action=setmacaddrs --args=macaddrs.txt\n", argv[0]);
		printf("=====================================================================\n");

		return 0;
	}

	for(i = 1; i < argc; i++)
	{
		if(strncmp(argv[i], "--passwd=", strlen("--passwd=")) == 0)
		{
			passwd = argv[i] + strlen("--passwd=");
			continue;
		}

		if(strncmp(argv[i], "--action=", strlen("--action=")) == 0)
		{
			action = argv[i] + strlen("--action=");
			continue;
		}
		
		if(strncmp(argv[i], "--args=", strlen("--args=")) == 0)
		{
			args = argv[i] + strlen("--args=");
			continue;
		}
	}

	if(passwd == NULL)
	{
		passwd = getpass ("Password:");
	}

	data_safe_client_info_init(&info, sock, STR_ADMIN, passwd);
	strcpy(info.magic, magic);

	ret = data_safe_cmd_check(proxy, &info);
	if(ret != RET_IS_ADMIN)
	{
		printf("Authentication failed(%d), the action is logged.\n", ret);
		data_safe_cmd_destroy(proxy);
		exit(0);
	}

	ret = RET_FAIL;
	if(strcmp(action, "adduser") == 0)
	{
		ret = data_safe_cmd_add_user(proxy, args);
	}
	else if(strcmp(action, "deluser") == 0)
	{
		ret = data_safe_cmd_delete_user(proxy, args);
	}
	else if(strcmp(action, "changepasswd") == 0)
	{
		char* user = strdup(args);
		passwd = strchr(user, ':');
		if(passwd != NULL)
		{
			*passwd = '\0';
			passwd++;
			if(strlen(passwd) >= 8)
			{
				ret = data_safe_cmd_change_passwd(proxy, user, passwd);
			}
			else
			{
				printf("passwd is too short.\n");
			}
		}
		free(user);
	}
	else if(strcmp(action, "getpolicy") == 0)
	{
		ret = data_safe_cmd_get_policy(proxy, &str);
		if(str != NULL)
		{
			printf("%s", str);
			free(str);
		}
	}
	else if(strcmp(action, "setpolicy") == 0)
	{
		str = data_safe_read_file(args, NULL);
		if(str != NULL)
		{
			ret = data_safe_cmd_set_policy(proxy, str);
			free(str);
		}
	}
	else if(strcmp(action, "getusers") == 0)
	{
		ret = data_safe_cmd_get_users(proxy, &str);
		if(str != NULL)
		{
			printf("%s", str);
			free(str);
		}
	}
	else if(strcmp(action, "getmacaddrs") == 0)
	{
		ret = data_safe_cmd_get_mac_addrs(proxy, &str);
		if(str != NULL)
		{
			printf("%s", str);
			free(str);
		}
	}
	else if(strcmp(action, "setmacaddrs") == 0)
	{
		char* str = data_safe_read_file(args, NULL);
		if(str != NULL)
		{
			ret = data_safe_cmd_set_mac_addrs(proxy, str);
			free(str);
		}
	}

	printf("\n%s %s.\n", action, ret == RET_OK ? "Success" : "Failed");

	return 0;
}


