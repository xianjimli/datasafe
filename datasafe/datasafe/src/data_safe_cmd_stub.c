/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <time.h>
#include <assert.h>
#include <string.h>
#include <syslog.h>
#include "data_safe_cmd_stub.h"
#include "data_safe_cmd_local.h"

typedef struct _DataSafeCmdStub
{
	FILE* log;
	int logined;
	int is_admin;
	DataSafeCmd* local;
	DataSafeStream* stream;
	DataSafeCmdRequest req;
	DataSafeCmdResponse resp;
	DataSafeClientInfo client;
}DataSafeCmdStub;

static Ret data_safe_log_time(DataSafeCmdStub* thiz)
{
	char buffer[64] = {0};
	time_t now = time(0);
	time_t result = 0;
	struct tm tm_now;
	localtime_r(&now, &tm_now);
	
	strftime(buffer, sizeof(buffer), "[%D %H:%M:%S]: ", &tm_now);
	fprintf(thiz->log, "%s", buffer);
	
	return RET_OK;;
}

static Ret  data_safe_cmd_stub_check(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	return_val_if_fail(thiz->req.length == sizeof(DataSafeClientInfo), RET_FAIL);
	
	ret_length = data_safe_stream_read(thiz->stream, &thiz->client, sizeof(DataSafeClientInfo));
	if(ret_length == sizeof(DataSafeClientInfo))
	{
		ret = data_safe_cmd_check(thiz->local, &thiz->client);
		if(ret == RET_OK)
		{
			thiz->logined = 1;
		}
		else if(ret == RET_IS_ADMIN)
		{
			thiz->logined = 1;
			thiz->is_admin = 1;
		}
		thiz->resp.result = ret;

		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_set_policy(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	
	if(thiz->logined)
	{
		char* policy = calloc(1, thiz->req.length + 1);
		ret_length = data_safe_stream_read(thiz->stream, policy, thiz->req.length);
		ret = data_safe_cmd_set_policy(thiz->local, policy);
		thiz->resp.result = ret;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
		free(policy);
	}
	else
	{
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_get_policy(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	
	if(thiz->logined)
	{
		char* policy = NULL;

		ret = data_safe_cmd_get_policy(thiz->local, &policy);

		thiz->resp.result = ret;
		thiz->resp.length = STR_LEN(policy);
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
		if(policy != NULL)
		{
			ret_length = data_safe_stream_write(thiz->stream, policy, STR_LEN(policy));
			free(policy);
		}
	}
	else
	{
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_get_users(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	
	if(thiz->is_admin)
	{
		char* users = NULL;

		ret = data_safe_cmd_get_users(thiz->local, &users);

		thiz->resp.result = ret;
		thiz->resp.length = STR_LEN(users);
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
		if(users != NULL)
		{
			ret_length = data_safe_stream_write(thiz->stream, users, STR_LEN(users));
			free(users);
		}
	}
	else
	{
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_set_mac_addrs(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	
	if(thiz->is_admin)
	{
		char* mac_addrs = calloc(1, thiz->req.length + 1);
		ret_length = data_safe_stream_read(thiz->stream, mac_addrs, thiz->req.length);
		ret = data_safe_cmd_set_mac_addrs(thiz->local, mac_addrs);
		thiz->resp.result = ret;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
		free(mac_addrs);
	}
	else
	{
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_get_mac_addrs(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	
	if(thiz->is_admin)
	{
		char* mac_addrs = NULL;

		ret = data_safe_cmd_get_mac_addrs(thiz->local, &mac_addrs);

		thiz->resp.result = ret;
		thiz->resp.length = STR_LEN(mac_addrs);
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
		if(mac_addrs != NULL)
		{
			ret_length = data_safe_stream_write(thiz->stream, mac_addrs, STR_LEN(mac_addrs));
			free(mac_addrs);
		}
	}
	else
	{
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_get_passwd(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	
	if(thiz->logined)
	{
		char* passwd = NULL;

		ret = data_safe_cmd_get_passwd(thiz->local, &passwd);

		thiz->resp.result = ret;
		thiz->resp.length = STR_LEN(passwd);
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
		if(passwd != NULL)
		{
			ret_length = data_safe_stream_write(thiz->stream, passwd, STR_LEN(passwd));
			free(passwd);
		}
	}
	else
	{
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_get_app_pkg(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	
	if(thiz->logined)
	{
		int length = 0;
		char* content = NULL;
		content = data_safe_read_file(STR_APP_PKG, &length);

		thiz->resp.length = length;
		thiz->resp.result = content != NULL ? RET_OK : RET_FAIL;

		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
		if(ret_length == sizeof(thiz->resp) && content != NULL)
		{
			ret_length = data_safe_stream_write(thiz->stream, content, length);
		}
		free(content);
		ret = RET_OK;
	}
	else
	{
		ret = RET_NO_PERMISSION;
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_delete_user(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	char* user = NULL;

	user = calloc(1, thiz->req.length  + 1);
	ret_length = data_safe_stream_read(thiz->stream, user, thiz->req.length);

	if(thiz->is_admin)
	{
		ret = data_safe_cmd_delete_user(thiz->local, user);
		thiz->resp.result = ret;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}
	else
	{
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d data=%s\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret, user);
	free(user);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_add_user(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	char* user = NULL;

	user = calloc(1, thiz->req.length  + 1);
	ret_length = data_safe_stream_read(thiz->stream, user, thiz->req.length);

	if(thiz->is_admin)
	{
		ret = data_safe_cmd_add_user(thiz->local, user);
		thiz->resp.result = ret;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}
	else
	{
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d data=%s\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret, user);
	free(user);

	return RET_OK;
}

static Ret  data_safe_cmd_stub_change_passwd(DataSafeCmdStub* thiz)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	char* user_passwd = NULL;

	user_passwd = calloc(1, thiz->req.length  + 1);
	ret_length = data_safe_stream_read(thiz->stream, user_passwd, thiz->req.length);

	if(thiz->is_admin || (thiz->logined && strcmp(user_passwd, thiz->client.user) == 0))
	{
		ret = data_safe_cmd_change_passwd(thiz->local, user_passwd, 
			user_passwd + strlen(user_passwd) + 1);
		thiz->resp.result = ret;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}
	else
	{
		thiz->resp.result = RET_NO_PERMISSION;
		ret_length = data_safe_stream_write(thiz->stream, &thiz->resp, sizeof(thiz->resp));
	}

	fprintf(thiz->log, "ip=%s mac=%s user=%s login_user=%s req=%d ret=%d data=%s\n", 
		thiz->client.ip, thiz->client.mac, thiz->client.user, thiz->client.login_user,
		thiz->req.type, ret, user_passwd);
	free(user_passwd);

	return RET_OK;
}

static void data_safe_cmd_stub_destroy(DataSafeCmdStub* thiz)
{
	free(thiz);

	return ;
}

static DataSafeCmdStub* data_safe_cmd_stub_create(DataSafeStream* stream, DataSafePolicyDb* db, FILE* log)
{
	DataSafeCmdStub* thiz = calloc(1, sizeof(DataSafeCmdStub));

	if(thiz != NULL)
	{
		thiz->log = log != NULL ? log : stderr;
		thiz->stream = stream;
		thiz->local = data_safe_cmd_local_create(db);
	}

	return thiz;
}

Ret data_safe_cmd_loop(DataSafeStream* stream, DataSafePolicyDb* db, FILE* log)
{
	int ret_length = 0;
	Ret ret = RET_FAIL;
	DataSafeCmdStub* thiz = NULL;
	return_val_if_fail(stream != NULL, RET_FAIL);

	thiz = data_safe_cmd_stub_create(stream, db, log);
	return_val_if_fail(thiz != NULL, RET_FAIL);

	do
	{
		memset(&thiz->req, 0x00, sizeof(thiz->req));
		memset(&thiz->resp, 0x00, sizeof(thiz->resp));

		ret_length = data_safe_stream_read(stream, &(thiz->req), sizeof(DataSafeCmdRequest));
		if(ret_length != sizeof(DataSafeCmdRequest))
		{
			break;
		}

		data_safe_log_time(thiz);
		thiz->resp.type = thiz->req.type;
		switch(thiz->req.type)
		{
			case DATA_SAFE_CMD_CHECK:
			{
				ret = data_safe_cmd_stub_check(thiz);
				break;
			}
			case DATA_SAFE_CMD_SET_POLICY:
			{
				ret = data_safe_cmd_stub_set_policy(thiz);
				break;
			}
			case DATA_SAFE_CMD_GET_POLICY:
			{
				ret = data_safe_cmd_stub_get_policy(thiz);
				break;
			}
			case DATA_SAFE_CMD_GET_PASSWD:
			{
				ret = data_safe_cmd_stub_get_passwd(thiz);
				break;
			}
			case DATA_SAFE_CMD_GET_APP_PKG:
			{
				ret = data_safe_cmd_stub_get_app_pkg(thiz);
				break;
			}
			case DATA_SAFE_CMD_DELETE_USER:
			{
				ret = data_safe_cmd_stub_delete_user(thiz);
				break;
			}
			case DATA_SAFE_CMD_ADD_USER:
			{
				ret = data_safe_cmd_stub_add_user(thiz);
				break;
			}
			case DATA_SAFE_CMD_CHANGE_PASSWD:
			{
				ret = data_safe_cmd_stub_change_passwd(thiz);
				break;
			}
			case DATA_SAFE_CMD_GET_USERS:
			{
				ret = data_safe_cmd_stub_get_users(thiz);
				break;
			}
			case DATA_SAFE_CMD_GET_MAC_ADDRS:
			{
				ret = data_safe_cmd_stub_get_mac_addrs(thiz);
				break;
			}
			case DATA_SAFE_CMD_SET_MAC_ADDRS:
			{
				ret = data_safe_cmd_stub_set_mac_addrs(thiz);
				break;
			}
			default:break;
		}
		fflush(log);
	}while(ret == RET_OK);

	data_safe_policy_db_save(db);
	data_safe_cmd_stub_destroy(thiz);

	return ret;
}

#ifdef TEST
int main(int argc, char* argv[])
{
	return 0;
}
#endif/*TEST*/

