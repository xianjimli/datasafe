/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <string.h>
#include "data_safe_cmd_proxy.h"

typedef struct _PrivInfo
{
	DataSafeStream* stream;
}PrivInfo;

static Ret  data_safe_cmd_proxy_check(DataSafeCmd* thiz, DataSafeClientInfo* info)
{
	int ret = 0;
	DataSafeCmdResponse resp = {0};
	DataSafeCmdRequest* req = NULL;
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	size_t length = sizeof(DataSafeCmdRequest) + sizeof(DataSafeClientInfo);
	
	req = calloc(1, length);
	req->type   = DATA_SAFE_CMD_CHECK;
	req->length = sizeof(DataSafeClientInfo);
	memcpy(req->data, info, sizeof(DataSafeClientInfo));

	resp.result = RET_FAIL;
	ret = data_safe_stream_write(priv->stream, req, length);
	if(ret == length)
	{
		ret = data_safe_stream_read(priv->stream, &resp, sizeof(resp));
	}
	free(req);

	return resp.result;
}

static Ret  data_safe_cmd_proxy_set_str_req(DataSafeCmd* thiz, int type, const char* str, int slen)
{
	int ret = 0;
	DataSafeCmdResponse resp = {0};
	DataSafeCmdRequest* req = NULL;
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	size_t data_length = slen >= 0 ? slen : strlen(str);
	size_t length = sizeof(DataSafeCmdRequest) + data_length;

	resp.result = RET_FAIL;
	req = calloc(1, length );
	req->length = data_length;
	req->type = type;
	memcpy(req->data, str, req->length);

	ret = data_safe_stream_write(priv->stream, req, length);
	if(ret == length)
	{
		ret = data_safe_stream_read(priv->stream, &resp, sizeof(resp));
	}
	free(req);

	return resp.result;
}

static Ret  data_safe_cmd_proxy_get_str_req(DataSafeCmd* thiz, int type, char** str)
{
	int ret = 0;
	DataSafeCmdResponse resp = {0};
	DataSafeCmdRequest* req = NULL;
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	size_t length = sizeof(DataSafeCmdRequest);

	resp.result = RET_FAIL;
	req = calloc(1, length);
	req->type = type;

	*str = NULL;
	ret = data_safe_stream_write(priv->stream, req, length);
	if(ret == length)
	{
		ret = data_safe_stream_read(priv->stream, &resp, sizeof(resp));
		if(ret == sizeof(resp) && resp.length > 0)
		{
			*str = calloc(1, resp.length + 1);
			ret = data_safe_stream_read(priv->stream, *str, resp.length);
		}
	}
	free(req);

	return resp.result;
}

static Ret  data_safe_cmd_proxy_set_policy(DataSafeCmd* thiz, const char* policy)
{
	return data_safe_cmd_proxy_set_str_req(thiz, DATA_SAFE_CMD_SET_POLICY, policy, -1);
}

static Ret  data_safe_cmd_proxy_get_policy(DataSafeCmd* thiz, char** policy)
{
	return data_safe_cmd_proxy_get_str_req(thiz, DATA_SAFE_CMD_GET_POLICY, policy);
}

static Ret  data_safe_cmd_proxy_get_users(DataSafeCmd* thiz, char** users)
{
	return data_safe_cmd_proxy_get_str_req(thiz, DATA_SAFE_CMD_GET_USERS, users);
}

static Ret  data_safe_cmd_proxy_set_mac_addrs(DataSafeCmd* thiz, const char* mac_addrs)
{
	return data_safe_cmd_proxy_set_str_req(thiz, DATA_SAFE_CMD_SET_MAC_ADDRS, mac_addrs, -1);
}

static Ret  data_safe_cmd_proxy_get_mac_addrs(DataSafeCmd* thiz, char** mac_addrs)
{
	return data_safe_cmd_proxy_get_str_req(thiz, DATA_SAFE_CMD_GET_MAC_ADDRS, mac_addrs);
}

static Ret  data_safe_cmd_proxy_get_passwd(DataSafeCmd* thiz, char** passwd)
{
	return data_safe_cmd_proxy_get_str_req(thiz, DATA_SAFE_CMD_GET_PASSWD, passwd);
}

static Ret  data_safe_cmd_proxy_get_app_pkg(DataSafeCmd* thiz, char** filename)
{
	int ret = 0;
	DataSafeCmdResponse resp = {0};
	DataSafeCmdRequest* req = NULL;
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	size_t length = sizeof(DataSafeCmdRequest);

	resp.result = RET_FAIL;
	req = calloc(1, length);
	req->type = DATA_SAFE_CMD_GET_APP_PKG;

	*filename = NULL;
	ret = data_safe_stream_write(priv->stream, req, length);
	if(ret == length)
	{
		ret = data_safe_stream_read(priv->stream, &resp, sizeof(resp));
		if(ret == sizeof(resp) && resp.length > 0)
		{
			char* data = calloc(1, 0x4000);
			FILE* fp = fopen(STR_C_APP_PKG, "wb+");

			do
			{
				if(data == NULL || fp == NULL) break;

				ret = data_safe_stream_read(priv->stream, data, 0x4000);
				if(ret <= 0) break;
				resp.length -= ret;
				fwrite(data, ret, 1, fp);
				fflush(fp);
				if(resp.length <= 0) break;
			}while(1);
			
			free(data);
			if(fp != NULL) fclose(fp);
			*filename = strdup(STR_C_APP_PKG);
		}
	}
	free(req);

	return resp.result;
}

static Ret  data_safe_cmd_proxy_delete_user(DataSafeCmd* thiz, const char* user)
{
	return data_safe_cmd_proxy_set_str_req(thiz, DATA_SAFE_CMD_DELETE_USER, user, -1);
}

static Ret  data_safe_cmd_proxy_add_user(DataSafeCmd* thiz, const char* user)
{
	return data_safe_cmd_proxy_set_str_req(thiz, DATA_SAFE_CMD_ADD_USER, user, -1);
}

static Ret  data_safe_cmd_proxy_change_passwd(DataSafeCmd* thiz, const char* user, const char* passwd)
{
	Ret ret = RET_FAIL;
	size_t slen = STR_LEN(user) + STR_LEN(passwd) + 2;
	char* str = calloc(slen, 1);
	memcpy(str, user, STR_LEN(user) + 1);
	memcpy(str+STR_LEN(user)+1, passwd, STR_LEN(passwd) + 1);

	ret = data_safe_cmd_proxy_set_str_req(thiz, DATA_SAFE_CMD_CHANGE_PASSWD, str, slen);
	free(str);

	return ret;
}

static void data_safe_cmd_proxy_destroy(DataSafeCmd* thiz)
{
	PrivInfo* priv = (PrivInfo*)thiz->priv;

	data_safe_stream_destroy(priv->stream);
	free(thiz);

	return ;
}

DataSafeCmd* data_safe_cmd_proxy_create(DataSafeStream* stream)
{
	DataSafeCmd* thiz = NULL;
	return_val_if_fail(stream != NULL, NULL);

	thiz = calloc(1, sizeof(DataSafeCmd) + sizeof(PrivInfo));

	if(thiz != NULL)
	{
		PrivInfo* priv = (PrivInfo*)thiz->priv;

		priv->stream        = stream;
		thiz->check         = data_safe_cmd_proxy_check;
		thiz->set_policy    = data_safe_cmd_proxy_set_policy;
		thiz->get_policy    = data_safe_cmd_proxy_get_policy;
		thiz->get_passwd    = data_safe_cmd_proxy_get_passwd;
		thiz->get_app_pkg   = data_safe_cmd_proxy_get_app_pkg;
		thiz->delete_user   = data_safe_cmd_proxy_delete_user;
		thiz->add_user      = data_safe_cmd_proxy_add_user;
		thiz->change_passwd = data_safe_cmd_proxy_change_passwd;
		thiz->get_users     = data_safe_cmd_proxy_get_users;
		thiz->set_mac_addrs = data_safe_cmd_proxy_set_mac_addrs;
		thiz->get_mac_addrs = data_safe_cmd_proxy_get_mac_addrs;
		thiz->destroy       = data_safe_cmd_proxy_destroy;
	}

	return thiz;
}

#ifdef TEST
int main(int argc, char* argv[])
{
	return 0;
}
#endif/*TEST*/
