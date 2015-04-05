/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <string.h>
#include "data_safe_cmd_local.h"

typedef struct _PrivInfo
{
	DataSafePolicyDb* db;
}PrivInfo;

static int  data_safe_cmd_is_proxy(DataSafeClientInfo* info)
{
	char magic[DATA_SAFE_MAGIC_LENGTH + 1] = {0};
	data_safe_get_proxy_magic(magic);
	if( strcmp(info->user, "broncho") == 0 && strcmp(info->magic, magic) == 0)
	{
		return 1;
	}

	return 0;
}

static Ret  data_safe_cmd_local_check(DataSafeCmd* thiz, DataSafeClientInfo* info)
{
	Ret ret = RET_FAIL;
	UserInfo user = {0};
	const char* mac_addrs = NULL;
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);

	strncpy(user.name, info->user, DATA_SAFE_USER_LENGTH);
	strncpy(user.passwd, info->passwd, DATA_SAFE_USER_LENGTH);

	ret = data_safe_policy_db_check_user(priv->db, &user);
	if(ret == RET_OK)
	{
		if(strcmp(user.name, STR_ADMIN) == 0)
		{
			return RET_IS_ADMIN;
		}
		else
		{
			return RET_OK;
		}
	}
	
	data_safe_policy_db_get_mac_addrs(priv->db, &mac_addrs);
	if(mac_addrs != NULL && strstr(mac_addrs, info->mac) == NULL)
	{
		return RET_ILLEGAL_MAC;
	}

	if(data_safe_cmd_is_proxy(info))
	{
		return RET_OK;
	}

	return RET_FAIL;
}

static Ret  data_safe_cmd_local_set_policy(DataSafeCmd* thiz, const char* policy)
{
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);
	
	data_safe_policy_db_set_policy(priv->db, policy);

	return RET_OK;
}

static Ret  data_safe_cmd_local_get_policy(DataSafeCmd* thiz, char** policy)
{
	const char* str = NULL;
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);
	
	data_safe_policy_db_get_policy(priv->db, &str);

	*policy = STR_DUP(str);
	
	return RET_OK;
}

static Ret  data_safe_cmd_local_get_users(DataSafeCmd* thiz, char** users)
{
	const char* str = NULL;
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);
	
	data_safe_policy_db_get_users(priv->db, &str);

	*users = STR_DUP(str);
	
	return RET_OK;
}


static Ret  data_safe_cmd_local_set_mac_addrs(DataSafeCmd* thiz, const char* mac_addrs)
{
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);
	
	data_safe_policy_db_set_mac_addrs(priv->db, mac_addrs);

	return RET_OK;
}

static Ret  data_safe_cmd_local_get_mac_addrs(DataSafeCmd* thiz, char** mac_addrs)
{
	const char* str = NULL;
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);
	
	data_safe_policy_db_get_mac_addrs(priv->db, &str);

	*mac_addrs = STR_DUP(str);
	
	return RET_OK;
}


static Ret  data_safe_cmd_local_get_passwd(DataSafeCmd* thiz, char** passwd)
{
	const char* str = NULL;
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);

	data_safe_policy_db_get_passwd(priv->db, &str);
	*passwd = STR_DUP(str);

	return RET_OK;
}

static Ret  data_safe_cmd_local_delete_user(DataSafeCmd* thiz, const char* user)
{
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);

	return data_safe_policy_db_del_user(priv->db, user);
}

static Ret  data_safe_cmd_local_add_user(DataSafeCmd* thiz, const char* user)
{
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);

	return data_safe_policy_db_add_user(priv->db, user);
}

static Ret  data_safe_cmd_local_change_passwd(DataSafeCmd* thiz, const char* user, const char* passwd)
{
	UserInfo info = {0};
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	return_val_if_fail(priv->db != NULL, RET_FAIL);

	strncpy(info.name, user, DATA_SAFE_USER_LENGTH);
	strncpy(info.passwd, passwd, DATA_SAFE_PASSWD_LENGTH);

	return data_safe_policy_db_change_passwd(priv->db, &info);
}

static void data_safe_cmd_local_destroy(DataSafeCmd* thiz)
{
	PrivInfo* priv = (PrivInfo*)thiz->priv;

	free(thiz);

	return ;
}

DataSafeCmd* data_safe_cmd_local_create(DataSafePolicyDb* db)
{
	DataSafeCmd* thiz = NULL;
	return_val_if_fail(db != NULL, NULL);

	thiz = calloc(1, sizeof(DataSafeCmd) + sizeof(PrivInfo));

	if(thiz != NULL)
	{
		PrivInfo* priv = (PrivInfo*)thiz->priv;

		priv->db = db;
		thiz->check         = data_safe_cmd_local_check;
		thiz->set_policy    = data_safe_cmd_local_set_policy;
		thiz->get_policy    = data_safe_cmd_local_get_policy;
		thiz->get_passwd    = data_safe_cmd_local_get_passwd;
		thiz->delete_user   = data_safe_cmd_local_delete_user;
		thiz->add_user      = data_safe_cmd_local_add_user;
		thiz->change_passwd = data_safe_cmd_local_change_passwd;
		thiz->get_users     = data_safe_cmd_local_get_users;
		thiz->set_mac_addrs = data_safe_cmd_local_set_mac_addrs;
		thiz->get_mac_addrs = data_safe_cmd_local_get_mac_addrs;
		thiz->destroy       = data_safe_cmd_local_destroy;
	}

	return thiz;
}

#ifdef TEST
int main(int argc, char* argv[])
{
	return 0;
}
#endif/*TEST*/

