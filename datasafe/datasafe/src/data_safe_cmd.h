/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_CMD_H
#define DATA_SAFE_CMD_H

#include "data_safe_common.h"

struct _DataSafeCmd;
typedef struct _DataSafeCmd DataSafeCmd;

typedef enum _DataSafeCmdType
{
	DATA_SAFE_CMD_NONE,
	DATA_SAFE_CMD_CHECK,
	DATA_SAFE_CMD_SET_POLICY,
	DATA_SAFE_CMD_GET_POLICY,
	DATA_SAFE_CMD_GET_PASSWD,
	DATA_SAFE_CMD_GET_APP_PKG,
	DATA_SAFE_CMD_DELETE_USER,
	DATA_SAFE_CMD_ADD_USER,
	DATA_SAFE_CMD_CHANGE_PASSWD,
	DATA_SAFE_CMD_GET_USERS,
	DATA_SAFE_CMD_SET_MAC_ADDRS,
	DATA_SAFE_CMD_GET_MAC_ADDRS,
	DATA_SAFE_CMD_NR
}DataSafeCmdType;

typedef struct _DataSafeCmdRequest
{
	int type;
	int length;
	char data[0];
}DataSafeCmdRequest;

typedef struct _DataSafeCmdResponse
{
	int type;
	int result;
	int length;
	char data[0];
}DataSafeCmdResponse;

typedef Ret  (*DataSafeCmdCheck)(DataSafeCmd* thiz, DataSafeClientInfo* info);
typedef Ret  (*DataSafeCmdGetPolicy)(DataSafeCmd* thiz, char** policy);
typedef Ret  (*DataSafeCmdSetPolicy)(DataSafeCmd* thiz, const char* policy);
typedef Ret  (*DataSafeCmdGetPasswd)(DataSafeCmd* thiz, char** passwd);
typedef Ret  (*DataSafeCmdGetAppPkg)(DataSafeCmd* thiz, char** filename);
typedef Ret  (*DataSafeCmdDeleteUser)(DataSafeCmd* thiz, const char* user);
typedef Ret  (*DataSafeCmdAddUser)(DataSafeCmd* thiz, const char* user);
typedef Ret  (*DataSafeCmdGetUsers)(DataSafeCmd* thiz, char** users);
typedef Ret  (*DataSafeCmdGetMacAddrs)(DataSafeCmd* thiz, char** mac_addrs);
typedef Ret  (*DataSafeCmdSetMacAddrs)(DataSafeCmd* thiz, const char* mac_addrs);
typedef Ret  (*DataSafeCmdChangePasswd)(DataSafeCmd* thiz, const char* user, const char* passwd);
typedef void (*DataSafeCmdDestroy)(DataSafeCmd* thiz);

struct _DataSafeCmd
{
	DataSafeCmdCheck        check;
	DataSafeCmdSetPolicy    set_policy;
	DataSafeCmdGetPolicy    get_policy;
	DataSafeCmdGetPasswd    get_passwd;
	DataSafeCmdGetAppPkg    get_app_pkg;
	DataSafeCmdDeleteUser   delete_user;
	DataSafeCmdAddUser      add_user;
	DataSafeCmdChangePasswd change_passwd;
	DataSafeCmdGetUsers     get_users;
	DataSafeCmdGetMacAddrs  get_mac_addrs;
	DataSafeCmdSetMacAddrs  set_mac_addrs;
	DataSafeCmdDestroy      destroy;

	char priv[0];
};

static inline Ret  data_safe_cmd_check(DataSafeCmd* thiz, DataSafeClientInfo* info)
{
	return_val_if_fail(thiz != NULL && thiz->check && info != NULL, RET_FAIL);

	return thiz->check(thiz, info);
}

static inline Ret  data_safe_cmd_get_policy(DataSafeCmd* thiz, char** policy)
{
	return_val_if_fail(thiz != NULL && thiz->get_policy != NULL && policy != NULL, RET_FAIL);

	return thiz->get_policy(thiz, policy);
}

static inline Ret  data_safe_cmd_set_policy(DataSafeCmd* thiz, const char* policy)
{
	return_val_if_fail(thiz != NULL && thiz->set_policy != NULL && policy != NULL, RET_FAIL);

	return thiz->set_policy(thiz, policy);
}

static inline Ret  data_safe_cmd_get_passwd(DataSafeCmd* thiz, char** passwd)
{
	return_val_if_fail(thiz != NULL && thiz->get_passwd != NULL && passwd != NULL, RET_FAIL);

	return thiz->get_passwd(thiz, passwd);
}

static inline Ret  data_safe_cmd_get_app_pkg(DataSafeCmd* thiz, char** filename)
{
	return_val_if_fail(thiz != NULL && thiz->get_app_pkg != NULL && filename != NULL, RET_FAIL);

	return thiz->get_app_pkg(thiz, filename);
}

static inline Ret  data_safe_cmd_delete_user(DataSafeCmd* thiz, const char* user)
{
	return_val_if_fail(thiz != NULL && thiz->delete_user && user != NULL, RET_FAIL);

	return thiz->delete_user(thiz, user);
}

static inline Ret  data_safe_cmd_add_user(DataSafeCmd* thiz, const char* user)
{
	return_val_if_fail(thiz != NULL && thiz->add_user != NULL 
		&& user != NULL, RET_FAIL);

	return thiz->add_user(thiz, user);
}

static inline Ret  data_safe_cmd_change_passwd(DataSafeCmd* thiz, const char* user, const char* passwd)
{
	return_val_if_fail(thiz != NULL && thiz->change_passwd != NULL
		&& user != NULL && passwd != NULL, RET_FAIL);

	return thiz->change_passwd(thiz, user, passwd);
}

static inline Ret  data_safe_cmd_get_users(DataSafeCmd* thiz, char** users)
{
	return_val_if_fail(thiz != NULL && thiz->get_users != NULL && users != NULL, RET_FAIL);

	return thiz->get_users(thiz, users);
}

static inline Ret  data_safe_cmd_get_mac_addrs(DataSafeCmd* thiz, char** mac_addrs)
{
	return_val_if_fail(thiz != NULL && thiz->get_mac_addrs != NULL && mac_addrs != NULL, RET_FAIL);

	return thiz->get_mac_addrs(thiz, mac_addrs);
}

static inline Ret  data_safe_cmd_set_mac_addrs(DataSafeCmd* thiz, const char* mac_addrs)
{
	return_val_if_fail(thiz != NULL && thiz->set_mac_addrs != NULL && mac_addrs != NULL, RET_FAIL);

	return thiz->set_mac_addrs(thiz, mac_addrs);
}

static inline void data_safe_cmd_destroy(DataSafeCmd* thiz)
{
	if(thiz != NULL && thiz->destroy != NULL)
	{
		thiz->destroy(thiz);
	}

	return;
}

#endif/*DATA_SAFE_CMD_H*/

