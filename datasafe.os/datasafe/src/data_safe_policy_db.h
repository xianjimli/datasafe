/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_POLICY_DB_H
#define DATA_SAFE_POLICY_DB_H

#include "data_safe_common.h"

typedef struct _UserInfo
{
	char name[DATA_SAFE_USER_LENGTH + 1];
	char passwd[DATA_SAFE_PASSWD_LENGTH + 1];
}UserInfo;

struct _DataSafePolicyDb;
typedef struct _DataSafePolicyDb DataSafePolicyDb;

DataSafePolicyDb* data_safe_policy_db_create(void);

Ret  data_safe_policy_db_load(DataSafePolicyDb* thiz);
Ret  data_safe_policy_db_save(DataSafePolicyDb* thiz);
Ret  data_safe_policy_db_get_passwd(DataSafePolicyDb* thiz, const char** passwd);
Ret  data_safe_policy_db_set_passwd(DataSafePolicyDb* thiz, const char* passwd);
Ret  data_safe_policy_db_get_policy(DataSafePolicyDb* thiz, const char** policy);
Ret  data_safe_policy_db_set_policy(DataSafePolicyDb* thiz, const char* policy);
Ret  data_safe_policy_db_get_users(DataSafePolicyDb* thiz, const char** users);
Ret  data_safe_policy_db_get_mac_addrs(DataSafePolicyDb* thiz, const char** mac_addrs);
Ret  data_safe_policy_db_set_mac_addrs(DataSafePolicyDb* thiz, const char* mac_addrs);
Ret  data_safe_policy_db_add_user(DataSafePolicyDb* thiz, const char* user);
Ret  data_safe_policy_db_del_user(DataSafePolicyDb* thiz, const char* user);
Ret  data_safe_policy_db_check_user(DataSafePolicyDb* thiz, UserInfo* info);
Ret  data_safe_policy_db_change_passwd(DataSafePolicyDb* thiz, UserInfo* info);
Ret  data_safe_policy_db_get_user_nr(DataSafePolicyDb* thiz);
Ret  data_safe_policy_db_get_user(DataSafePolicyDb* thiz, int index, UserInfo* info);
void data_safe_policy_db_destroy(DataSafePolicyDb* thiz);

#endif/*DATA_SAFE_POLICY_DB_H*/

