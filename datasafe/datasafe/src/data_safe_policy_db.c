/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <expat.h>
#include <pthread.h>
#include "data_safe_policy_db.h"
#include "data_safe_encrypted_file.h"

#define DATA_SAFE_MAC_ADDRS 8192
#ifdef DATA_SAFE_POLICY_DB_TEST
#define DB_FILE "./data_safe_policy.xml"
#else
#define DB_FILE "/etc/datasafe/policy.xml"
#endif

struct _DataSafePolicyDb
{
	int  is_dirty;
	int  users_nr;
	char policy[POLICY_BUFFER_LEN+1];
	char mac_addrs[DATA_SAFE_MAC_ADDRS+1];
	char passwd[DATA_SAFE_PASSWD_LENGTH+1];
	UserInfo users[DATA_SAFE_MAX_USERS];
	char* user_names;
	pthread_mutex_t lock;
	/*expat state*/
	int in_policy_state;
	int in_mac_addrs_state;
};

static int data_safe_policy_db_find_user(DataSafePolicyDb* thiz, const char* user);

static void data_safe_policy_lock(DataSafePolicyDb* thiz)
{
	pthread_mutex_lock(&(thiz->lock));

	return;
}

static void data_safe_policy_unlock(DataSafePolicyDb* thiz)
{
	pthread_mutex_unlock(&(thiz->lock));

	return;
}

static void data_safe_policy_db_reset(DataSafePolicyDb* thiz)
{
	if(thiz != NULL)
	{
		thiz->passwd[0] = 'B';
		thiz->passwd[1] = 'R';
		thiz->passwd[2] = 'N';
		thiz->passwd[3] = '@';
		thiz->passwd[4] = 'c';
		thiz->passwd[5] = 'H';
		thiz->passwd[6] = 'i';
		thiz->passwd[7] = 'N';
		thiz->passwd[8] = 'a';
		thiz->passwd[9] = '1';
		thiz->passwd[10] = '.';
		thiz->passwd[11] = '2';
		thiz->passwd[12] = '0';
		thiz->passwd[13] = '1';
		thiz->passwd[14] = '0';
		thiz->passwd[15] = '*';
	}

	return;
}

DataSafePolicyDb* data_safe_policy_db_create(void)
{
	DataSafePolicyDb* thiz = calloc(1, sizeof(DataSafePolicyDb));

	if(thiz != NULL)
	{
		data_safe_policy_db_reset(thiz);
		pthread_mutex_init(&(thiz->lock), NULL);
	}

	return thiz;
}

static void on_start_element (void *userData, const XML_Char *name, const XML_Char **atts)
{
	DataSafePolicyDb* thiz = userData;

	if(strcmp(name, "policy") == 0)
	{
		thiz->in_policy_state = 1;		
		return;
	}
	
	if(strcmp(name, "mac_addrs") == 0)
	{
		thiz->in_mac_addrs_state = 1;		
		return;
	}


	if(strcmp(name, "passwd") == 0 && atts != NULL)
	{
#ifdef DATA_SAFE_POLICY_DB_TEST 
		strncpy(thiz->passwd, atts[1], DATA_SAFE_PASSWD_LENGTH);
#endif
		return;
	}
	
	if(strcmp(name, "user") == 0 && atts != NULL)
	{
		UserInfo info = {0};
		strncpy(info.name, atts[1], DATA_SAFE_USER_LENGTH);
		strncpy(info.passwd, atts[3], DATA_SAFE_PASSWD_LENGTH);
		data_safe_policy_db_add_user(thiz, info.name);
		data_safe_policy_db_change_passwd(thiz, &info);

		return;
	}

	return;
}

static void on_end_element (void *userData, const XML_Char *name)
{
	DataSafePolicyDb* thiz = userData;
	
	if(strcmp(name, "policy") == 0)
	{
		thiz->in_policy_state = 0;		
	}
	
	if(strcmp(name, "mac_addrs") == 0)
	{
		thiz->in_mac_addrs_state = 0;		
	}

	return;
}

static void on_text (void *userData, const XML_Char *s, int len)
{
	DataSafePolicyDb* thiz = userData;

	if(thiz->in_policy_state)
	{
		strncat(thiz->policy, s, len);
	}

	if(thiz->in_mac_addrs_state)
	{
		strncat(thiz->mac_addrs, s, len);
	}

	return;
}

Ret  data_safe_policy_db_load(DataSafePolicyDb* thiz)
{
	int length = 0;
	char* buffer = data_safe_read_file(DB_FILE, &length);

	if(buffer != NULL)
	{
		char passwd[DATA_SAFE_PASSWD_LENGTH+1] = {0};
		XML_Parser parser = XML_ParserCreate(NULL);

		memset(thiz->mac_addrs, 0x00, sizeof(thiz->mac_addrs));
		memset(thiz->policy, 0x00, sizeof(thiz->policy));
#ifndef DATA_SAFE_POLICY_DB_TEST
		data_safe_decrypt_buff(buffer, length, data_safe_get_trans_passwd(passwd));	
#endif		
		XML_SetUserData(parser, thiz);
		XML_SetElementHandler(parser, on_start_element, on_end_element);
		XML_SetCharacterDataHandler(parser, on_text);
		XML_Parse(parser, buffer, strlen(buffer), 1);
		XML_ParserFree(parser);

		free(buffer);
	}

	if(data_safe_policy_db_find_user(thiz, STR_ADMIN) < 0)
	{
		UserInfo info = {0};
		strcpy(info.name, STR_ADMIN);
		info.passwd[0] = 'b';
		info.passwd[1] = 'r';
		info.passwd[2] = 'n';
		info.passwd[3] = 'A';
		info.passwd[4] = 'D';
		info.passwd[5] = 'M';
		info.passwd[6] = 'I';
		info.passwd[7] = 'N';
		info.passwd[8] = '\0';
		data_safe_policy_db_add_user(thiz, info.name);
		data_safe_policy_db_change_passwd(thiz, &info);
		data_safe_policy_db_save(thiz);
	}

	return RET_OK;
}

static int data_safe_policy_db_calc_length(DataSafePolicyDb* thiz)
{
	int  i = 0;
	int length = 1024;
	return_val_if_fail(thiz != NULL, 0);

	if(thiz->policy != NULL)
	{
		length += strlen(thiz->policy);
	}

	for(i = 0; i < thiz->users_nr; i++)
	{
		length += 128;
	}

	if(thiz->mac_addrs != NULL)
	{
		length += strlen(thiz->mac_addrs);
	}

	return length;
}

Ret  data_safe_policy_db_save(DataSafePolicyDb* thiz)
{
	int i = 0;
	int ret = 0;
	char* p = NULL;
	char* buffer = NULL;
	char passwd[DATA_SAFE_PASSWD_LENGTH+1] = {0};
	return_val_if_fail(thiz != NULL, RET_FAIL);

	if(!thiz->is_dirty)
	{
		return RET_OK;
	}

	data_safe_policy_lock(thiz);
	buffer = calloc(1, data_safe_policy_db_calc_length(thiz));
	return_val_if_fail(buffer != NULL, RET_FAIL);

	p = buffer;
	p += sprintf(p, "<data_safe_policy>\n");
#ifdef DATA_SAFE_POLICY_DB_TEST 
	p += sprintf(p, "<passwd value=\"%s\"/>\n", thiz->passwd);
#endif	
	p += sprintf(p, "<policy>%s</policy>\n", thiz->policy);
	p += sprintf(p, "<mac_addrs>%s</mac_addrs>\n", thiz->mac_addrs);
	for(i = 0; i < thiz->users_nr; i++)
	{
		p += sprintf(p, "<user name=\"%s\" passwd=\"%s\"/>\n", 
			thiz->users[i].name, thiz->users[i].passwd);
	}
	p += sprintf(p, "</data_safe_policy>\n");

	size_t length = strlen(buffer);
#ifndef DATA_SAFE_POLICY_DB_TEST	
	data_safe_encrypt_buff(buffer, length, data_safe_get_trans_passwd(passwd));	
#endif	
	data_safe_write_file(DB_FILE, buffer, length);
	free(buffer);
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_get_passwd(DataSafePolicyDb* thiz, const char** passwd)
{
	return_val_if_fail(thiz != NULL && passwd != NULL, RET_FAIL);

	data_safe_policy_lock(thiz);
	*passwd = thiz->passwd;
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_set_passwd(DataSafePolicyDb* thiz, const char* passwd)
{
	return_val_if_fail(thiz != NULL && passwd != NULL, RET_FAIL);

	data_safe_policy_lock(thiz);
#ifdef DATA_SAFE_POLICY_DB_TEST 
	strncpy(thiz->passwd, passwd, sizeof(thiz->passwd) - 1);
#endif	
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_get_policy(DataSafePolicyDb* thiz, const char** policy)
{
	return_val_if_fail(thiz != NULL && policy != NULL, RET_FAIL);

	data_safe_policy_lock(thiz);
	*policy = thiz->policy;
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_set_policy(DataSafePolicyDb* thiz, const char* policy)
{
	return_val_if_fail(thiz != NULL && policy != NULL, RET_FAIL);

	data_safe_policy_lock(thiz);
	thiz->is_dirty = 1;
	strncpy(thiz->policy, policy, sizeof(thiz->policy));
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_get_users(DataSafePolicyDb* thiz, const char** users)
{
	int i = 0;
	int length = 1;
	return_val_if_fail(thiz != NULL && users != NULL, RET_FAIL);

	data_safe_policy_lock(thiz);
	for(i = 0; i < thiz->users_nr; i++)
	{
		length += strlen(thiz->users[i].name) + 1;
	}

	if(thiz->user_names != NULL)
	{
		free(thiz->user_names);
		thiz->user_names = NULL;
	}

	thiz->user_names = calloc(length + 1, 1);
	for(i = 0; i < thiz->users_nr; i++)
	{
		strcat(thiz->user_names, thiz->users[i].name);
		strcat(thiz->user_names, "\n");
	}
	*users = thiz->user_names;
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_get_mac_addrs(DataSafePolicyDb* thiz, const char** mac_addrs)
{
	return_val_if_fail(thiz != NULL && mac_addrs != NULL, RET_FAIL);

	data_safe_policy_lock(thiz);
	*mac_addrs = thiz->mac_addrs;
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_set_mac_addrs(DataSafePolicyDb* thiz, const char* mac_addrs)
{
	return_val_if_fail(thiz != NULL && mac_addrs != NULL, RET_FAIL);

	data_safe_policy_lock(thiz);
	thiz->is_dirty = 1;
	strncpy(thiz->mac_addrs, mac_addrs, sizeof(thiz->mac_addrs));
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

static int data_safe_policy_db_find_user(DataSafePolicyDb* thiz, const char* user)
{
	int i = 0;
	return_val_if_fail(thiz != NULL && user != NULL, -1);

	for(i = 0; i < thiz->users_nr; i++)
	{
		if(strcmp(thiz->users[i].name, user) == 0)
		{
			return i;
		}
	}

	return -1;
}

Ret  data_safe_policy_db_add_user(DataSafePolicyDb* thiz, const char* user)
{
	if(data_safe_policy_db_find_user(thiz, user) >= 0)
	{
		return RET_EXISTS;
	}

	data_safe_policy_lock(thiz);
	thiz->is_dirty = 1;
	memset(thiz->users+thiz->users_nr, 0x00, sizeof(UserInfo));
	strncpy(thiz->users[thiz->users_nr].name, user, DATA_SAFE_USER_LENGTH);
	thiz->users_nr++;
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_del_user(DataSafePolicyDb* thiz, const char* user)
{
	int i = data_safe_policy_db_find_user(thiz, user);
	return_val_if_fail(thiz != NULL && user != NULL && i >= 0, RET_FAIL);

	data_safe_policy_lock(thiz);
	for(; (i + 1) < thiz->users_nr; i++)
	{
		memcpy(thiz->users+i, thiz->users+i + 1, sizeof(UserInfo));
	}
	thiz->users_nr--;
	thiz->is_dirty = 1;
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_change_passwd(DataSafePolicyDb* thiz, UserInfo* info)
{
	int i = data_safe_policy_db_find_user(thiz, info->name);	
	return_val_if_fail(thiz != NULL && info != NULL && i >= 0, RET_FAIL);

	data_safe_policy_lock(thiz);
	strncpy(thiz->users[i].passwd, info->passwd, DATA_SAFE_PASSWD_LENGTH);
	thiz->is_dirty = 1;
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

Ret  data_safe_policy_db_check_user(DataSafePolicyDb* thiz, UserInfo* info)
{
	int i = 0;
	return_val_if_fail(thiz != NULL && info != NULL, RET_FAIL);
	i = data_safe_policy_db_find_user(thiz, info->name);	
	return_val_if_fail(i >= 0, RET_FAIL);
	
	if(strcmp(thiz->users[i].passwd, info->passwd) == 0)
	{
		return RET_OK;
	}

	return RET_FAIL;
}

Ret  data_safe_policy_db_get_user_nr(DataSafePolicyDb* thiz)
{
	return_val_if_fail(thiz != NULL, 0);

	return thiz->users_nr;
}

Ret  data_safe_policy_db_get_user(DataSafePolicyDb* thiz, int index, UserInfo* info)
{
	return_val_if_fail(thiz != NULL && info != NULL && index < thiz->users_nr, RET_FAIL);

	data_safe_policy_lock(thiz);
	memcpy(info, thiz->users+index, sizeof(UserInfo));
	data_safe_policy_unlock(thiz);

	return RET_OK;
}

void data_safe_policy_db_destroy(DataSafePolicyDb* thiz)
{
	if(thiz != NULL)
	{
		free(thiz->user_names);
		pthread_mutex_destroy(&(thiz->lock));
		free(thiz);
	}

	return;
}

#ifdef DATA_SAFE_POLICY_DB_TEST
#include <assert.h>

#define TEST_PASSWD "12345678"
#define TEST_POLICY "/usr/bin/g++;fd61f1d57d1202cf1fe4792891f1f41b;1;0\n"
#define TEST_MAC_ADDRS "002421F1EF25"

int main(int argc, char* argv[])
{
	int i = 0;
	UserInfo info;
	const char* users = NULL;
	const char* passwd = NULL;
	const char* policy = NULL;
	const char* mac_addrs = NULL;
	DataSafePolicyDb* thiz = data_safe_policy_db_create();

	assert(data_safe_policy_db_set_passwd(thiz, TEST_PASSWD) == RET_OK);
	assert(data_safe_policy_db_set_policy(thiz, TEST_POLICY) == RET_OK);
	assert(data_safe_policy_db_get_passwd(thiz, &passwd) == RET_OK);
	assert(strcmp(passwd, TEST_PASSWD) == 0);
	assert(data_safe_policy_db_get_policy(thiz, &policy) == RET_OK);
	assert(strcmp(policy, TEST_POLICY) == 0);

	assert(data_safe_policy_db_set_mac_addrs(thiz, TEST_MAC_ADDRS) == RET_OK);
	assert(data_safe_policy_db_get_mac_addrs(thiz, &mac_addrs) == RET_OK);
	assert(strcmp(mac_addrs, TEST_MAC_ADDRS) == 0);

	for(i = 0; i < 20; i++)
	{
		sprintf(info.name, "user%d", i);
		sprintf(info.passwd, "passwd%d", i);
		assert(data_safe_policy_db_add_user(thiz, info.name) == RET_OK);
		assert(data_safe_policy_db_change_passwd(thiz, &info) == RET_OK);
		assert(data_safe_policy_db_get_user_nr(thiz) == i + 1);
	}

	assert(data_safe_policy_db_get_users(thiz, &users) == RET_OK);

	for(i = 0; i < 20; i++)
	{
		sprintf(info.name, "user%d", i);
		sprintf(info.passwd, "passwd%d", i);
		assert(data_safe_policy_db_del_user(thiz, info.name) == RET_OK);
	}
	assert(data_safe_policy_db_get_user_nr(thiz) == 0);
	
	assert(data_safe_policy_db_add_user(thiz, STR_ADMIN) == RET_OK);
	assert(data_safe_policy_db_get_user_nr(thiz) == 1);
	assert(data_safe_policy_db_add_user(thiz, "lixianjing") == RET_OK);
	assert(data_safe_policy_db_get_user_nr(thiz) == 2);
	strcpy(info.name, STR_ADMIN);
	strcpy(info.passwd, TEST_PASSWD);
	assert(data_safe_policy_db_change_passwd(thiz, &info) == RET_OK);

	assert(data_safe_policy_db_save(thiz) == RET_OK);
	data_safe_policy_db_destroy(thiz);

	thiz = data_safe_policy_db_create();
	assert(data_safe_policy_db_load(thiz) == RET_OK);
	assert(data_safe_policy_db_get_passwd(thiz, &passwd) == RET_OK);
	assert(strcmp(passwd, TEST_PASSWD) == 0);
	assert(data_safe_policy_db_get_policy(thiz, &policy) == RET_OK);
	assert(data_safe_policy_db_get_user_nr(thiz) == 2);
	assert(data_safe_policy_db_get_mac_addrs(thiz, &mac_addrs) == RET_OK);

	assert(strcmp(policy, TEST_POLICY) == 0);
	data_safe_policy_db_destroy(thiz);

	return 0;
}
#endif/*TEST*/

