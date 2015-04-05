/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_COMMON_H
#define DATA_SAFE_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "policy_dev.h"
#include "data_safe_crypto_algo.h"

#define STR_VERSION "r1.0(2010912)"
#define KERNEL_RELEASE "2.6.31.5-broncho"
#define KERNEL_VERSION "#3 SMP Fri May 7 14:16:32 CST 2010"

typedef struct _DataSafeClientInfo
{
	char ip[16];
	char mac[16];
	char version[32];
	char magic[DATA_SAFE_MAGIC_LENGTH + 1];
	char user[DATA_SAFE_USER_LENGTH + 1];
	char passwd[DATA_SAFE_PASSWD_LENGTH + 1];
	char login_user[DATA_SAFE_USER_LENGTH + 1];
}DataSafeClientInfo;

typedef enum _Ret
{
	RET_OK,
	RET_FAIL,
	RET_EXISTS,
	RET_IO_ERR,
	RET_IS_ADMIN,
	RET_NO_PERMISSION,
	RET_ILLEGAL_MAC
}Ret;

void data_safe_crack_detect(void);
int data_safe_get_mac_addr(char* addr);
int data_safe_get_tag(const char* filename);
Ret data_safe_set_tag(const char* filename, int value);

int data_safe_is_binary(const char* filename);
int data_safe_is_crypto_ext(const char* filename);
int digit_to_hex(const char* in, int len, char* out);

char* data_safe_read_file(const char* filename, int* length);
void  data_safe_write_file(const char* filename, char* contents, size_t length);
Ret data_safe_client_info_init(DataSafeClientInfo* info, int sock, const char* user, const char* passwd);

char* data_safe_get_proxy_magic(char magic[DATA_SAFE_MAGIC_LENGTH+1]);
char* data_safe_get_admin_tool_magic(char magic[DATA_SAFE_MAGIC_LENGTH+1]);
char* data_safe_get_crypto_tool_magic(char magic[DATA_SAFE_MAGIC_LENGTH+1]);

#define STR_ADMIN "admin"
#define STR_APP_PKG "/etc/datasafe/apkg.tar.gz"
#define STR_C_APP_PKG "/tmp/apkg.tar.gz"
#define CHECK_IS_OK(result) (result == RET_OK || result == RET_IS_ADMIN)

#define STR_LEN(str) (((str) != NULL) ? strlen(str) : 0)
#define STR_PACK(buff, str) if(str != NULL) {memcpy(buff, str, strlen(str)+1);} \
	else {buff[0] = '\0';}
#define STR_DUP(str) (str != NULL) ? strdup(str) : strdup("")

#define return_if_fail(p) if(!(p)) {return;};
#define return_val_if_fail(p, v) if(!(p)) {return (v);}

#endif/*DATA_SAFE_COMMON_H*/

