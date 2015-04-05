/**
 * History:
 *  2010-04-15 Li XianJing <xianjimli@hotmail.com> created.
 *
 */

#ifndef POLICY_DEV_H
#define POLICY_DEV_H

#include <linux/ioctl.h>

#define POLICY_BUFFER_LEN 8092
#define DATA_SAFE_MAGIC_LENGTH  32
#define DATA_SAFE_MAX_USERS     32
#define DATA_SAFE_USER_LENGTH   32
#define DATA_SAFE_PASSWD_LENGTH 32

#define MAJOR_NUM   200
#define DEVICE_NAME "policy"

typedef struct _DataSafePolicyInfo
{
	char magic[DATA_SAFE_MAGIC_LENGTH + 1];
	char passwd[DATA_SAFE_PASSWD_LENGTH+1];
	char policy[POLICY_BUFFER_LEN+1];
}DataSafePolicyInfo;

#define IOCTL_RESET          _IOWR(MAJOR_NUM, 0, char *)

static inline char* data_safe_get_trans_passwd(char passwd[DATA_SAFE_PASSWD_LENGTH+1])
{
	passwd[0] = 'P';
	passwd[1] = '!';
	passwd[2] = '#';
	passwd[3] = 'D';
	passwd[4] = 'F';
	passwd[5] = 'E';
	passwd[6] = 'F';
	passwd[7] = 'V';
	passwd[8] = 'q';
	passwd[9] = 'k';
	passwd[10] = 'a';
	passwd[11] = 'e';
	passwd[12] = 't';
	passwd[13] = 'y';
	passwd[14] = 'n';
	passwd[15] = '.';
	passwd[16] = '>';
	passwd[17] = '<';
	passwd[18] = '?';
	passwd[19] = 'V';
	passwd[20] = '\0';
	
	return passwd;
}
#endif

