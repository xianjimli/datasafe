/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include "data_safe_common.h"

#define __NR_setxattr 226
#define __NR_getxattr 229
#define SYS_setxattr __NR_setxattr
#define SYS_getxattr __NR_getxattr

int digit_to_hex(const char* in, int len, char* out)
{
    int i = 0;
    char str[3] = {0};

    for (i = 0; i < len; i++)
    {
        unsigned int v = (in[i] >> 4) & 0x0F;
        str[0] = (v >= 0 && v <= 9) ? v + '0' : (v - 10 + 'a');

        v = in[i] & 0x0F;
        str[1] = (v >= 0 && v <= 9) ? v + '0' : (v - 10 + 'a');

        out[i << 1] = str[0];
        out[(i << 1) + 1] = str[1];
    }

    return 0;
}

int data_safe_get_mac_addr(char* addr)
{
	struct ifreq ifr;
	struct ifreq *IFR;
	struct ifconf ifc;
	char buf[1024];
	int s, i;
	int ok = 0;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s==-1) 
	{
		return -1;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	ioctl(s, SIOCGIFCONF, &ifc);

	IFR = ifc.ifc_req;
	for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; IFR++) 
	{
		strcpy(ifr.ifr_name, IFR->ifr_name);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) 
		{
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) 
			{
				if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) 
				{
					ok = 1;
					break;
				}
			}
		}
	}

	close(s);

	if (ok) 
	{	
		unsigned char* src = ifr.ifr_hwaddr.sa_data;
		digit_to_hex(src, 6, addr);
		
		return 0;
	}
	else 
	{
		return -1;
	}
}


Ret data_safe_client_info_init(DataSafeClientInfo* info, int sock, const char* user, const char* passwd)
{
	int uid = getuid();
	struct passwd* pwd = getpwuid(uid);
	unsigned long addr = 0;
	struct sockaddr_in my_addr = {0};
	socklen_t len = sizeof(struct sockaddr_in);
	return_val_if_fail(info != NULL && user != NULL && passwd != NULL, RET_FAIL);

	memset(info, 0x00, sizeof(DataSafeClientInfo));

	data_safe_get_mac_addr(info->mac);
	getsockname(sock, (struct sockaddr*)&my_addr, &len);
	addr = ntohl(my_addr.sin_addr.s_addr);
	snprintf(info->ip, sizeof(info->ip), "%08x", addr);

	strcpy(info->version, STR_VERSION);
	strncpy(info->login_user, pwd->pw_name, DATA_SAFE_USER_LENGTH);
	strncpy(info->user, user, DATA_SAFE_USER_LENGTH);
	strncpy(info->passwd, passwd, DATA_SAFE_PASSWD_LENGTH);

	return RET_OK;
}

static const char* g_filters = NULL;

//export DS_FILE_TYPES=".c;.cpp;.cxx;.java;.h;"
int data_safe_is_crypto_ext(const char* filename)
{
	char  match[260];
	const char* ext = NULL;
	if(filename == NULL) return 0;

	ext = strrchr(filename, '.');
	if(ext == NULL) return 0;

	if(g_filters == NULL)
	{
		g_filters = getenv("DS_FILE_TYPES");
	}

	if(g_filters == NULL)
	{
		g_filters=".c;.cpp;.cxx;.java;.h;";
	}

	match[0] = '\0';
	strcat(match, ext);
	strcat(match, ";");

	return strstr(g_filters, match) != NULL;
}

int data_safe_is_binary(const char* filename)
{
	/*TODO*/	
	return 0;
}

static int setxattr (const char *path, const char *name,
                       const void *value, size_t size, int flags)
{                       
	return syscall(SYS_setxattr, path, name, value, size, flags);
}

static ssize_t getxattr (const char *path, const char *name,
                            void *value, size_t size)
{
	return syscall(SYS_getxattr, path, name, value, size);
}

#define FILE_TAG "user.encrypted"
int data_safe_get_tag(const char* filename)
{
	int value = 0;

	if(getxattr(filename, FILE_TAG, &value, sizeof(value)) < 0)
	{
	}

	return value;
}

Ret data_safe_set_tag(const char* filename, int value)
{
	Ret ret = RET_OK;

	if(setxattr(filename, FILE_TAG, &value, sizeof(value), 0) < 0)
	{
		perror("setxattr");
		ret = RET_FAIL;
	}

	return ret;
}

char* data_safe_read_file(const char* filename, int* length)
{
	struct stat st = {0};
	FILE* fp = NULL;
	char* buffer = NULL;

	if(stat(filename, &st) != 0)
	{
		return NULL;
	}

	fp = fopen(filename, "rb");
	if(fp != NULL)
	{
		buffer = calloc(1, st.st_size+1);
		fread(buffer, 1, st.st_size, fp);
		fclose(fp);
	}

	if(length != NULL)
	{
		*length = st.st_size;
	}

	return buffer;
}

void  data_safe_write_file(const char* filename, char* contents, size_t length)
{
	FILE* fp = NULL;

	return_if_fail(filename != NULL && contents != NULL);

	fp = fopen(filename, "wb+");

	if(fp != NULL)
	{
		fwrite(contents, 1, length, fp);
		fclose(fp);
	}

	return;
}

void data_safe_crack_detect(void)
{
#ifdef ANTI_DEBUG
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) 
	{
		int i = 0;
		for(i = 0; i < 10000; i++)
		{
			printf("XXXXXXXXXXXXXXDONT DO EVILXXXXXXXXXXXXXXXXXXXXX\n");
		}
		_exit(0);
	}
#endif/*ANTI_DEBUG*/

	return;
}

char* data_safe_get_proxy_magic(char magic[DATA_SAFE_MAGIC_LENGTH+1])
{
	magic[0] = 'f';
	magic[1] = '6';
	magic[2] = '6';
	magic[3] = '0';
	magic[4] = '4';
	magic[5] = 'd';
	magic[6] = 'd';
	magic[7] = 'f';
	magic[8] = '7';
	magic[9] = 'b';
	magic[10] = '3';
	magic[11] = 'e';
	magic[12] = 'b';
	magic[13] = '6';
	magic[14] = 'c';
	magic[15] = '8';
	magic[16] = '9';
	magic[17] = '3';
	magic[18] = '7';
	magic[19] = 'a';
	magic[20] = 'f';
	magic[21] = '9';
	magic[22] = '3';
	magic[23] = 'a';
	magic[24] = 'c';
	magic[25] = 'e';
	magic[26] = 'f';
	magic[27] = '7';
	magic[28] = 'd';
	magic[29] = '6';
	magic[30] = '5';
	magic[31] = '1';
	magic[32] = '\0';

	return magic;
}

char* data_safe_get_admin_tool_magic(char magic[DATA_SAFE_MAGIC_LENGTH+1])
{
	magic[0] = 'a';
	magic[1] = '8';
	magic[2] = '6';
	magic[3] = 'e';
	magic[4] = '5';
	magic[5] = '7';
	magic[6] = 'd';
	magic[7] = '5';
	magic[8] = '2';
	magic[9] = '1';
	magic[10] = 'b';
	magic[11] = 'e';
	magic[12] = '3';
	magic[13] = '3';
	magic[14] = '8';
	magic[15] = '0';
	magic[16] = '0';
	magic[17] = 'a';
	magic[18] = 'e';
	magic[19] = '4';
	magic[20] = '0';
	magic[21] = '4';
	magic[22] = 'c';
	magic[23] = 'd';
	magic[24] = '5';
	magic[25] = '6';
	magic[26] = '9';
	magic[27] = '8';
	magic[28] = 'e';
	magic[29] = '3';
	magic[30] = 'f';
	magic[31] = 'f';
	magic[32] = '\0';

	return magic;
}

char* data_safe_get_crypto_tool_magic(char magic[DATA_SAFE_MAGIC_LENGTH+1])
{
	magic[0] = '2';
	magic[1] = 'c';
	magic[2] = 'a';
	magic[3] = '6';
	magic[4] = '3';
	magic[5] = '1';
	magic[6] = '6';
	magic[7] = '8';
	magic[8] = '0';
	magic[9] = 'e';
	magic[10] = '9';
	magic[11] = '3';
	magic[12] = 'f';
	magic[13] = 'c';
	magic[14] = '7';
	magic[15] = '9';
	magic[16] = 'c';
	magic[17] = '5';
	magic[18] = 'c';
	magic[19] = 'd';
	magic[20] = '3';
	magic[21] = 'a';
	magic[22] = '9';
	magic[23] = 'f';
	magic[24] = 'a';
	magic[25] = '3';
	magic[26] = '9';
	magic[27] = '5';
	magic[28] = '2';
	magic[29] = 'e';
	magic[30] = '0';
	magic[31] = 'd';
	magic[32] = '\0';

	return magic;
}


