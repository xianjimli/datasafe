/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <openssl/blowfish.h>
#include "data_safe_common.h"

#define ENC_KEY_SIZE 16

static int blowfish_init_key(BF_KEY* key, const char* passwd)
{
	char real_passwd[33] = {0};
	char* md5 = MD5(passwd, strlen(passwd), NULL);
	
	digit_to_hex(md5, 16, real_passwd);
	BF_set_key(key, strlen(real_passwd), real_passwd);

   return 0;
}

int data_safe_encrypt_buff(char *in, int len, const char* passwd)
{ 
	int i = 0;
	BF_KEY key;
	int size = (len >> 3) << 3;

	blowfish_init_key(&key, passwd);
	for (i = 0; i < size; i += 8)
	{
		BF_ecb_encrypt(in+i, in+i, &key, BF_ENCRYPT);
	}
	
	return len;
}

int data_safe_decrypt_buff(char *in, int len, const char* passwd)
{
	int i = 0;
	BF_KEY key;
	int size = (len >> 3) << 3;

	blowfish_init_key(&key, passwd);
	for (i = 0; i < size; i += 8)
	{
		BF_ecb_encrypt(in+i, in+i, &key, BF_DECRYPT);
	}
	
	return len;
}

static int data_safe_en_de_crypt_file(const char* filename, const char* passwd, int en)
{
	int fd = 0;
	char* addr = NULL;
	char* copy = NULL;
	struct stat st = {0};
	return_val_if_fail(filename != NULL && passwd != NULL, 0);
	if(stat(filename, &st) != 0 || st.st_size < 8) return 0;

	fd = open(filename, O_RDWR);
	if(fd < 0)
	{
		printf("open %s failed.\n", filename);

		return 0;
	}

	addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	copy = calloc(1, st.st_size + 1);
	if(copy != NULL && addr != NULL)
	{
		memcpy(copy, addr, st.st_size);
		if(en)
		{
			data_safe_encrypt_buff(copy, st.st_size, passwd);
		}
		else
		{
			data_safe_decrypt_buff(copy, st.st_size, passwd);
		}
	}
	munmap(addr, st.st_size);
	lseek(fd, 0, SEEK_SET);
	close(fd);

	fd = open(filename, O_RDWR);
	if(copy != NULL)
	{
		int ret = write(fd, copy, st.st_size);
		assert(ret == st.st_size);
	}
	close(fd);

	return 0;
}

int data_safe_encrypt_file(const char* filename, const char* passwd)
{
	return data_safe_en_de_crypt_file(filename, passwd, 1);
}

int data_safe_decrypt_file(const char* filename, const char* passwd)
{
	return data_safe_en_de_crypt_file(filename, passwd, 0);
}

#ifdef BLOWFISH_TEST
#include <assert.h>
#define SIZE 10*1024+5
#define BUFF_SIZE 4096

void test(void)
{
	char in[SIZE+1] = {0};
	char expected[SIZE+1] = {0};
	memset(in, 'a', SIZE);
	memset(expected, 'a', SIZE);

	data_safe_encrypt_buff(in, SIZE, "1234abcd");
	assert(memcmp(in, expected, SIZE) != 0);

	data_safe_decrypt_buff(in, SIZE, "1234abcd");
	assert(memcmp(in, expected, SIZE) == 0);

	return;
}

int main(int argc, char* argv[])
{
	const char* action = NULL;
	const char* passwd = NULL;
	const char* filename = NULL;

	if(argc < 4)
	{
		test();
		printf("usage: %s dec|enc passwd file\n", argv[0]);

		return 0;
	}

	action   = argv[1];
	passwd   = argv[2];
	filename = argv[3];

	if(action[0] == 'e')
	{
		data_safe_encrypt_file(filename, passwd);		
	}
	else
	{
		data_safe_decrypt_file(filename, passwd);		
	}

	return 0;
}
#endif/*BLOWFISH_TEST*/

