/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "data_safe_common.h"
#include "data_safe_encrypted_file.h"

static void data_safe_encrypt(char* buffer, size_t length)
{
	/*TODO*/
	return;
}

static void data_safe_decrypt(char* buffer, size_t length)
{
	/*TODO*/
	return;
}

char* data_safe_read_encrypted_file(const char* filename)
{
	return data_safe_read_file(filename);
}

void  data_safe_write_encrypted_file(const char* filename, char* contents)
{
	return data_safe_write_file(filename, contents);
}

#ifdef DATA_SAFE_ENCRYTED_TEST
#include <assert.h>
#define BUFF_SIZE 10 * 1024
int main(int argc, char* argv[])
{
	char in[BUFF_SIZE + 1];
	char* out = NULL;
	memset(in, 'a', BUFF_SIZE);
	in[BUFF_SIZE] = '\0';

	data_safe_write_file("./test.bin", in);
	out = data_safe_read_file("./test.bin");

	assert(strcmp(in, out) == 0);
	free(out);

	return 0;
}
#endif
