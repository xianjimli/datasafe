/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include "data_safe_foreach_files.h"


enum _TagAction
{
	TAG_A_UNSET = 0,
	TAG_A_SHOW,
	TAG_A_SET
};

static Ret tag(const char* filename, void* ctx)
{
	int action = (int)ctx;
	switch(action)
	{
		case TAG_A_SET:
		{
			data_safe_set_tag(filename, 1);
			break;
		}
		case TAG_A_UNSET:
		{
			data_safe_set_tag(filename, 0);
			break;
		}
		default:
		{
			int tag = data_safe_get_tag(filename);
			printf("[%d] %s\n", tag, filename);
			break;
		}
	}
	return RET_OK;
}

int main(int argc, char* argv[])
{
	int action = 0;
	if(argc < 3)
	{
		printf("Usage(%s): %s set|show|unset path|file\n", STR_VERSION, argv[0]);
		printf(" example: %s set   test.c\n", argv[0]);
		printf(" example: %s show  test.c\n", argv[0]);
		printf(" example: %s unset test.c\n", argv[0]);
		printf(" example: %s set   /broncho/cupcake\n", argv[0]);

		return 0;
	}

	if(strcmp(argv[1], "set") == 0)
	{
		action = TAG_A_SET;
	}
	else if(strcmp(argv[1], "unset") == 0)
	{
		action = TAG_A_UNSET;
	}
	else
	{
		action = TAG_A_SHOW;
	}

	data_safe_foreach_file(argv[2], tag, (void*)action);
	
	return 0;
}

