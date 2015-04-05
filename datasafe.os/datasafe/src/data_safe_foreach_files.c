/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "data_safe_foreach_files.h"

Ret data_safe_foreach_file(const char* path, VisitFile visit, void* ctx)
{
	DIR* dir = NULL;
	char* ignore = NULL;
	struct stat st = {0};
	char filename[260] = {0};
	return_val_if_fail(path != NULL && visit != NULL, RET_FAIL);

	if(stat(path, &st) != 0)
	{
		printf("%s: %s not exist.\n", __func__, path);

		return RET_FAIL;
	}

	if(S_ISDIR(st.st_mode))
	{
		dir = opendir(path);
		if(dir != NULL)
		{
			char* p = NULL;
			struct dirent* iter = NULL;
			snprintf(filename, sizeof(filename), "%s/%s", path, "ds.ignore");
			if(stat(path, &st) == 0 && getenv("NO_DS_IGNORE") == NULL)
			{
				FILE* fp = fopen(filename, "r");
				if(fp != NULL)
				{
					ignore = malloc(st.st_size + 1);
					fread(ignore, 1, st.st_size, fp);
					ignore[st.st_size] = '\0';
					fclose(fp);
				}
			}

			while((iter = readdir(dir)) != NULL)
			{
				if(iter->d_name[0] == '.') continue;
				
				snprintf(filename, sizeof(filename), "%s/%s", path, iter->d_name);

				if(ignore != NULL && (p = strstr(ignore, iter->d_name)) != NULL)
				{
					if(p == ignore || isspace(p[-1]))
					{
						p += strlen(iter->d_name);
						if(*p == '\0' || isspace(*p))
						{
							printf("ignore %s\n", filename);
							continue;
						}
					}
				}

				if(DT_DIR & iter->d_type)
				{
					data_safe_foreach_file(filename, visit, ctx);
				}
				else if(DT_REG & iter->d_type)
				{
					if(data_safe_is_crypto_ext(filename))
					{
						visit(filename, ctx);
					}
				}
			}
			closedir(dir);

			if(ignore != NULL)
			{
				free(ignore);
				ignore = NULL;
			}
		}
	}
	else if(S_ISREG(st.st_mode))
	{
		if(data_safe_is_crypto_ext(path))
		{
			visit(path, ctx);
		}
	}

	return RET_OK;
}

#ifdef FOREACH_FILES_TEST
static Ret print(const char* filename, void* ctx)
{
	int* count = ctx;
	*count = *count + 1;

	printf("%s \n", filename);

	return;
}

int main(int argc, char* argv[])
{
	int count = 0;
	data_safe_foreach_file(".", print, &count);

	return 0;
}
#endif/*FOREACH_FILES_TEST*/

