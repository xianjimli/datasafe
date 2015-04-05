#include "data_safe_common.h"

int main(int argc, char* argv[])
{
	if(argc == 2)
	{
		return data_safe_get_tag(argv[1]);
	}

	return 0;
}
