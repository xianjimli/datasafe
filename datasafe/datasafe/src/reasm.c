#include <stdio.h>

int main(int argc, char* argv[])
{
	int i = 0;
	const char* name = argv[1];
	const char* value = argv[2];

	if(name == NULL || value == NULL)
	{
		printf("usage: %s name value\n", argv[0]);

		return 0;
	}

	for(i = 0; value[i]; i++)
	{
		printf("%s[%d] = \'%c\';\n", name, i, value[i]);
	}
	printf("%s[%d] = \'\\0\';\n", name, i);

	return 0;
}
