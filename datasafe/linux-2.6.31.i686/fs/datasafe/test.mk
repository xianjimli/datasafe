all:
	gcc -g data_safe_policy_lib.c -DTEST -o policy_lib_test
	gcc -g data_safe_policy.c -DTEST -o policy_test

clean:
	rm -f *_test
