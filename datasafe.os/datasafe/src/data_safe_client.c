/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */
#include <assert.h>
#include "common.h"
#include "client.h"
#include <sys/utsname.h>
#include "data_safe_common.h"
#include "data_safe_cmd_proxy.h"
#include "data_safe_stream_ssl.h"
#include "data_safe_crypto.h"

__attribute ((constructor)) void hello_init(void)
{
	data_safe_crack_detect();

	return;
} 

int data_safe_test(DataSafeCmd* proxy, int sock, int argc, char* argv[])
{
	Ret ret = RET_FAIL;
	char* policy = NULL;
	char* passwd = NULL;
	char* filename = NULL;
	DataSafeClientInfo info = {0};
	data_safe_client_info_init(&info, sock, "admin", "12345678");

	ret = data_safe_cmd_check(proxy, &info);
	assert(ret != RET_FAIL);

	ret = data_safe_cmd_get_policy(proxy, &policy);
	if(policy != NULL)
	{
		printf("%s\n", policy);
		free(policy);
	}
	ret = data_safe_cmd_get_passwd(proxy, &passwd);
	if(passwd != NULL)
	{
		free(passwd);
	}

	ret = data_safe_cmd_add_user(proxy, "lixianjing");
	ret = data_safe_cmd_change_passwd(proxy, "lixianjing", "1234abcd");
	ret = data_safe_cmd_delete_user(proxy, "lixianjing");
	ret = data_safe_cmd_get_app_pkg(proxy, &filename);
	free(filename);
	data_safe_cmd_destroy(proxy);

	return 0;
}

int main(int argc, char* argv[])
{
	SSL *ssl = NULL;
	int sock = 0;
	BIO *sbio = NULL;
	SSL_CTX *ctx = NULL;
	char* host = HOST;
	struct utsname info = {0};

	ctx=initialize_ctx(KEYFILE, (char*)PASSWORD);

	printf("%s %s\n", argv[0], STR_VERSION);
	if(getenv("DATASAFE_SERVER") != NULL)
	{
		host = getenv("DATASAFE_SERVER");
	}

	if(uname(&info) != 0)
	{
		printf("No PERMISSION(1).\n");

		return 0;
	}

	if(strcmp(info.release, KERNEL_RELEASE) != 0) 
//		|| strcmp(info.version, KERNEL_VERSION) != 0)
	{
		printf("KERNEL VERSION MISMATCH.\n");

		return 0;
	}

	sock = tcp_connect(host, PORT);
	if(sock < 0)
	{
		printf("Connect to server failed.\n");

		return 0;
	}

	ssl  = SSL_new(ctx);
	sbio = BIO_new_socket(sock,BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);

	if(SSL_connect(ssl)<=0)
	{
		berr_exit("SSL connect error");
	}

	DataSafeStream* stream = data_safe_stream_ssl_create(ssl, sock);
	DataSafeCmd* proxy = data_safe_cmd_proxy_create(stream);

#ifdef DATA_SAFE_PROXY
	data_safe_proxy(proxy, sock, argc, argv);
#elif defined(DATA_SAFE_ADMIN)
	data_safe_admin(proxy, sock, argc, argv);
#elif defined(DATA_SAFE_CRYPTO)
	data_safe_crypto(proxy, sock, argc, argv);
#else
	data_safe_test(proxy, sock, argc, argv);
#endif

	destroy_ctx(ctx);

	return 0;
}

