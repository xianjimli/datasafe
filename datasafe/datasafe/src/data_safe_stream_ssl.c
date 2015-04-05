/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include "common.h"
#include "data_safe_stream_ssl.h"

typedef struct _PrivInfo
{
	SSL *ssl;
	int sock;
}PrivInfo;

static int  data_safe_stream_ssl_read(DataSafeStream* thiz, void* buffer, size_t len)
{
	int ret = 0;
	char passwd[DATA_SAFE_PASSWD_LENGTH] = {0};
	PrivInfo* priv = (PrivInfo*)thiz->priv;

	ret = SSL_read(priv->ssl, buffer, len);
	if(ret > 0)
	{
		data_safe_decrypt_buff((char*)buffer, ret, data_safe_get_trans_passwd(passwd));
	}

	return ret;
}

static int  data_safe_stream_ssl_write(DataSafeStream* thiz, const void* buffer, size_t len)
{
	int ret = 0;
	char passwd[DATA_SAFE_PASSWD_LENGTH] = {0};
	PrivInfo* priv = (PrivInfo*)thiz->priv;

	data_safe_encrypt_buff((char*)buffer, len, data_safe_get_trans_passwd(passwd));

	ret = SSL_write(priv->ssl, buffer, len);

	return ret;
}

static void data_safe_stream_ssl_destroy(DataSafeStream* thiz)
{
	PrivInfo* priv = (PrivInfo*)thiz->priv;
	
	SSL_shutdown(priv->ssl);
    SSL_free(priv->ssl);
    close(priv->sock);
	free(thiz);

	return;
}

DataSafeStream* data_safe_stream_ssl_create(SSL* ssl, int sock)
{
	DataSafeStream* thiz = NULL;
	
	return_val_if_fail(ssl != NULL, NULL);
	thiz = calloc(1, sizeof(DataSafeStream) + sizeof(PrivInfo));

	if(thiz != NULL)
	{
		PrivInfo* priv = (PrivInfo*)thiz->priv;

		thiz->read    = data_safe_stream_ssl_read;
		thiz->write   = data_safe_stream_ssl_write;
		thiz->destroy = data_safe_stream_ssl_destroy;

		priv->ssl = ssl;
		priv->sock = sock;
	}

	return thiz;
}

#ifdef DATA_SAFE_STREAM_SSL_TEST
int main(int argc, char* argv[])
{
	return 0;
}
#endif/*DATA_SAFE_STREAM_SSL_TEST*/

