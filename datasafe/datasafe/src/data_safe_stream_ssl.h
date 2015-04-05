/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_STREAM_SSL_H
#define DATA_SAFE_STREAM_SSL_H

#include "data_safe_stream.h"
#include <openssl/ssl.h>

DataSafeStream* data_safe_stream_ssl_create(SSL* ssl, int sock);

#endif/*DATA_SAFE_STREAM_SSL_H*/

