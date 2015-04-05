/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef _client_h
#define _client_h

const char* get_client_passwd(void);
#define PASSWORD get_client_passwd()
#define KEYFILE "/etc/datasafe/client.pem"

int  tcp_connect(char *host,int port);
void check_cert(SSL *ssl,char *host);

#endif

