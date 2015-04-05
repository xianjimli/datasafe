/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef _server_h
#define _server_h

#define PASSWORD get_server_passwd()
#define DHFILE   "/etc/datasafe/dh1024.pem"
#define KEYFILE  "/etc/datasafe/server.pem"

int tcp_listen(void);
void load_dh_params(SSL_CTX *ctx,char *file);
void generate_eph_rsa_key(SSL_CTX *ctx);
const char* get_server_passwd(void);

#endif

