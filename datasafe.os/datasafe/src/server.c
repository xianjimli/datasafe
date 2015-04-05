/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include "common.h"
#include "server.h"

int tcp_listen()
  {
    int sock;
    struct sockaddr_in sin;
    int val=1;
    
    if((sock=socket(AF_INET,SOCK_STREAM,0))<0)
      err_exit("Couldn't make socket");
    
    memset(&sin,0,sizeof(sin));
    sin.sin_addr.s_addr=INADDR_ANY;
    sin.sin_family=AF_INET;
    sin.sin_port=htons(PORT);
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,
      &val,sizeof(val));
    
    if(bind(sock,(struct sockaddr *)&sin,
      sizeof(sin))<0)
      berr_exit("Couldn't bind");
    listen(sock,5);  

	printf("listen on %s %d\n", HOST, PORT);
    return(sock);
  }

void load_dh_params(ctx,file)
  SSL_CTX *ctx;
  char *file;
  {
    DH *ret=0;
    BIO *bio;

    if ((bio=BIO_new_file(file,"r")) == NULL)
      berr_exit("Couldn't open DH file");

    ret=PEM_read_bio_DHparams(bio,NULL,NULL,
      NULL);
    BIO_free(bio);
    if(SSL_CTX_set_tmp_dh(ctx,ret)<0)
      berr_exit("Couldn't set DH parameters");
  }

void generate_eph_rsa_key(ctx)
  SSL_CTX *ctx;
  {
    RSA *rsa;

    rsa=RSA_generate_key(512,RSA_F4,NULL,NULL);
    
    if (!SSL_CTX_set_tmp_rsa(ctx,rsa))
      berr_exit("Couldn't set RSA key");

    RSA_free(rsa);
  }
    
  
const char* get_server_passwd(void)
{
	static char passwd[32] = {0};

	passwd[0] = 'b';
	passwd[1] = 'r';
	passwd[2] = 'n';
	passwd[3] = 'S';
	passwd[4] = 'E';
	passwd[5] = 'R';
	passwd[6] = 'V';
	passwd[7] = 'E';
	passwd[8] = 'R';
	passwd[9] = '\0';

	return passwd;
}

