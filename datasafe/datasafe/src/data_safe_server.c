/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include "common.h"
#include "server.h"
#include <syslog.h>
#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include "data_safe_common.h"
#include "data_safe_cmd_stub.h"
#include "data_safe_stream_ssl.h"
#include "data_safe_policy_db.h"

typedef struct _ThreadCtx
{
	int sock;
	SSL *ssl;
	FILE* log;
	DataSafePolicyDb* db;
}ThreadCtx;

static g_server_thread_nr;
#define SERVER_THREAD_NR 32

static int data_safe_server(void* data)
{
	ThreadCtx* ctx = data;
	
	g_server_thread_nr++;

	DataSafeStream* stream = NULL;
	stream = data_safe_stream_ssl_create(ctx->ssl, ctx->sock);
	data_safe_cmd_loop(stream, ctx->db, ctx->log);
	data_safe_stream_destroy(stream);
	free(ctx);

	g_server_thread_nr--;

	return(0);
}

#ifdef ANTI_DEBUG
#include <sys/ptrace.h>
__attribute ((constructor)) void hello_init(void)
{
	data_safe_crack_detect();

	return;
} 
#endif/*ANTI_DEBUG*/

static int is_allowed_mac(void)
{
	int ret = 0;
	char my[32] = {0};
	char allowed[32] = {0};
	data_safe_get_mac_addr(my);

	allowed[0] = '0';
	allowed[1] = '0';
	allowed[2] = '2';
	allowed[3] = '4';
	allowed[4] = '2';
	allowed[5] = '1';
	allowed[6] = 'F';
	allowed[7] = '1';
	allowed[8] = 'E';
	allowed[9] = 'F';
	allowed[10] = '2';
	allowed[11] = '5';
	allowed[12] = '\0';

	if(strcasecmp(my, allowed) == 0)
	{
		return 1;
	}
	
	allowed[0] = '0';
	allowed[1] = '0';
	allowed[2] = '2';
	allowed[3] = '4';
	allowed[4] = '2';
	allowed[5] = '1';
	allowed[6] = 'F';
	allowed[7] = '1';
	allowed[8] = 'F';
	allowed[9] = '8';
	allowed[10] = '5';
	allowed[11] = '9';
	allowed[12] = '\0';

	if(strcasecmp(my, allowed) == 0)
	{
		return 1;
	}
	
	allowed[0] = '0';
	allowed[1] = '0';
	allowed[2] = '1';
	allowed[3] = 'A';
	allowed[4] = '4';
	allowed[5] = 'D';
	allowed[6] = '8';
	allowed[7] = '5';
	allowed[8] = '9';
	allowed[9] = '5';
	allowed[10] = 'A';
	allowed[11] = 'B';
	allowed[12] = '\0';

	if(strcasecmp(my, allowed) == 0)
	{
		return 1;
	}

	return ret;
}

int main(int argc, char* argv[])
{
	int sock = 0;
	int s = 0;
	FILE* log = NULL;
	BIO *sbio = NULL;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int r = 0;
   	DataSafePolicyDb* db = NULL;
   
	printf("%s %s\n", argv[0], STR_VERSION);
	if(!is_allowed_mac())
	{
		printf("No permission.\n");
		exit(0);
	}

   	if(argc < 2)
   	{
   		printf("Run as a deamon.\n");
   		if(fork() != 0)
   		{
   			exit(0);
   		}
   	}

   	db = data_safe_policy_db_create();
   	data_safe_policy_db_load(db);
	
	log = fopen("/var/log/datasafe"	, "a+");
	if(log != NULL)
	{
		int value = 0;
		r = ioctl(fileno(log), EXT2_IOC_GETFLAGS, &value, sizeof(value));
		value |= EXT2_APPEND_FL;
		r = ioctl(fileno(log), EXT2_IOC_SETFLAGS, &value, sizeof(value));
	}

	ctx=initialize_ctx(KEYFILE,PASSWORD);
	load_dh_params(ctx,DHFILE);
   
	sock=tcp_listen();
	while(1)
	{
		pthread_t tid = 0;
		ThreadCtx* thread_ctx = NULL;

		if(g_server_thread_nr < SERVER_THREAD_NR)
		{
			if((s=accept(sock,0,0))<0)
			{
				printf("Problem accepting");
				continue;
			}

			sbio=BIO_new_socket(s, BIO_NOCLOSE);
			ssl=SSL_new(ctx);
			SSL_set_bio(ssl, sbio, sbio);
			if((r=SSL_accept(ssl)<=0))
			{
				printf("SSL accept error");
				continue;
			}

			thread_ctx = calloc(1, sizeof(ThreadCtx));
			thread_ctx->sock = s;
			thread_ctx->ssl  = ssl;
			thread_ctx->db   = db;
			thread_ctx->log  = log;

			pthread_create(&tid, NULL, data_safe_server, thread_ctx);
			pthread_detach(tid);
		}
		else
		{
			close(s);
		}
	}

	fclose(log);
	data_safe_policy_db_destroy(db);
	destroy_ctx(ctx);

	return 0;
}

