bin_PROGRAMS=datasafe_service datasafe_proxy datasafe_admin datasafe_decrypt datasafe_tags datasafe_encrypt datasafe_has_attr
noinst_PROGRAMS=encrypted_test foreach_files_test datasafe_test data_safe_crypto_algo_test data_safe_policy_db_test reasm

LIBS= libssl.a libcrypto.a  libexpat.a -lpthread -ldl -lm -lc

KERNEL_PATH=$(top_srcdir)/../linux-2.6.31.i686/
INCLUDES=-I$(KERNEL_PATH)/fs/datasafe

reasm_SOURCES=reasm.c

datasafe_has_attr_SOURCES=data_safe_has_attr.c data_safe_crypto_algo.c data_safe_common.c
datasafe_has_attr_LDFLAGS=$(LIBS)

data_safe_policy_db_test_SOURCES=data_safe_policy_db.c data_safe_crypto_algo.c data_safe_common.c 
data_safe_policy_db_test_LDFLAGS=$(LIBS)
data_safe_policy_db_test_CFLAGS=-DDATA_SAFE_POLICY_DB_TEST

data_safe_crypto_algo_test_SOURCES=data_safe_crypto_algo.c data_safe_common.c
data_safe_crypto_algo_test_CFLAGS=-DBLOWFISH_TEST
data_safe_crypto_algo_test_LDFLAGS=$(LIBS)

foreach_files_test_SOURCES=data_safe_common.c data_safe_foreach_files.c
foreach_files_test_LDFLAGS=$(LIBS)
foreach_files_test_CFLAGS=-DFOREACH_FILES_TEST

encrypted_test_SOURCES=data_safe_crypto_algo.c data_safe_common.c
encrypted_test_CFLAGS=-DBLOWFISH_TEST
encrypted_test_LDFLAGS=$(LIBS)

datasafe_tags_SOURCES=data_safe_common.c data_safe_foreach_files.c data_safe_tags.c
datasafe_tags_LDFLAGS=$(LIBS)

datasafe_service_SOURCES=server.c \
	data_safe_server.c \
	data_safe_policy_db.c \
	data_safe_stream_ssl.c \
	data_safe_cmd_stub.c \
	data_safe_cmd_local.c \
	data_safe_crypto_algo.c \
	common.c \
	data_safe_common.c 

datasafe_service_LDFLAGS=$(LIBS)

CLIENT_SRC=data_safe_client.c \
	client.c \
	data_safe_cmd_proxy.c \
	data_safe_stream_ssl.c \
	common.c \
	data_safe_crypto_algo.c \
	data_safe_common.c \
	data_safe_policy_lib.c \
	data_safe_foreach_files.c

datasafe_proxy_SOURCES=$(CLIENT_SRC) data_safe_proxy.c
datasafe_proxy_LDFLAGS=$(LIBS)
datasafe_proxy_CFLAGS=-DDATA_SAFE_PROXY

datasafe_admin_SOURCES=$(CLIENT_SRC) data_safe_admin.c
datasafe_admin_LDFLAGS=$(LIBS)
datasafe_admin_CFLAGS=-DDATA_SAFE_ADMIN

datasafe_decrypt_SOURCES=$(CLIENT_SRC) data_safe_crypto.c
datasafe_decrypt_LDFLAGS=$(LIBS)
datasafe_decrypt_CFLAGS=-DDATA_SAFE_CRYPTO

datasafe_encrypt_SOURCES=$(CLIENT_SRC) data_safe_crypto.c
datasafe_encrypt_LDFLAGS=$(LIBS)
datasafe_encrypt_CFLAGS=-DDATA_SAFE_CRYPTO -DDATA_SAFE_ENCRYPT

datasafe_test_SOURCES=$(CLIENT_SRC)
datasafe_test_LDFLAGS=$(LIBS)
datasafe_test_CFLAGS=-DDATA_SAFE_TEST

EXTRA_DIST=client.pem  dh1024.pem  root.pem  server.pem \
	libcrypto.a  libexpat.a  libssl.a stress.sh gen_policy.sh gen_apkg.sh files.lst dsfiles.lst osfiles.lst \
	data_safe_crypto_algo.h         data_safe_cmd.h        data_safe_common.h \
	data_safe_policy_db.h   data_safe_stream_ssl.h \
	client.h           data_safe_cmd_local.h  data_safe_crypto.h \
	data_safe_policy_lib.h  server.h \
	common.h           data_safe_cmd_proxy.h  data_safe_encrypted_file.h  data_safe_proxy.h \
	data_safe_admin.h  data_safe_cmd_stub.h   data_safe_foreach_files.h   data_safe_stream.h

