/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_STREAM_H
#define DATA_SAFE_STREAM_H

#include "data_safe_common.h"

struct _DataSafeStream;
typedef struct _DataSafeStream DataSafeStream;

typedef int  (*DataSafeStreamRead)(DataSafeStream* thiz, void* buffer, size_t len);
typedef int  (*DataSafeStreamWrite)(DataSafeStream* thiz, const void* buffer, size_t len);
typedef void (*DataSafeStreamDestroy)(DataSafeStream* thiz);

struct _DataSafeStream
{
	DataSafeStreamRead    read;
	DataSafeStreamWrite   write;
	DataSafeStreamDestroy destroy;

	char priv[0];
};

static inline  int  data_safe_stream_read(DataSafeStream* thiz, void* buffer, size_t len)
{
	return_val_if_fail(thiz != NULL && thiz->read != NULL && buffer != NULL, -1);

	return thiz->read(thiz, buffer, len);
}

static inline  int  data_safe_stream_write(DataSafeStream* thiz, const void* buffer, size_t len)
{
	return_val_if_fail(thiz != NULL && thiz->write != NULL && buffer != NULL, -1);

	return thiz->write(thiz, buffer, len);
}

static inline  void data_safe_stream_destroy(DataSafeStream* thiz)
{
	if(thiz != NULL && thiz->destroy != NULL)
	{
		thiz->destroy(thiz);
	}

	return;
}

#endif/*DATA_SAFE_STREAM_H*/

