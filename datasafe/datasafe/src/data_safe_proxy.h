/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_PROXY_H
#define DATA_SAFE_PROXY_H

#include "data_safe_cmd.h"

int data_safe_proxy(DataSafeCmd* proxy, int sock, int argc, char* argv[]);

#endif/*DATA_SAFE_PROXY_H*/

