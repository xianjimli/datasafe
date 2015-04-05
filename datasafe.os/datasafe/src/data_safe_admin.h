/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_ADMIN_H
#define DATA_SAFE_ADMIN_H

#include "data_safe_cmd.h"

int data_safe_admin(DataSafeCmd* proxy, int sock, int argc, char* argv[]);

#endif/*DATA_SAFE_ADMIN_H*/

