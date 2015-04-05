/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#include "data_safe_cmd.h"
#include "data_safe_stream.h"
#include "data_safe_policy_db.h"

#ifndef DATA_SAFE_CMD_STUB_H
#define DATA_SAFE_CMD_STUB_H

Ret data_safe_cmd_loop(DataSafeStream* stream, DataSafePolicyDb* db, FILE* log);

#endif/*DATA_SAFE_CMD_STUB_H*/


