/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_POLICY_LIB_H
#define DATA_SAFE_POLICY_LIB_H 

#include "data_safe_common.h"

Ret  data_safe_policy_open(void);
Ret  data_safe_policy_set_passwd(const char* passwd);
Ret  data_safe_policy_add(const char* name, const char* md5sum, int r_de, int w_en);
Ret  data_safe_policy_set_policy(const char* policy);
Ret  data_safe_policy_flush(void);
void data_safe_policy_close(void);

#endif/*DATA_SAFE_POLICY_LIB_H*/


