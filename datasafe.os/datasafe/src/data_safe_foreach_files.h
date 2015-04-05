/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_FOREACH_FILES_H
#define DATA_SAFE_FOREACH_FILES_H

#include "data_safe_common.h"

typedef Ret (*VisitFile)(const char* filename, void* ctx);
Ret data_safe_foreach_file(const char* path, VisitFile visit, void* ctx);

#endif/*DATA_SAFE_FOREACH_FILES_H*/

