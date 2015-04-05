/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef DATA_SAFE_ENCRYPTED_FILE_H
#define DATA_SAFE_ENCRYPTED_FILE_H

#include "data_safe_common.h"

char* data_safe_read_encrypted_file(const char* filename);
void  data_safe_write_encrypted_file(const char* filename, char* contents);

#endif/*DATA_SAFE_ENCRYPTED_FILE_H*/

