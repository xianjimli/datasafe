/**
 * Date  : 2010/4/10
 * Author: LiXianJing <lixianjing@broncho.cn>
 *
 */

#ifndef AUTH_BLOW_FISH_H
#define AUTH_BLOW_FISH_H

int data_safe_encrypt_buff(char *in, int len, const char* passwd);
int data_safe_decrypt_buff(char *in, int len, const char* passwd);
int data_safe_encrypt_file(const char* filename, const char* passwd);
int data_safe_decrypt_file(const char* filename, const char* passwd);

#endif/*AUTH_BLOW_FISH_H*/

