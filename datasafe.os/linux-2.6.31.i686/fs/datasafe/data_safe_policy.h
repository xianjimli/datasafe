/**
 * History:
 *  2010-04-15 Li XianJing <xianjimli@hotmail.com> created.
 *
 */

#ifndef DATA_SAFE_POLICY_H
#define DATA_SAFE_POLICY_H

#define DATA_SAFE_READ_DE  1
#define DATA_SAFE_WRITE_EN 2

typedef struct _AppPolicy
{
	char name[260];
	char md5sum[33];
	char header_md5sum[33];
	unsigned int policy;
	unsigned long mtime;
	unsigned long size;
}AppPolicy;

int         data_safe_policy_set_passwd(const char* passwd);
const char* data_safe_policy_get_passwd(void);
int         data_safe_policy_reset(void);
int         data_safe_policy_total(void);
int         data_safe_policy_parse(const char* data);
int         data_safe_policy_add(AppPolicy* policy);
int         data_safe_policy_is_file_changed(AppPolicy* policy);
AppPolicy*  data_safe_policy_get(int index);
AppPolicy*  data_safe_policy_find_by_name(const char* name);
AppPolicy*  data_safe_policy_find_by_md5(const char* md5sum);

#endif/*DATA_SAFE_POLICY_H*/

