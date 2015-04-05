#ifndef DATA_SAFE_H
#define DATA_SAFE_H

#define DATA_SAFE_DEBUG 0

int data_safe_on_exec(const char* filename);

int md5sum_file(const char *filename, char digits[33]);
int md5sum_filp(struct file* filp, size_t max_len, char digits[33]);
int md5sum_file_len(const char *filename, size_t max_len, char digits[33]);
int data_safe_encrypt(u8 *out, const u8 *in, size_t blk_size, size_t blk_nr, const char* key);
int data_safe_decrypt(u8 *out, const u8 *in, size_t blk_size, size_t blk_nr, const char* key);

int  data_safe_is_normal_file(struct file* file);
void data_safe_load_encrypt_flags(struct file* file);
void data_safe_save_encrypt_flags(struct file* file);
int  file_need_decrypt(struct file* file);
int  file_need_encrypt(struct file* file);

int sys_read_normal(struct file *file, char __user * buf, size_t count);
int sys_read_decrypt(struct file *file, char __user * buf, size_t count);
int sys_write_normal(struct file *file, const char __user * buf, size_t count);
int sys_write_encrypt(struct file *file, const char __user * buf, size_t count);

#endif/*DATA_SAFE_H*/

