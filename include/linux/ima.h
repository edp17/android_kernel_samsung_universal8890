/*
 * Copyright (C) 2008 IBM Corporation
 * Author: Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#ifndef _LINUX_IMA_H
#define _LINUX_IMA_H

#include <linux/fs.h>
#include <linux/integrity.h>
#include <linux/key.h>

struct linux_binprm;

#ifdef CONFIG_IMA
extern int ima_bprm_check(struct linux_binprm *bprm);
extern int ima_file_check(struct file *file, int mask, int opened);
extern void ima_file_free(struct file *file);
extern int ima_file_mmap(struct file *file, unsigned long prot);
extern int ima_module_check(struct file *file);
extern bool ima_memlock_file(char *sig, unsigned int siglen);
extern int ima_file_signature_alloc(struct file *file, char **sig);
extern int ima_signature_type(char *sig);
extern int ima_fw_from_file(struct file *file, char *buf, size_t size);

#else
static inline int ima_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}

static inline int ima_file_check(struct file *file, int mask, int opened)
{
	return 0;
}

static inline void ima_file_free(struct file *file)
{
	return;
}

static inline int ima_file_mmap(struct file *file, unsigned long prot)
{
	return 0;
}

static inline int ima_module_check(struct file *file)
{
	return 0;
}

static inline int ima_fw_from_file(struct file *file, char *buf, size_t size)
{
	return 0;
}

static inline bool ima_memlock_file(char *sig, unsigned int siglen)
{
	return false;
}

 
static inline int ima_file_signature_alloc(struct file *file, char **sig)
{
	return -EOPNOTSUPP;
}

static inline int ima_signature_type(char *sig)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_IMA */

#ifdef CONFIG_IMA_APPRAISE
extern void ima_inode_post_setattr(struct dentry *dentry);
extern int ima_inode_setxattr(struct dentry *dentry, const char *xattr_name,
		       const void *xattr_value, size_t xattr_value_len);
extern int ima_inode_removexattr(struct dentry *dentry, const char *xattr_name);
extern int ima_appraise_file_digsig(struct key *keyring, struct file *file, char *sig, unsigned int siglen);
#else
static inline void ima_inode_post_setattr(struct dentry *dentry)
{
	return;
}

static inline int ima_inode_setxattr(struct dentry *dentry,
				     const char *xattr_name,
				     const void *xattr_value,
				     size_t xattr_value_len)
{
	return 0;
}

static inline int ima_inode_removexattr(struct dentry *dentry,
					const char *xattr_name)
{
	return 0;
}
static inline int ima_appraise_file_digsig(struct key *keyring, struct file *file, char *sig, unsigned int siglen)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_IMA_APPRAISE */
#endif /* _LINUX_IMA_H */
