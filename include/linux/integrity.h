/*
 * Copyright (C) 2009 IBM Corporation
 * Author: Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#ifndef _LINUX_INTEGRITY_H
#define _LINUX_INTEGRITY_H

#include <linux/fs.h>
#include <linux/key.h>

enum integrity_status {
	INTEGRITY_PASS = 0,
	INTEGRITY_FAIL,
	INTEGRITY_NOLABEL,
	INTEGRITY_NOXATTRS,
	INTEGRITY_UNKNOWN,
};


enum evm_ima_xattr_type {
	IMA_XATTR_DIGEST = 0x01,
	EVM_XATTR_HMAC,
	EVM_IMA_XATTR_DIGSIG,
	IMA_XATTR_DIGEST_NG,
	EVM_XATTR_PORTABLE_DIGSIG,
	IMA_XATTR_LAST
};
/* List of EVM protected security xattrs */
#ifdef CONFIG_INTEGRITY
extern struct integrity_iint_cache *integrity_inode_get(struct inode *inode);
extern void integrity_inode_free(struct inode *inode);

#else
static inline struct integrity_iint_cache *
				integrity_inode_get(struct inode *inode)
{
	return NULL;
}

static inline void integrity_inode_free(struct inode *inode)
{
	return;
}
#endif /* CONFIG_INTEGRITY */


#ifdef CONFIG_INTEGRITY_SIGNATURE
extern int integrity_verify_user_buffer_digsig(struct key *keyring,
				const char __user *data,
				unsigned long data_len,
				char *sig, unsigned int siglen);
#else
static inline int integrity_verify_user_buffer_digsig(struct key *keyring,
				const char __user *data,
				unsigned long data_len,
				char *sig, unsigned int siglen)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_INTEGRITY_SIGNATURE */


#endif /* _LINUX_INTEGRITY_H */
