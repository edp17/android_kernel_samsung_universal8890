/*
 * Copyright (C) 2011 IBM Corporation
 *
 * Author:
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/magic.h>
#include <linux/ima.h>
#include <linux/evm.h>
#include <crypto/public_key.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>

#include "ima.h"

static int __init default_appraise_setup(char *str)
{
	if (strncmp(str, "off", 3) == 0)
		ima_appraise = 0;
	else if (strncmp(str, "log", 3) == 0)
		ima_appraise = IMA_APPRAISE_LOG;
	else if (strncmp(str, "fix", 3) == 0)
		ima_appraise = IMA_APPRAISE_FIX;
	return 1;
}

__setup("ima_appraise=", default_appraise_setup);

/*
 * ima_must_appraise - set appraise flag
 *
 * Return 1 to appraise
 */
int ima_must_appraise(struct inode *inode, int mask, enum ima_hooks func)
{
	if (!ima_appraise)
		return 0;

	return ima_match_policy(inode, func, mask, IMA_APPRAISE);
}

static int ima_fix_xattr(struct dentry *dentry,
			 struct integrity_iint_cache *iint)
{
	int rc, offset;
	u8 algo = iint->ima_hash->algo;

	if (algo <= HASH_ALGO_SHA1) {
		offset = 1;
		iint->ima_hash->xattr.sha1.type = IMA_XATTR_DIGEST;
	} else {
		offset = 0;
		iint->ima_hash->xattr.ng.type = IMA_XATTR_DIGEST_NG;
		iint->ima_hash->xattr.ng.algo = algo;
	}
	rc = __vfs_setxattr_noperm(dentry, XATTR_NAME_IMA,
				   &iint->ima_hash->xattr.data[offset],
				   (sizeof(iint->ima_hash->xattr) - offset) +
				   iint->ima_hash->length, 0);
	return rc;
}

/* Return specific func appraised cached result */
enum integrity_status ima_get_cache_status(struct integrity_iint_cache *iint,
					   int func)
{
	switch (func) {
	case MMAP_CHECK:
		return iint->ima_mmap_status;
	case BPRM_CHECK:
		return iint->ima_bprm_status;
	case MODULE_CHECK:
		return iint->ima_module_status;
	case FIRMWARE_CHECK:
		return iint->ima_firmware_status;
	case FILE_CHECK:
	default:
		return iint->ima_file_status;
	}
}

static void ima_set_cache_status(struct integrity_iint_cache *iint,
				 int func, enum integrity_status status)
{
	switch (func) {
	case MMAP_CHECK:
		iint->ima_mmap_status = status;
		break;
	case BPRM_CHECK:
		iint->ima_bprm_status = status;
		break;
	case MODULE_CHECK:
		iint->ima_module_status = status;
		break;
	case FIRMWARE_CHECK:
		iint->ima_firmware_status = status;
		break;
	case FILE_CHECK:
	default:
		iint->ima_file_status = status;
		break;
	}
}

static void ima_cache_flags(struct integrity_iint_cache *iint, int func)
{
	switch (func) {
	case MMAP_CHECK:
		iint->flags |= (IMA_MMAP_APPRAISED | IMA_APPRAISED);
		break;
	case BPRM_CHECK:
		iint->flags |= (IMA_BPRM_APPRAISED | IMA_APPRAISED);
		break;
	case MODULE_CHECK:
		iint->flags |= (IMA_MODULE_APPRAISED | IMA_APPRAISED);
		break;
	case FIRMWARE_CHECK:
		iint->flags |= (IMA_FIRMWARE_APPRAISED | IMA_APPRAISED);
		break;
	case FILE_CHECK:
	default:
		iint->flags |= (IMA_FILE_APPRAISED | IMA_APPRAISED);
		break;
	}
}

static int ima_get_file_hash(struct file *file, char **_digest,
				unsigned int *digest_len,
				enum pkey_hash_algo hash_algo)
{
	loff_t i_size, offset = 0;
	char *rbuf;
	int ret, read = 0;
	struct crypto_shash *tfm;
	size_t desc_size, digest_size;
	struct shash_desc *desc;
	char *digest = NULL;

	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!rbuf)
		return -ENOMEM;

	tfm = crypto_alloc_shash(pkey_hash_algo_name[hash_algo], 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		goto out;
	}

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	desc = kzalloc(desc_size, GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	desc->tfm   = tfm;
	desc->flags = 0;

	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto out_free_desc;

	digest_size = crypto_shash_digestsize(tfm);
	digest = kzalloc(digest_size, GFP_KERNEL);
	if (!digest) {
		ret = -ENOMEM;
		goto out_free_desc;
	}

	if (!(file->f_mode & FMODE_READ)) {
		file->f_mode |= FMODE_READ;
		read = 1;
	}
	i_size = i_size_read(file_inode(file));
	while (offset < i_size) {
		int rbuf_len;

		rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE);
		if (rbuf_len < 0) {
			ret = rbuf_len;
			break;
		}
		if (rbuf_len == 0)
			break;
		offset += rbuf_len;

		ret = crypto_shash_update(desc, rbuf, rbuf_len);
		if (ret)
			break;
	}

	if (!ret) {
		ret = crypto_shash_final(desc, digest);
		*_digest = digest;
		*digest_len = digest_size;
		digest = NULL;
	}

	if (read)
		file->f_mode &= ~FMODE_READ;

out_free_desc:
	kfree(desc);
out_free_tfm:
	kfree(tfm);
out:
	if (digest)
		kfree(digest);
	kfree(rbuf);
	return ret;
}

/*
 * Appraise a file with a given digital signature
 * keyring: keyring to use for appraisal
 * sig: signature
 * siglen: length of signature
 *
 * Returns 0 on successful appraisal, error otherwise.
 */
int ima_appraise_file_digsig(struct key *keyring, struct file *file, char *sig,
				unsigned int siglen)
{
	struct evm_ima_xattr_data *xattr_value;
	int ret = 0;
	char *digest = NULL;
	enum pkey_hash_algo hash_algo;
	unsigned int digest_len = 0;

	xattr_value = (struct evm_ima_xattr_data*) sig;

	if (xattr_value->type != EVM_IMA_XATTR_DIGSIG)
		return -EBADMSG;
	ret = integrity_digsig_get_hash_algo(xattr_value->digest);
	if (ret < 0)
		return ret;

	hash_algo = (enum pkey_hash_algo)ret;
	ret = ima_get_file_hash(file, &digest, &digest_len, hash_algo);
	if (ret)
		return ret;

	ret = integrity_digsig_verify_keyring(keyring, xattr_value->digest,
				integrity_get_digsig_size(xattr_value->digest),
				digest, digest_len);
	kfree(digest);
	return ret;
}

void ima_get_hash_algo(struct evm_ima_xattr_data *xattr_value, int xattr_len,
		       struct ima_digest_data *hash)
{
	struct signature_v2_hdr *sig;

	if (!xattr_value || xattr_len < 2)
		return;

	switch (xattr_value->type) {
	case EVM_IMA_XATTR_DIGSIG:
		sig = (typeof(sig))xattr_value;
		if (sig->version != 2 || xattr_len <= sizeof(*sig))
			return;
		hash->algo = sig->hash_algo;
		break;
	case IMA_XATTR_DIGEST_NG:
		hash->algo = xattr_value->digest[0];
		break;
	case IMA_XATTR_DIGEST:
		/* this is for backward compatibility */
		if (xattr_len == 21) {
			unsigned int zero = 0;
			if (!memcmp(&xattr_value->digest[16], &zero, 4))
				hash->algo = HASH_ALGO_MD5;
			else
				hash->algo = HASH_ALGO_SHA1;
		} else if (xattr_len == 17)
			hash->algo = HASH_ALGO_MD5;
		break;
	}
}

int ima_read_xattr(struct dentry *dentry,
		   struct evm_ima_xattr_data **xattr_value)
{
	struct inode *inode = dentry->d_inode;

	if (!inode->i_op->getxattr)
		return 0;

	return vfs_getxattr_alloc(dentry, XATTR_NAME_IMA, (char **)xattr_value,
				  0, GFP_NOFS);
}

/*
 * ima_appraise_measurement - appraise file measurement
 *
 * Call evm_verifyxattr() to verify the integrity of 'security.ima'.
 * Assuming success, compare the xattr hash with the collected measurement.
 *
 * Return 0 on success, error code otherwise
 */
int ima_appraise_measurement(int func, struct integrity_iint_cache *iint,
			     struct file *file, const unsigned char *filename,
			     struct evm_ima_xattr_data *xattr_value,
			     int xattr_len, int opened)
{
	static const char op[] = "appraise_data";
	char *cause = "unknown";
	struct dentry *dentry = file->f_dentry;
	struct inode *inode = dentry->d_inode;
	enum integrity_status status = INTEGRITY_UNKNOWN;
	int rc = xattr_len, hash_start = 0;

	if (!inode->i_op->getxattr)
		return INTEGRITY_UNKNOWN;

	if (rc <= 0) {
		if (rc && rc != -ENODATA)
			goto out;

		cause = "missing-hash";
		status = INTEGRITY_NOLABEL;
		if (opened & FILE_CREATED) {
			iint->flags |= IMA_NEW_FILE;
			status = INTEGRITY_PASS;
		}
		goto out;
	}

	status = evm_verifyxattr(dentry, XATTR_NAME_IMA, xattr_value, rc, iint);
	if ((status != INTEGRITY_PASS) && (status != INTEGRITY_UNKNOWN)) {
		if ((status == INTEGRITY_NOLABEL)
		    || (status == INTEGRITY_NOXATTRS))
			cause = "missing-HMAC";
		else if (status == INTEGRITY_FAIL)
			cause = "invalid-HMAC";
		goto out;
	}
	switch (xattr_value->type) {
	case IMA_XATTR_DIGEST_NG:
		/* first byte contains algorithm id */
		hash_start = 1;
	case IMA_XATTR_DIGEST:
		if (iint->flags & IMA_DIGSIG_REQUIRED) {
			cause = "IMA-signature-required";
			status = INTEGRITY_FAIL;
			break;
		}
		if (xattr_len - sizeof(xattr_value->type) - hash_start >=
				iint->ima_hash->length)
			/* xattr length may be longer. md5 hash in previous
			   version occupied 20 bytes in xattr, instead of 16
			 */
			rc = memcmp(&xattr_value->digest[hash_start],
				    iint->ima_hash->digest,
				    iint->ima_hash->length);
		else
			rc = -EINVAL;
		if (rc) {
			cause = "invalid-hash";
			status = INTEGRITY_FAIL;
			break;
		}
		status = INTEGRITY_PASS;
		break;
	case EVM_IMA_XATTR_DIGSIG:
		iint->flags |= IMA_DIGSIG;
		rc = integrity_digsig_verify(INTEGRITY_KEYRING_IMA,
				xattr_value->digest,
				integrity_get_digsig_size(xattr_value->digest),
				iint->ima_xattr.digest, IMA_DIGEST_SIZE);
		if (rc == -EOPNOTSUPP) {
			status = INTEGRITY_UNKNOWN;
		} else if (rc) {
			cause = "invalid-signature";
			status = INTEGRITY_FAIL;
		} else {
			status = INTEGRITY_PASS;
		}
		break;
	default:
		status = INTEGRITY_UNKNOWN;
		cause = "unknown-ima-data";
		break;
	}

out:
	if (status != INTEGRITY_PASS) {
		if ((ima_appraise & IMA_APPRAISE_FIX) &&
		    (!xattr_value ||
		     xattr_value->type != EVM_IMA_XATTR_DIGSIG)) {
			if (!ima_fix_xattr(dentry, iint))
				status = INTEGRITY_PASS;
		}
		integrity_audit_msg(AUDIT_INTEGRITY_DATA, inode, filename,
				    op, cause, rc, 0);
	} else {
		ima_cache_flags(iint, func);
	}
	ima_set_cache_status(iint, func, status);
	return status;
}

/*
 * ima_update_xattr - update 'security.ima' hash value
 */
void ima_update_xattr(struct integrity_iint_cache *iint, struct file *file)
{
	struct dentry *dentry = file->f_dentry;
	int rc = 0;

	/* do not collect and update hash for digital signatures */
	if (iint->flags & IMA_DIGSIG)
		return;

	rc = ima_collect_measurement(iint, file, NULL, NULL);
	if (rc < 0)
		return;

	ima_fix_xattr(dentry, iint);
}

/**
 * ima_inode_post_setattr - reflect file metadata changes
 * @dentry: pointer to the affected dentry
 *
 * Changes to a dentry's metadata might result in needing to appraise.
 *
 * This function is called from notify_change(), which expects the caller
 * to lock the inode's i_mutex.
 */
void ima_inode_post_setattr(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct integrity_iint_cache *iint;
	int must_appraise, rc;

	if (!(ima_policy_flag & IMA_APPRAISE) || !S_ISREG(inode->i_mode)
	    || !inode->i_op->removexattr)
		return;

	must_appraise = ima_must_appraise(inode, MAY_ACCESS, POST_SETATTR);
	iint = integrity_iint_find(inode);
	if (iint) {
		iint->flags &= ~(IMA_APPRAISE | IMA_APPRAISED |
				 IMA_APPRAISE_SUBMASK | IMA_APPRAISED_SUBMASK |
				 IMA_ACTION_FLAGS);
		if (must_appraise)
			iint->flags |= IMA_APPRAISE;
	}
	if (!must_appraise)
		rc = inode->i_op->removexattr(dentry, XATTR_NAME_IMA);
	return;
}

/*
 * ima_protect_xattr - protect 'security.ima'
 *
 * Ensure that not just anyone can modify or remove 'security.ima'.
 */
static int ima_protect_xattr(struct dentry *dentry, const char *xattr_name,
			     const void *xattr_value, size_t xattr_value_len)
{
	if (strcmp(xattr_name, XATTR_NAME_IMA) == 0) {
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return 1;
	}
	return 0;
}

static void ima_reset_appraise_flags(struct inode *inode, int digsig)
{
	struct integrity_iint_cache *iint;

	if (!(ima_policy_flag & IMA_APPRAISE) || !S_ISREG(inode->i_mode))
		return;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	iint->flags &= ~IMA_DONE_MASK;
	if (digsig)
		iint->flags |= IMA_DIGSIG;
	return;
}

int ima_inode_setxattr(struct dentry *dentry, const char *xattr_name,
		       const void *xattr_value, size_t xattr_value_len)
{
	const struct evm_ima_xattr_data *xvalue = xattr_value;
	int result;

	result = ima_protect_xattr(dentry, xattr_name, xattr_value,
				   xattr_value_len);
	if (result == 1) {
		if (!xattr_value_len || (xvalue->type >= IMA_XATTR_LAST))
			return -EINVAL;
		ima_reset_appraise_flags(dentry->d_inode,
			 (xvalue->type == EVM_IMA_XATTR_DIGSIG) ? 1 : 0);
		result = 0;
	}
	return result;
}

int ima_inode_removexattr(struct dentry *dentry, const char *xattr_name)
{
	int result;

	result = ima_protect_xattr(dentry, xattr_name, NULL, 0);
	if (result == 1) {
		ima_reset_appraise_flags(dentry->d_inode, 0);
		result = 0;
	}
	return result;
}
