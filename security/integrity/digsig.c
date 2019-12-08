/*
 * Copyright (C) 2011 Intel Corporation
 *
 * Author:
 * Dmitry Kasatkin <dmitry.kasatkin@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/err.h>
#include <linux/sched.h>
#include <linux/rbtree.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/key-type.h>
#include <linux/digsig.h>
#include <crypto/hash.h>
#include <crypto/public_key.h>

#include "integrity.h"

static struct key *keyring[INTEGRITY_KEYRING_MAX];

static const char *keyring_name[INTEGRITY_KEYRING_MAX] = {
	"_evm",
	"_module",
#ifndef CONFIG_IMA_TRUSTED_KEYRING
	"_ima",
#else
	".ima",
#endif
};



int integrity_digsig_get_hash_algo(char *sig)
{
	uint8_t hash_algo;

	if (sig[0] == 1) {
		hash_algo = ((struct signature_hdr *)sig)->hash;
		switch (hash_algo) {
		case 0:
			return PKEY_HASH_SHA1;
		case 1:
			return PKEY_HASH_SHA256;
		default:
		return -ENOPKG;
		}
	} else if (sig[0] == 2 ) {
		hash_algo = ((struct signature_v2_hdr *)sig)->hash_algo;
		if (hash_algo >= PKEY_HASH__LAST)
			return -ENOPKG;
		return hash_algo;
	}

	return -EBADMSG;
}


/* Get size of digital signature */
int integrity_get_digsig_size(char *sig)
{
	uint16_t sz;

	if (sig[0] == 1) {
		sz = *((uint16_t *)(sig + sizeof(struct signature_hdr)));
		sz = __be16_to_cpu(sz);
		return sizeof(struct signature_hdr) + 2 + (sz >> 3);
	} else if (sig[0] == 2 ) {
		sz = ((struct signature_v2_hdr *)sig)->sig_size;
		return sizeof(struct signature_v2_hdr) + __be16_to_cpu(sz);
	}

	return -EBADMSG;
}

int integrity_digsig_verify_keyring(struct key *keyring, const char *sig,
		int siglen, const char *digest, int digestlen)
{
	switch (sig[0]) {
	case 1:
		return digsig_verify(keyring, sig, siglen,
				     digest, digestlen);
	case 2:
		return asymmetric_verify(keyring, sig, siglen,
					 digest, digestlen);
	}
	return -EOPNOTSUPP;
}

int integrity_digsig_verify(const unsigned int id, const char *sig, int siglen,
			    const char *digest, int digestlen)
{
	if (id >= INTEGRITY_KEYRING_MAX)
		return -EINVAL;

	if (!keyring[id]) {
		keyring[id] =
			request_key(&key_type_keyring, keyring_name[id], NULL);
		if (IS_ERR(keyring[id])) {
			int err = PTR_ERR(keyring[id]);
			pr_err("no %s keyring: %d\n", keyring_name[id], err);
			keyring[id] = NULL;
			return err;
		}
	}
	return integrity_digsig_verify_keyring(keyring[id], sig, siglen, digest, digestlen);
}

static int integrity_calc_user_buffer_hash(enum pkey_hash_algo hash_algo,
					const char __user *data,
					unsigned long data_len, char **_digest,
					unsigned int *digest_len)
{
	char *buffer, *digest;
	unsigned long len;
	struct crypto_shash *tfm;
	size_t desc_size, digest_size;
	struct shash_desc *desc;
	int ret;

	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	/* TODO: allow different kind of hash */
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

	do {
		len = min(data_len, PAGE_SIZE - ((size_t)data & ~PAGE_MASK));
		ret = -EFAULT;
		if (copy_from_user(buffer, data, len) != 0)
			goto out_free_digest;

		ret = crypto_shash_update(desc, buffer, len);
                if (ret)
                        break;

		data_len -= len;
		data += len;

		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}
	} while (data_len > 0);

	if (!ret) {
		ret = crypto_shash_final(desc, digest);
		*_digest = digest;
		*digest_len = digest_size;
		digest = NULL;
	}

out_free_digest:
	if (digest)
		kfree(digest);
out_free_desc:
	kfree(desc);
out_free_tfm:
	kfree(tfm);
out:
	kfree(buffer);
	return ret;
}

/*
 * Appraise a user buffer with a given digital signature
 * keyring: keyring to use for appraisal
 * sig: signature
 * siglen: length of signature
 *
 * Returns 0 on successful appraisal, error otherwise.
 */
int integrity_verify_user_buffer_digsig(struct key *keyring,
				const char __user *data,
				unsigned long data_len,
				char *sig, unsigned int siglen)
{
	int ret = 0;
	enum pkey_hash_algo hash_algo;
	char *digest = NULL;
	unsigned int digest_len = 0;

	hash_algo = integrity_digsig_get_hash_algo(sig);
	if (hash_algo < 0)
		return hash_algo;

	ret = integrity_calc_user_buffer_hash(hash_algo, data, data_len,
						&digest, &digest_len);
	if (ret)
		return ret;

	ret = integrity_digsig_verify_keyring(keyring, sig, siglen, digest,
					digest_len);
	kfree(digest);
	return ret;
}

int integrity_init_keyring(const unsigned int id)
{
	const struct cred *cred = current_cred();
	int err = 0;

	keyring[id] = keyring_alloc(keyring_name[id], KUIDT_INIT(0),
				    KGIDT_INIT(0), cred,
				    ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
				     KEY_USR_VIEW | KEY_USR_READ |
				     KEY_USR_WRITE | KEY_USR_SEARCH),
				    KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (!IS_ERR(keyring[id]))
		set_bit(KEY_FLAG_TRUSTED_ONLY, &keyring[id]->flags);
	else {
		err = PTR_ERR(keyring[id]);
		pr_info("Can't allocate %s keyring (%d)\n",
			keyring_name[id], err);
		keyring[id] = NULL;
	}
	return err;
}
