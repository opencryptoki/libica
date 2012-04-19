/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Ruben Straus<rstraus@de.ibm.com>
 * 	    Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2011
 */

#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "ica_api.h"
#include "icastats.h"
#include "s390_crypto.h"
#include "s390_aes.h"
#include "s390_cmac.h"
#include "s390_ccm.h"
#include "s390_common.h"

/* assoc_data first meta block with data
 * for small assoc_data_length */
struct meta_ad_small {
	uint16_t length;
	unsigned char data[14];
} __attribute__((packed));

/* assoc_data first meta block with prefix and data
 * for medium assoc_data_length */
struct meta_ad_medium {
	unsigned char prefix[2];
	uint32_t length;
	unsigned char data[10];
} __attribute__((packed));

/* assoc_data first meta block with prefix and data
 * for large assoc_data_length */
struct meta_ad_large {
	unsigned char prefix[2];
	uint64_t length;
	unsigned char data[6];
} __attribute__((packed));

/* assoc_data meta block union with size cipher block size */
typedef union {
	struct meta_ad_small small;
	struct meta_ad_medium medium;
	struct meta_ad_large large;
} __attribute__((packed)) ad_meta_t;

static inline unsigned int fc_to_key_length(unsigned int function_code)
{
	switch(function_code | 0x7F) {
	case S390_CRYPTO_AES_128_ENCRYPT:
		return 128/8;
	case S390_CRYPTO_AES_192_ENCRYPT:
		return 192/8;
	case S390_CRYPTO_AES_256_ENCRYPT:
	default:
		return 256/8;
	}
}

static inline void __compute_meta_b0(const unsigned char *nonce,
				     unsigned long nonce_length,
				     unsigned long assoc_data_length,
				     unsigned long payload_length,
				     unsigned long mac_length,
				     unsigned char *meta_b0)
{
	struct {
		uint8_t reserved :1;
		uint8_t adata    :1;
		uint8_t t_enc    :3;
		uint8_t q_enc    :3;
	} __attribute__((packed)) meta_flags;

	memset(meta_b0, 0x00, AES_BLOCK_SIZE);

	/* meta flags */
	memset(&meta_flags, 0x00, sizeof(meta_flags));
	if (assoc_data_length)
		meta_flags.adata = 1;

	meta_flags.t_enc = (mac_length-2) / 2;
	meta_flags.q_enc = (15 - nonce_length) - 1;

	memcpy(meta_b0, &meta_flags, sizeof(meta_flags));

	/* encoding N */
	memcpy(meta_b0 + sizeof(meta_flags), nonce, nonce_length);

	/* encoding Q */
	memcpy_r_allign(meta_b0, AES_BLOCK_SIZE,
			&payload_length, sizeof(payload_length),
			AES_BLOCK_SIZE - (sizeof(meta_flags) + nonce_length));
}

static inline void __compute_initial_ctr(const unsigned char *nonce,
					 unsigned long nonce_length,
					 unsigned long payload_length,
					 unsigned char *ctr)
{
	struct {
		uint8_t reserved :2;
		uint8_t zero     :3;
		uint8_t q_enc    :3;
	} __attribute__((packed)) ctr_flags;

	memset(ctr, 0x00, AES_BLOCK_SIZE);

	memset(&ctr_flags, 0x00, sizeof(ctr_flags));
	ctr_flags.q_enc = (15 - nonce_length) - 1;

	memcpy(ctr, &ctr_flags, sizeof(ctr_flags));
	memcpy(ctr + sizeof(ctr_flags), nonce, nonce_length);
}

static inline unsigned int __auth_assoc_data(unsigned int function_code,
					     const unsigned char *assoc_data,
					     unsigned long assoc_data_length,
					     const unsigned char *key,
					     unsigned int key_length,
					     unsigned char *iv)
{
	unsigned int rc;
	ad_meta_t meta;
	unsigned char *meta_data;
	unsigned long meta_data_length;
	unsigned char tmp_block[AES_BLOCK_SIZE];
	const unsigned char *rest;
	unsigned long rest_length;
	unsigned long head_length;
	unsigned long tail_length;

	/* preparing first block of assoc_data */
	if (assoc_data_length < ((1ul << 16)-(1ul << 8))) {
		meta.small.length = assoc_data_length;
		meta_data = meta.small.data;
		meta_data_length = sizeof(meta.small.data);
	} else if (assoc_data_length < (1ul << 32)) {
		meta.medium.prefix[0] = 0xff;
		meta.medium.prefix[1] = 0xfe;
		meta.medium.length = assoc_data_length;
		meta_data = meta.medium.data;
		meta_data_length = sizeof(meta.medium.data);
	} else {
		meta.large.prefix[0] = 0xff;
		meta.large.prefix[1] = 0xff;
		meta.large.length = assoc_data_length;
		meta_data = meta.large.data;
		meta_data_length = sizeof(meta.large.data);
	}

	if (assoc_data_length < meta_data_length) {
		memset(meta_data, 0x00, meta_data_length);
		memcpy(meta_data, assoc_data, assoc_data_length);
		rest_length = 0;
		rest = NULL;
	} else {
		memcpy(meta_data, assoc_data, meta_data_length);
		rest_length = assoc_data_length - meta_data_length;
		rest = assoc_data + meta_data_length;
	}

	/* processing first block of assoc_data */
	rc = s390_cmac(function_code,
		       (unsigned char *)&meta, AES_BLOCK_SIZE,
		       key_length, key,
		       AES_BLOCK_SIZE, NULL,	/* cmac_intermediate */
		       iv);
	if (rc)
		return rc;

	/* processing remaining assoc_data */
	if (rest_length) {
		tail_length = rest_length % AES_BLOCK_SIZE;
		head_length = rest_length - tail_length;

		if (head_length) {
			rc = s390_cmac(function_code,
				       rest, head_length,
				       key_length, key,
				       AES_BLOCK_SIZE, NULL,	/* cmac_intermediate */
				       iv);
			if (rc)
				return rc;

			rest += head_length;
		}

		/* assoc_data padding */
		if (tail_length) {
			memset(tmp_block, 0x00, AES_BLOCK_SIZE);
			memcpy(tmp_block, rest, tail_length);

			rc = s390_cmac(function_code,
				       tmp_block, AES_BLOCK_SIZE,
				       key_length, key,
				       AES_BLOCK_SIZE, NULL,	/* cmac_intermediate */
				       iv);
			if (rc)
				return rc;
		}
	}

	return 0;
}

static unsigned int s390_ccm_authenticate(unsigned int function_code,
					  const unsigned char *payload,
					  unsigned long payload_length,
					  const unsigned char *assoc_data,
					  unsigned long assoc_data_length,
					  const unsigned char *nonce,
					  unsigned int nonce_length,
					  unsigned char *tag,
					  unsigned int tag_length,
					  const unsigned char *key,
					  unsigned int key_length)
{
	unsigned int rc;
	unsigned char meta_b0[AES_BLOCK_SIZE];
	unsigned char tmp_block[AES_BLOCK_SIZE];
	unsigned long head_length;
	unsigned long tail_length;

	/* compute meta information block B0 */
	__compute_meta_b0(nonce, nonce_length,
			  assoc_data_length, payload_length, tag_length,
			  meta_b0);

	/* kmac of first block (intermediate) */
	memset(tag, 0x00, AES_BLOCK_SIZE);
	rc = s390_cmac(function_code,
		       meta_b0, AES_BLOCK_SIZE,
		       key_length, key,
		       AES_BLOCK_SIZE, NULL,	/* cmac_intermediate */
		       tag);
	if (rc)
		return rc;

	/* kmac of assoc_data blocks (intermediate) */
	if (assoc_data_length) {
		rc = __auth_assoc_data(function_code,
				       assoc_data, assoc_data_length,
				       key, key_length,
				       tag);
		if (rc)
			return rc;
	}

	/* kmac of payload (intermediate) */
	tail_length = payload_length % AES_BLOCK_SIZE;
	head_length = payload_length - tail_length;

	if (head_length) {
		rc = s390_cmac(function_code,
			       payload, head_length,
			       key_length, key,
			       AES_BLOCK_SIZE, NULL,	/* cmac_intermediate */
			       tag);
		if (rc)
			return rc;
	}

	if (tail_length) {
		memset(tmp_block, 0x00, AES_BLOCK_SIZE);
		memcpy(tmp_block, payload + head_length, tail_length);

		rc = s390_cmac(function_code,
			       tmp_block, AES_BLOCK_SIZE,
			       key_length, key,
			       AES_BLOCK_SIZE, NULL,	/* cmac_intermediate */
			       tag);
		if (rc)
			return rc;
	}

	return 0;
}

unsigned int s390_ccm(unsigned int function_code,
		      unsigned char *payload, unsigned long payload_length,
		      unsigned char *ciphertext,
		      const unsigned char *assoc_data, unsigned long assoc_data_length,
		      const unsigned char *nonce, unsigned long nonce_length,
		      unsigned char *mac, unsigned long mac_length,
		      const unsigned char *key)
{
	unsigned char initial_ctr[AES_BLOCK_SIZE];
	unsigned char cipher_ctr[AES_BLOCK_SIZE];
	unsigned char tag[AES_BLOCK_SIZE];
	unsigned int ccm_ctr_width;
	unsigned int hardware;
	unsigned int rc;

	hardware = 1;

	/* compute initial counter */
	__compute_initial_ctr(nonce, nonce_length, payload_length, initial_ctr);
	ccm_ctr_width = (15 - nonce_length) * 8;

	if (payload_length) {
		/* compute counter for en-/decryption */
		memcpy(cipher_ctr, initial_ctr, AES_BLOCK_SIZE);
		ctr_inc_single(cipher_ctr, AES_BLOCK_SIZE, ccm_ctr_width);

		/* en-/decrypt */
		if (function_code % 2) {
			/* decrypt */
			rc = s390_aes_ctr(UNDIRECTED_FC(function_code),
					  ciphertext, payload, payload_length,
					  key, cipher_ctr, ccm_ctr_width);
			if (rc)
				return rc;

			stats_increment(ICA_STATS_CCM_DECRYPT, hardware);
		} else {
			/*encrypt */
			rc = s390_aes_ctr(UNDIRECTED_FC(function_code),
					  payload, ciphertext, payload_length,
					  key, cipher_ctr, ccm_ctr_width);
			if (rc)
				return rc;

			stats_increment(ICA_STATS_CCM_ENCRYPT, hardware);
		}
	}

	/* generate tag */
	rc = s390_ccm_authenticate(UNDIRECTED_FC(function_code),
				   payload, payload_length,
				   assoc_data, assoc_data_length,
				   nonce, nonce_length,
				   tag, mac_length,
				   key, fc_to_key_length(function_code));
	if (rc)
		return rc;

	/* encrypt tag into mac */
	return s390_aes_ctr(UNDIRECTED_FC(function_code),
			    tag, mac, mac_length,
			    key, initial_ctr, ccm_ctr_width);
}

