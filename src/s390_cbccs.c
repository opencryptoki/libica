/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2011
 */

#include <string.h>
#include <errno.h>

#include <ica_api.h>

#include "icastats.h"
#include "s390_crypto.h"
#include "s390_des.h"
#include "s390_aes.h"
#include "s390_common.h"

static inline unsigned int
cbccs_last_block_swap(unsigned char *base, unsigned long length,
		      unsigned int block_size,
		      unsigned int direction, unsigned int variant)
{
	unsigned char tmp[block_size];
	unsigned long rest_length;
	unsigned long head_length;

	rest_length = length % block_size;

	switch (variant) {
	case 1:
		/* keep last two blocks in order */
		break;
	case 2:
		/* switch order of the last two blocks if length is not
		 * a multiple of the cipher block size, otherwise keep last
		 * two blocks in order */
		if (rest_length == 0)
			break;
	case 3:
		/* always switch order of the last two blocks */
		if (rest_length == 0)
			rest_length = block_size;
		head_length = length - rest_length;

		if (direction) {
			/* encrypt */
			memcpy(tmp,
			       base + (head_length - block_size) + rest_length,
			       block_size);
			memcpy(base + head_length,
			       base + (head_length - block_size),
			       rest_length);
			memcpy(base + (head_length - block_size),
			       tmp,
			       block_size);
		} else {
			/*decrypt */
			memcpy(tmp,
			       base + (head_length - block_size),
			       block_size);
			memcpy(base + (head_length - block_size),
			       base + head_length,
			       rest_length);
			memcpy(base + (head_length - block_size) + rest_length,
			       tmp,
			       block_size);
		}
		break;
	default:
		/* unsupported variant */
		return EINVAL;
	}

	return 0;
}
static unsigned int
s390_des_cbccs_enc(unsigned int fc, const unsigned char *in_data,
		   unsigned char *out_data, unsigned long data_length,
		   const unsigned char *key,
		   unsigned char *iv, unsigned int variant)
{
	unsigned int rc;
	unsigned char tmp_in_data[DES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % DES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length;

	/* tmp_data_length is at least DES_BLOCK_SIZE */
	rc = s390_des_cbc(fc, tmp_data_length, in_data, iv, key, out_data);
	if (rc)
		return rc;

	if (rest_data_length) {
		/* zero padding for uncomplete last block */
		memset(tmp_in_data, 0, DES_BLOCK_SIZE);
		memcpy(tmp_in_data, in_data + tmp_data_length, rest_data_length);

		rc = s390_des_cbc(fc, DES_BLOCK_SIZE, tmp_in_data, iv, key,
				  out_data + (tmp_data_length - DES_BLOCK_SIZE) +
				  rest_data_length);
		if (rc)
			return rc;
	}

	return cbccs_last_block_swap(out_data, data_length,
				     DES_BLOCK_SIZE, ICA_ENCRYPT, variant);
}

static unsigned int
s390_des_cbccs_dec(unsigned int fc, const unsigned char *in_data,
		   unsigned char *out_data, unsigned long data_length,
		   const unsigned char *key,
		   unsigned char *iv, unsigned int variant)
{
	unsigned int rc;
	unsigned char tmp_in_data[2* DES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long swap_length;
	unsigned long tmp_data_length;
	unsigned char tmp_iv[DES_BLOCK_SIZE];
	unsigned char tmp_out_data[DES_BLOCK_SIZE];

	rest_data_length = data_length % DES_BLOCK_SIZE;
	swap_length = (rest_data_length) ?
		DES_BLOCK_SIZE + rest_data_length :
		2* DES_BLOCK_SIZE;
	tmp_data_length = data_length - swap_length;

	/* copy last 2 blocks to temporary buffer, because blocks can not
	 * be re-ordered in in_data (const) */
	memset(tmp_in_data, 0, 2*DES_BLOCK_SIZE);
	memcpy(tmp_in_data, in_data + tmp_data_length, swap_length);

	rc = cbccs_last_block_swap(tmp_in_data, swap_length,
				   DES_BLOCK_SIZE, ICA_DECRYPT, variant);
	if (rc)
		return rc;

	if (rest_data_length == 0) {
		/* complete message handling */
		if (tmp_data_length) {
			rc = s390_des_cbc(fc, tmp_data_length, in_data,
					  iv, key, out_data);
			if (rc)
				return rc;
		}

		return s390_des_cbc(fc, swap_length, tmp_in_data,
				    iv, key, out_data + tmp_data_length);
	}

	if (tmp_data_length) {
		rc = s390_des_cbc(fc, tmp_data_length, in_data,
				  iv, key, out_data);
		if (rc)
			return rc;
	}

	/* decrypt block C(n) with zero iv */
	memset(tmp_iv, 0, DES_BLOCK_SIZE);
	rc = s390_des_cbc(fc, DES_BLOCK_SIZE,
			  tmp_in_data + rest_data_length,
			  tmp_iv, key, tmp_out_data);
	if(rc)
		return rc;

	/* complete block C*(n-1) to C(n-1) and decrypt it */
	memcpy_r_allign(tmp_in_data, DES_BLOCK_SIZE,
			tmp_out_data, DES_BLOCK_SIZE,
			DES_BLOCK_SIZE - rest_data_length);
	rc = s390_des_cbc(fc, DES_BLOCK_SIZE, tmp_in_data,
			  iv, key, out_data + tmp_data_length);
	if(rc)
		return rc;

	/* XOR tmp_out_data with C*(n-1) */
	block_xor(out_data + tmp_data_length + DES_BLOCK_SIZE,
		  tmp_in_data, tmp_out_data, rest_data_length);

	return 0;
}

static unsigned int
s390_aes_cbccs_enc(unsigned int fc, const unsigned char *in_data,
		   unsigned char *out_data, unsigned long data_length,
		   const unsigned char *key, unsigned int key_length,
		   unsigned char *iv, unsigned int variant)
{
	unsigned int rc;
	unsigned char tmp_in_data[AES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % AES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length;

	/* tmp_data_length is at least AES_BLOCK_SIZE */
	rc = s390_aes_cbc(fc, tmp_data_length, in_data, iv, key, out_data);
	if (rc)
		return rc;

	if (rest_data_length) {
		memset(tmp_in_data, 0, AES_BLOCK_SIZE);
		memcpy(tmp_in_data, in_data + tmp_data_length, AES_BLOCK_SIZE);

		rc = s390_aes_cbc(fc, AES_BLOCK_SIZE, tmp_in_data, iv, key,
				  out_data + (tmp_data_length - AES_BLOCK_SIZE) +
				  rest_data_length);
		if (rc)
			return rc;
	}

	return cbccs_last_block_swap(out_data, data_length,
				     AES_BLOCK_SIZE, ICA_ENCRYPT, variant);
}

static unsigned int
s390_aes_cbccs_dec(unsigned int fc, const unsigned char *in_data,
		   unsigned char *out_data, unsigned long data_length,
		   const unsigned char *key, unsigned int key_length,
		   unsigned char *iv, unsigned int variant)
{
	unsigned int rc;
	unsigned char tmp_in_data[2* AES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long swap_length;
	unsigned long tmp_data_length;
	unsigned char tmp_iv[AES_BLOCK_SIZE];
	unsigned char tmp_out_data[AES_BLOCK_SIZE];

	rest_data_length = data_length % AES_BLOCK_SIZE;
	swap_length = (rest_data_length) ?
		(AES_BLOCK_SIZE + rest_data_length) :
		(2* AES_BLOCK_SIZE);
	tmp_data_length = data_length - swap_length;

	/* copy last 2 blocks to temporary buffer, because blocks can not
	 * be re-ordered in in_data (const) */
	memset(tmp_in_data, 0, 2* AES_BLOCK_SIZE);
	memcpy(tmp_in_data, in_data + tmp_data_length, swap_length);

	rc = cbccs_last_block_swap(tmp_in_data, swap_length,
				   AES_BLOCK_SIZE, ICA_DECRYPT, variant);
	if (rc)
		return rc;

	if (rest_data_length == 0) {
		/* complete message handling */
		if (tmp_data_length) {
			rc = s390_aes_cbc(fc, tmp_data_length, in_data,
					  iv, key, out_data);
			if (rc)
				return rc;
		}

		return s390_aes_cbc(fc, swap_length, tmp_in_data,
				    iv, key, out_data + tmp_data_length);
	}

	if (tmp_data_length) {
		rc = s390_aes_cbc(fc, tmp_data_length, in_data,
				  iv, key, out_data);
		if (rc)
			return rc;
	}

	/* decrypt block C(n) with zero iv */
	memset(tmp_iv, 0, AES_BLOCK_SIZE);
	rc = s390_aes_cbc(fc, AES_BLOCK_SIZE,
			  tmp_in_data + rest_data_length,
			  tmp_iv, key, tmp_out_data);
	if(rc)
		return rc;

	/* complete block C*(n-1) to C(n-1) and decrypt it */
	memcpy_r_allign(tmp_in_data, AES_BLOCK_SIZE,
			tmp_out_data, AES_BLOCK_SIZE,
			AES_BLOCK_SIZE - rest_data_length);
	rc = s390_aes_cbc(fc, AES_BLOCK_SIZE, tmp_in_data,
			  iv, key, out_data + tmp_data_length);
	if(rc)
		return rc;

	/* XOR tmp_out_data with C*(n-1) */
	block_xor(out_data + tmp_data_length + AES_BLOCK_SIZE,
		  tmp_in_data, tmp_out_data, rest_data_length);

	return 0;
}

inline int s390_des_cbccs(unsigned int fc, const unsigned char *in_data,
			  unsigned char *out_data, unsigned long data_length,
			  const unsigned char *key,
			  unsigned char *iv, unsigned int variant)
{
	if (s390_msa4_functions[fc].hw_fc & S390_CRYPTO_DIRECTION_MASK)
		return s390_des_cbccs_dec(fc, in_data, out_data, data_length,
					  key, iv, variant);
	else
		return s390_des_cbccs_enc(fc, in_data, out_data, data_length,
					  key, iv, variant);
}

inline int s390_aes_cbccs(unsigned int fc, const unsigned char *in_data,
			  unsigned char *out_data, unsigned long data_length,
			  const unsigned char *key, unsigned int key_length,
			  unsigned char *iv, unsigned int variant)
{
	if (s390_msa4_functions[fc].hw_fc & S390_CRYPTO_DIRECTION_MASK)
		return s390_aes_cbccs_dec(fc, in_data, out_data, data_length,
					  key, key_length, iv, variant);
	else
		return s390_aes_cbccs_enc(fc, in_data, out_data, data_length,
					  key, key_length, iv, variant);
}
