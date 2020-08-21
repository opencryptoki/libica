/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *	    Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2010, 2011
 */

#ifndef S390_DES_H
#define S390_DES_H

#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "icastats.h"
#include "s390_crypto.h"
#include "s390_ctr.h"

#define DES_BLOCK_SIZE  8

static inline int s390_des_ecb_hw(unsigned int function_code, unsigned long input_length,
		    const unsigned char *input_data, unsigned char *keys,
		    unsigned char *output_data)
{
	int rc = -1;
	rc = s390_km(function_code, keys, output_data, input_data,
		     input_length);

	if (rc >= 0)
		return 0;
	else
		return EIO;
}


static inline int s390_des_ecb_sw(unsigned int function_code, unsigned long input_length,
		    const unsigned char *input_data, const unsigned char *keys,
		    unsigned char *output_data)
{
#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	DES_key_schedule key_schedule1;
	DES_key_schedule key_schedule2;
	DES_key_schedule key_schedule3;
	switch (function_code & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		DES_set_key_unchecked((const_DES_cblock *) keys,
				      &key_schedule1);
		for (; input_length; input_length -= sizeof(DES_cblock)) {
			DES_ecb_encrypt((const_DES_cblock *) input_data,
					(DES_cblock *) output_data,
					&key_schedule1,
					(function_code &
					 S390_CRYPTO_DIRECTION_MASK) ? 0 : 1);
			input_data += sizeof(DES_cblock);
			output_data += sizeof(DES_cblock);
		}
		break;

	case S390_CRYPTO_TDEA_128_ENCRYPT:
		DES_set_key_unchecked((const_DES_cblock *) keys,
				      &key_schedule1);
		DES_set_key_unchecked((const_DES_cblock *) keys + 1,
				      &key_schedule2);
		for (; input_length; input_length -= sizeof(DES_cblock)) {
			DES_ecb2_encrypt((const_DES_cblock *)
					 input_data,
					 (DES_cblock *) output_data,
					 &key_schedule1, &key_schedule2,
					 (function_code &
					  S390_CRYPTO_DIRECTION_MASK) ? 0 : 1);
			input_data += sizeof(DES_cblock);
			output_data += sizeof(DES_cblock);
		}
		break;

	case S390_CRYPTO_TDEA_192_ENCRYPT:
		DES_set_key_unchecked((const_DES_cblock *) keys,
				      &key_schedule1);
		DES_set_key_unchecked((const_DES_cblock *) keys + 1,
				      &key_schedule2);
		DES_set_key_unchecked((const_DES_cblock *) keys + 2,
				      &key_schedule3);
		for (; input_length; input_length -= sizeof(DES_cblock)) {
			DES_ecb3_encrypt((const_DES_cblock *)
					 input_data,
					 (DES_cblock *) output_data,
					 &key_schedule1, &key_schedule2,
					 &key_schedule3, (function_code &
					  S390_CRYPTO_DIRECTION_MASK) ? 0 : 1);
			input_data += sizeof(DES_cblock);
			output_data += sizeof(DES_cblock);
		}
		break;
	}

	OPENSSL_cleanse(&key_schedule1, sizeof(key_schedule1));
	OPENSSL_cleanse(&key_schedule2, sizeof(key_schedule2));
	OPENSSL_cleanse(&key_schedule2, sizeof(key_schedule3));

	return 0;
}


static inline int s390_des_cbc_hw(unsigned int function_code,
			   unsigned long input_length,
			   const unsigned char *input_data, unsigned char *iv,
			   const unsigned char *keys, unsigned char *output_data)
{
	struct {
		ica_des_vector_t iv;
		ica_des_key_triple_t keys;
	} key_buffer;

	int rc = -1;
	unsigned int key_size = (function_code & S390_CRYPTO_FUNCTION_MASK) *
	    sizeof(ica_des_key_single_t);
	memcpy(&key_buffer.iv, iv, sizeof(ica_des_vector_t));
	memcpy(&key_buffer.keys, keys, key_size);

	rc = s390_kmc(function_code, &key_buffer, output_data,
		      input_data, input_length);

	memset(&key_buffer.keys, 0, key_size);

	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_des_vector_t));
		return 0;
	} else
		return EIO;
}


static inline int s390_des_cbc_sw(unsigned int function_code,
			   unsigned long input_length,
			   const unsigned char *input_data, unsigned char *iv,
			   const unsigned char *keys, unsigned char *output_data)
{
#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	DES_key_schedule key_schedule1;
	DES_key_schedule key_schedule2;
	DES_key_schedule key_schedule3;
	switch (function_code & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		DES_set_key_unchecked((const_DES_cblock *) keys,
				      &key_schedule1);
		DES_ncbc_encrypt(input_data, output_data, input_length,
				 &key_schedule1, (DES_cblock *) iv,
				 (function_code & S390_CRYPTO_DIRECTION_MASK) ?
				 0 : 1);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
		DES_set_key_unchecked((const_DES_cblock *) keys,
				      &key_schedule1);
		DES_set_key_unchecked((const_DES_cblock *) keys + 1,
				      &key_schedule2);
		DES_ede2_cbc_encrypt(input_data, output_data, input_length,
				     &key_schedule1, &key_schedule2,
				     (DES_cblock *) iv,
				     (function_code &
				      S390_CRYPTO_DIRECTION_MASK) ? 0 : 1);
		break;
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		DES_set_key_unchecked((const_DES_cblock *) keys,
				      &key_schedule1);
		DES_set_key_unchecked((const_DES_cblock *) keys + 1,
				      &key_schedule2);
		DES_set_key_unchecked((const_DES_cblock *) keys + 2,
				      &key_schedule3);
		DES_ede3_cbc_encrypt(input_data, output_data, input_length,
				     &key_schedule1, &key_schedule2,
				     &key_schedule3, (DES_cblock *) iv,
				     (function_code &
				      S390_CRYPTO_DIRECTION_MASK) ? 0 : 1);
		break;
	};

	OPENSSL_cleanse(&key_schedule1, sizeof(key_schedule1));
	OPENSSL_cleanse(&key_schedule2, sizeof(key_schedule2));
	OPENSSL_cleanse(&key_schedule2, sizeof(key_schedule3));

	return 0;
}

static inline int s390_des_ecb(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, unsigned char *key,
		 unsigned char *out_data)
{
	int rc = ENODEV;
	int hardware = ALGO_HW;

	if (*s390_kmc_functions[fc].enabled)
		rc = s390_des_ecb_hw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, key,
				     out_data);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_des_ecb_sw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, key,
				     out_data);
		hardware = ALGO_SW;
	}

	switch (s390_kmc_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment(ICA_STATS_DES_ECB, hardware,
				(s390_kmc_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ENCRYPT : DECRYPT);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment(ICA_STATS_3DES_ECB, hardware,
				 (s390_kmc_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ENCRYPT : DECRYPT);
		break;
	}

	return rc;
}

static inline int s390_des_cbc(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, unsigned char *iv,
		 const unsigned char *key, unsigned char *out_data)
{
	int rc = ENODEV;
	int hardware = ALGO_HW;

	if (*s390_kmc_functions[fc].enabled)
		rc = s390_des_cbc_hw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_des_cbc_sw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data);
		hardware = ALGO_SW;
	}

	switch (s390_kmc_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment(ICA_STATS_DES_CBC, hardware,
				(s390_kmc_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ENCRYPT : DECRYPT);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment(ICA_STATS_3DES_CBC, hardware,
				(s390_kmc_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ENCRYPT : DECRYPT);
		break;
	}

	return rc;
}

static inline int s390_des_cfb_hw(unsigned int function_code,
			   unsigned long data_length,
			   const unsigned char *in_data, unsigned char *iv,
			   const unsigned char *key, unsigned char *out_data,
			   unsigned int lcfb)
{
	struct {
		ica_des_vector_t iv;
		ica_des_key_triple_t keys;
	} key_buffer;
	int rc = -1;

	unsigned int key_size = (function_code & S390_CRYPTO_FUNCTION_MASK) *
				 sizeof(ica_des_key_single_t);
	memcpy(&key_buffer.iv, iv, sizeof(ica_des_vector_t));
	memcpy(&key_buffer.keys, key, key_size);

	rc = s390_kmf(function_code, &key_buffer, out_data,
		      in_data, data_length, &lcfb);

	memset(&key_buffer.keys, 0, key_size);

	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_des_vector_t));
		return 0;
	} else
		return EIO;
}

static inline int __s390_des_cfb(unsigned int fc, unsigned long data_length,
			  const unsigned char *in_data, unsigned char *iv,
			  const unsigned char *key, unsigned char *out_data,
			  unsigned int lcfb)
{
	int rc = ENODEV;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_des_cfb_hw(s390_msa4_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data, lcfb);
	if (rc)
		return rc;

	switch (s390_msa4_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment(ICA_STATS_DES_CFB, ALGO_HW,
				(s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ENCRYPT : DECRYPT);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment(ICA_STATS_3DES_CFB, ALGO_HW,
				(s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ENCRYPT : DECRYPT);
		break;
	}

	return 0;
}

static inline int s390_des_ofb_hw(unsigned int function_code,
			   unsigned int input_length,
			   const unsigned char *input_data, unsigned char *iv,
			   const unsigned char *keys, unsigned char *output_data)
{
	struct {
		ica_des_vector_t iv;
		ica_des_key_triple_t keys;
	} key_buffer;

	int rc = -1;
	unsigned int key_size = (function_code & S390_CRYPTO_FUNCTION_MASK) *
	    sizeof(ica_des_key_single_t);
	memcpy(&key_buffer.iv, iv, sizeof(ica_des_vector_t));
	memcpy(&key_buffer.keys, keys, key_size);

	rc = s390_kmo(function_code, &key_buffer, output_data,
		      input_data, input_length);

	memset(&key_buffer.keys, 0, key_size);

	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_des_vector_t));
		return 0;
	} else
		return EIO;
}

static inline int __s390_des_ofb(unsigned int fc, unsigned int input_length,
				 const unsigned char *input_data, unsigned char *iv,
				 const unsigned char *keys, unsigned char *output_data)
{
	int rc = ENODEV;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_des_ofb_hw(s390_msa4_functions[fc].hw_fc,
				     input_length, input_data, iv, keys,
				     output_data);
	if (rc)
		return rc;

	switch (s390_msa4_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment(ICA_STATS_DES_OFB, ALGO_HW,
				(s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ENCRYPT : DECRYPT);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment(ICA_STATS_3DES_OFB, ALGO_HW,
				(s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ENCRYPT : DECRYPT);
		break;
	}

	return 0;
}

static inline int s390_des_cfb(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, unsigned char *iv,
		 const unsigned char *key, unsigned char *out_data,
		 unsigned int lcfb)
{
	int rc = 0;
	/* Temporary buffers with size of lcfb should be
	 * sufficiant, using static maximun lcfb instead. */
	unsigned char rest_in_data[DES_BLOCK_SIZE];
	unsigned char rest_out_data[DES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % lcfb;
	tmp_data_length = data_length - rest_data_length;

	if (tmp_data_length) {
		rc = __s390_des_cfb(fc, tmp_data_length, in_data,
				    iv, key, out_data, lcfb);
		if (rc)
			return rc;
	}

	if (rest_data_length) {
		memcpy(rest_in_data, in_data + tmp_data_length,
		       rest_data_length);

		rc = __s390_des_cfb(fc, lcfb, rest_in_data, iv, key,
		    rest_out_data, lcfb);
		if (rc)
			return rc;

		memcpy(out_data + tmp_data_length,
		       rest_out_data, rest_data_length);
	}

	return rc;
}

static inline int s390_des_ofb(unsigned int fc, unsigned long data_length,
			const unsigned char *in_data, unsigned char *iv,
			const unsigned char *key, unsigned char *out_data)
{
	int rc = 0;
	unsigned char rest_in_data[DES_BLOCK_SIZE];
	unsigned char rest_out_data[DES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % DES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length;

	if (tmp_data_length) {
		rc = __s390_des_ofb(fc, tmp_data_length, in_data,
				    iv, key, out_data);
		if (rc)
			return rc;
	}

	if (rest_data_length) {
		memcpy(rest_in_data, in_data + tmp_data_length,
		       rest_data_length);

		rc = __s390_des_ofb(fc, DES_BLOCK_SIZE,
				    rest_in_data,
				    iv, key, rest_out_data);
		if (rc)
			return rc;

		memcpy(out_data + tmp_data_length,
		       rest_out_data, rest_data_length);
	}

	return rc;
}

static inline int __s390_des_ctrlist(unsigned int fc, unsigned long data_length,
				     const unsigned char *in_data,
				     const unsigned char *ctrlist,
				     unsigned char *key,
				     unsigned char *out_data)
{
	int rc = ENODEV;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_ctr_hw(s390_msa4_functions[fc].hw_fc,
				 data_length, in_data, key,
				 out_data, ctrlist);
	if (rc)
		return rc;

	switch (s390_msa4_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment(ICA_STATS_DES_CTR, ALGO_HW,
				(s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ?ENCRYPT: DECRYPT);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment(ICA_STATS_3DES_CTR, ALGO_HW,
				(s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ?ENCRYPT: DECRYPT);
		break;
	}

	return 0;
}

static inline int s390_des_ctrlist(unsigned int fc, unsigned long data_length,
			    const unsigned char *in_data,
			    const unsigned char *ctrlist,
			    unsigned char *key, unsigned char *out_data)
{
	int rc = 0;
	unsigned char rest_in_data[DES_BLOCK_SIZE];
	unsigned char rest_out_data[DES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % DES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length;

	if (tmp_data_length) {
		rc = __s390_des_ctrlist(fc, tmp_data_length, in_data,
					ctrlist, key, out_data);
		if (rc)
			return rc;
	}

	if (rest_data_length) {
		memcpy(rest_in_data, in_data + tmp_data_length,
		       rest_data_length);

		rc = __s390_des_ctrlist(fc, DES_BLOCK_SIZE,
					rest_in_data,
					ctrlist + tmp_data_length,
					key, rest_out_data);
		if (rc)
			return rc;

		memcpy(out_data + tmp_data_length,
		       rest_out_data, rest_data_length);
	}

	return rc;
}

static inline int s390_des_ctr(unsigned int fc, const unsigned char *in_data,
			unsigned char *out_data, unsigned long data_length,
			unsigned char *key, unsigned char *ctr,
			unsigned int ctr_width)
{
	const unsigned char *src;
	unsigned char *tmp_ctrlist = NULL;
	unsigned long chunk_length;
	unsigned long rest_length;
	unsigned long tmp_length;

	int rc = 0;

	if (data_length <= DES_BLOCK_SIZE) {
		/* short message handling */
		rc = s390_des_ctrlist(fc, data_length, in_data, ctr,
				      key, out_data);
		if (rc)
			goto free_out;

		__inc_des_ctr((uint64_t *)ctr, ctr_width);
		return rc;
	}

	/* find largest possible message chunk */
	/* get next multiple of blocksize of data_length */
	chunk_length = NEXT_BS(data_length, DES_BLOCK_SIZE);
	tmp_ctrlist = malloc(chunk_length);

	/* page size chunk fall back */
	if ((!tmp_ctrlist) && (data_length > LARGE_MSG_CHUNK)) {
		chunk_length = LARGE_MSG_CHUNK;
		tmp_ctrlist = malloc(chunk_length);
	}

	/* single block chunk fall back */
	if (!tmp_ctrlist)
		chunk_length = DES_BLOCK_SIZE;

	for (src = in_data, rest_length = data_length;
	     src < (in_data + data_length);
	     src += chunk_length, out_data += chunk_length,
	     rest_length -= chunk_length) {
		tmp_length = (rest_length < chunk_length) ?
			      rest_length : chunk_length;
		if (tmp_ctrlist) {
			__fill_des_ctrlist(tmp_ctrlist,
			    NEXT_BS(tmp_length, DES_BLOCK_SIZE),
			    (uint64_t *)ctr, ctr_width);

			rc = s390_des_ctrlist(fc, tmp_length, src,
					      tmp_ctrlist, key, out_data);
			if (rc)
				goto free_out;
		} else {
			rc = s390_des_ctrlist(fc, tmp_length, src,
					      ctr, key, out_data);
			if (rc)
				goto free_out;

			__inc_des_ctr((uint64_t *)ctr, ctr_width);
		}
	}

free_out:
	if (tmp_ctrlist)
		free(tmp_ctrlist);

	return rc;
}

#endif
