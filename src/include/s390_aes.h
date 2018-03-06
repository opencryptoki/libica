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

#ifndef S390_AES_H
#define S390_AES_H
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <stdlib.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "fips.h"
#include "ica_api.h"
#include "icastats.h"
#include "init.h"
#include "s390_crypto.h"
#include "s390_ctr.h"

#define AES_BLOCK_SIZE 16
#define GCM_RECOMMENDED_IV_LENGTH 12

#define HS_FLAG		0x400;
#define LAAD_FLAG	0x200;
#define LPC_FLAG	0x100;


static inline int s390_aes_gcm_hw(unsigned int function_code,
				  const unsigned char *input_data,
				  unsigned char *output_data,
				  unsigned long input_length,
				  unsigned char *key, unsigned char *j0,
				  unsigned char *ctr,
				  const unsigned char *aad,
				  unsigned long aad_length,
				  const unsigned char *subkey_h,
				  unsigned char *tag,
				  unsigned int laad, unsigned int lpc)
{
	struct {
		char reserved[12];
		unsigned int cv;
		ica_aes_vector_t tag;
		ica_aes_vector_t subkey_h;
		unsigned long long total_aad_length;
		unsigned long long total_input_length;
		ica_aes_vector_t j0;
		ica_aes_key_len_256_t key;
	} parm_block;

	int rc;
	unsigned int key_size = (function_code & 0x0f) * sizeof(ica_aes_key_single_t);

	memset(&parm_block, 0, sizeof(parm_block));
	memcpy(&parm_block.tag, tag, AES_BLOCK_SIZE);
	memcpy(&parm_block.subkey_h, subkey_h, AES_BLOCK_SIZE);
	memcpy(&parm_block.key, key, key_size);

	if (laad && lpc) {
		// total length in bits
		parm_block.total_aad_length = aad_length * 8;

		// total length in bits
		parm_block.total_input_length = input_length * 8;

		parm_block.cv = input_length / AES_BLOCK_SIZE + 1;
	}

	if (ctr) {
		memcpy(&parm_block.cv, &ctr[GCM_RECOMMENDED_IV_LENGTH],
		       sizeof(parm_block.cv));
		memcpy(&parm_block.j0, ctr, AES_BLOCK_SIZE);
	}

	if (j0)
		memcpy(&parm_block.j0, j0, AES_BLOCK_SIZE);

	// Set flags ...
	function_code = function_code | HS_FLAG;  // subkey flag is always = 1
	if (laad)
		function_code = function_code | LAAD_FLAG;
	if (lpc)
		function_code = function_code | LPC_FLAG;

	if (input_data == NULL)
		input_length = 0;
	if (aad == NULL)
		aad_length = 0;
	if (input_length == 0 && aad_length == 0)
		parm_block.cv++;

	rc = s390_kma(function_code, &parm_block, output_data, input_data,
		      input_length, aad, aad_length);

	if (rc >= 0) {
		memcpy(tag, &parm_block.tag, AES_BLOCK_SIZE);
		if (ctr) {
			// not in last call
			memcpy(&ctr[GCM_RECOMMENDED_IV_LENGTH], &parm_block.cv,
			       sizeof(parm_block.cv));
		}
		return 0;
	} else {
		return EIO;
	}
}

static inline int s390_aes_gcm(unsigned int fc, const unsigned char *in_data,
			unsigned char *out_data, unsigned long data_length,
			unsigned char *key, unsigned char *j0,
			unsigned char *ctr,
			const unsigned char *aad, unsigned long aad_length,
			unsigned char *subkey_h, unsigned char *tag,
			unsigned int laad, unsigned int lpc)
{
	int rc = ENODEV;

	if (*s390_kma_functions[fc].enabled) {
		rc = s390_aes_gcm_hw(s390_kma_functions[fc].hw_fc, in_data,
				     out_data, data_length, key, j0, ctr, aad,
				     aad_length, subkey_h, tag, laad, lpc);
	}
	if (rc)
		return rc;

	stats_increment(ICA_STATS_AES_GCM,
			ALGO_HW,
			(s390_kma_functions[fc].hw_fc &
			S390_CRYPTO_DIRECTION_MASK) == 0 ?
			ENCRYPT:DECRYPT);

	return 0;
}

static inline int __s390_aes_ctrlist(unsigned int fc, unsigned long data_length,
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

	stats_increment(ICA_STATS_AES_CTR, ALGO_HW,
			 (s390_msa4_functions[fc].hw_fc &
			 S390_CRYPTO_DIRECTION_MASK) ==
			 0 ?ENCRYPT:DECRYPT);
	return 0;
}



static inline int s390_aes_ctrlist(unsigned int fc, unsigned long data_length,
			    const unsigned char *in_data,
			    const unsigned char *ctrlist,
			    unsigned char *key, unsigned char *out_data)
{
	int rc = 0;
	unsigned char rest_in_data[AES_BLOCK_SIZE];
	unsigned char rest_out_data[AES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % AES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length;

	if (tmp_data_length) {
		rc = __s390_aes_ctrlist(fc, tmp_data_length, in_data,
					ctrlist, key, out_data);
		if (rc)
			return rc;
	}

	if (rest_data_length) {
		memcpy(rest_in_data, in_data + tmp_data_length,
		       rest_data_length);

		rc = __s390_aes_ctrlist(fc, AES_BLOCK_SIZE,
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

static inline int s390_aes_ctr(unsigned int fc, const unsigned char *in_data,
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

	if (data_length == 0)
		return 0;

	if (data_length <= AES_BLOCK_SIZE) {
		/* short message handling */
		rc = s390_aes_ctrlist(fc, data_length, in_data, ctr,
				      key, out_data);
		if (rc)
			goto free_out;

		__inc_aes_ctr((struct uint128 *)ctr,  ctr_width);
		return rc;
	}

	/* find largest possible message chunk */
	chunk_length = NEXT_BS(data_length, AES_BLOCK_SIZE);
	tmp_ctrlist = malloc(chunk_length);

	/* page size chunk fall back */
	if ((!tmp_ctrlist) && (data_length > LARGE_MSG_CHUNK)) {
		chunk_length = LARGE_MSG_CHUNK;
		tmp_ctrlist = malloc(chunk_length);
	}

	/* single block chunk fall back */
	if (!tmp_ctrlist)
		chunk_length = AES_BLOCK_SIZE;

	for (src = in_data, rest_length = data_length;
	     src < (in_data + data_length);
	     src += chunk_length, out_data += chunk_length,
	     rest_length -= chunk_length) {
		tmp_length = (rest_length < chunk_length) ?
			      rest_length : chunk_length;
		if (tmp_ctrlist) {
			__fill_aes_ctrlist(tmp_ctrlist,
			    NEXT_BS(tmp_length, AES_BLOCK_SIZE),
			    (struct uint128 *)ctr, ctr_width);

			rc = s390_aes_ctrlist(fc, tmp_length, src,
					      tmp_ctrlist, key, out_data);
			if (rc)
				goto free_out;
		} else {
			/* single block fall back */
			rc = s390_aes_ctrlist(fc, tmp_length, src,
					      ctr, key, out_data);
			if (rc)
				goto free_out;

			__inc_aes_ctr((struct uint128 *)ctr, ctr_width);
		}
	}

free_out:
	if (tmp_ctrlist)
		free(tmp_ctrlist);

	return rc;
}

static inline int s390_aes_ecb_hw(unsigned int function_code,
				  unsigned long input_length,
				  const unsigned char *input_data,
				  unsigned char *keys,
				  unsigned char *output_data)
{
	int rc = 0;
	rc = s390_km(function_code, keys, output_data, input_data,
		     input_length);
	if (rc >= 0)
		return 0;
	else
		return EIO;
}

static inline int s390_aes_ecb_sw(unsigned int function_code,
				  unsigned long input_length,
				  const unsigned char *input_data,
				  unsigned char *keys,
				  unsigned char *output_data)
{
	AES_KEY aes_key;
	unsigned long i;
	unsigned int direction;
	unsigned int key_size = (function_code & 0x0f) *
				sizeof(ica_aes_key_single_t);

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	if (function_code & S390_CRYPTO_DIRECTION_MASK) {
		AES_set_decrypt_key(keys, key_size * 8, &aes_key);
		direction = AES_DECRYPT;
	} else {
		AES_set_encrypt_key(keys, key_size * 8, &aes_key);
		direction = AES_ENCRYPT;
	}

	for (i = 0; i < input_length; i += AES_BLOCK_SIZE) {
		AES_ecb_encrypt(input_data + i, output_data + i,
				&aes_key, direction);
	}

	return 0;
}

static inline int s390_aes_cbc_hw(unsigned int function_code,
				  unsigned long input_length,
				  const unsigned char *input_data,
				  unsigned char *iv,
				  unsigned char *keys,
				  unsigned char *output_data)
{
	struct {
		ica_aes_vector_t iv;
		ica_aes_key_len_256_t keys;
	} key_buffer;
	unsigned int key_size = (function_code & 0x0f) *
				sizeof(ica_aes_key_single_t);

	memcpy(&key_buffer.iv, iv, sizeof(ica_aes_vector_t));
	memcpy(&key_buffer.keys, keys, key_size);

	int rc = 0;
	rc = s390_kmc(function_code, &key_buffer,
		      output_data, input_data, input_length);

	memset(&key_buffer.keys, 0, key_size);

	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_aes_vector_t));
		return 0;
	} else {
		return EIO;
	}
}

static inline int s390_aes_cbc_sw(unsigned int function_code,
				  unsigned long input_length,
				  const unsigned char *input_data,
				  unsigned char *iv,
				  unsigned char *keys,
				  unsigned char *output_data)
{
	AES_KEY aes_key;
	unsigned int direction;
	unsigned int key_size = (function_code & 0x0f) *
				sizeof(ica_aes_key_single_t);

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	if (function_code & S390_CRYPTO_DIRECTION_MASK) {
		AES_set_decrypt_key(keys, key_size * 8, &aes_key);
		direction = AES_DECRYPT;
	} else {
		AES_set_encrypt_key(keys, key_size * 8, &aes_key);
		direction = AES_ENCRYPT;
	}
	AES_cbc_encrypt(input_data, output_data, input_length,
			&aes_key, (unsigned char *) iv, direction);

	return 0;
}

static inline int s390_aes_ecb(unsigned int fc, unsigned long data_length,
			const unsigned char *in_data, unsigned char *key,
			unsigned char *out_data)
{
	int rc = ENODEV;
	int hardware = ALGO_HW;

	if (*s390_kmc_functions[fc].enabled)
		rc = s390_aes_ecb_hw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, key,
				     out_data);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_aes_ecb_sw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, key,
				     out_data);
		hardware = ALGO_SW;
	}
	stats_increment(ICA_STATS_AES_ECB,
			hardware,
			(s390_kmc_functions[fc].hw_fc &
			S390_CRYPTO_DIRECTION_MASK) == 0 ?
			ENCRYPT:DECRYPT);
	return rc;
}

static inline int s390_aes_cbc(unsigned int fc, unsigned long data_length,
			const unsigned char *in_data, unsigned char *iv,
			unsigned char *key, unsigned char *out_data)
{
	int rc = ENODEV;
	int hardware = ALGO_HW;

	if (*s390_kmc_functions[fc].enabled)
		rc = s390_aes_cbc_hw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_aes_cbc_sw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data);
		hardware = ALGO_SW;
	}
	stats_increment(ICA_STATS_AES_CBC,
			hardware, (s390_kmc_functions[fc].hw_fc &
			S390_CRYPTO_DIRECTION_MASK) == 0 ?
			ENCRYPT:DECRYPT);
	return rc;
}

static inline int s390_aes_cfb_hw(unsigned int function_code,
				  unsigned long input_length,
				  const unsigned char *input_data,
				  unsigned char *iv,
				  const unsigned char *keys,
				  unsigned char *output_data,
				  unsigned int lcfb)
{
	struct {
		ica_aes_vector_t iv;
		ica_aes_key_len_256_t keys;
	} key_buffer;

	unsigned int key_size = (function_code & 0x0f) *
				sizeof(ica_aes_key_single_t);

	memcpy(&key_buffer.iv, iv, sizeof(ica_aes_vector_t));
	memcpy(&key_buffer.keys, keys, key_size);

	int rc = -1;
	rc = s390_kmf(function_code, &key_buffer,
		      output_data, input_data, input_length, &lcfb);

	memset(&key_buffer.keys, 0, key_size);

	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_aes_vector_t));
		return 0;
	} else
		return EIO;
}

static inline int __s390_aes_cfb(unsigned int fc, unsigned long data_length,
				 const unsigned char *in_data,
				 unsigned char *iv, const unsigned char *key,
				 unsigned char *out_data, unsigned int lcfb)
{
	int rc = ENODEV;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_aes_cfb_hw(s390_msa4_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data, lcfb);
	if (rc)
		return rc;

	stats_increment(ICA_STATS_AES_CFB, ALGO_HW,
			(s390_kmc_functions[fc].hw_fc &
			S390_CRYPTO_DIRECTION_MASK) == 0 ?
			ENCRYPT:DECRYPT);

	return 0;
}

static inline int s390_aes_cfb(unsigned int fc, unsigned long data_length,
			const unsigned char *in_data, unsigned char *iv,
			const unsigned char *key, unsigned char *out_data,
			unsigned int lcfb)
{
	int rc = 0;
	/* Temporary buffers with size of lcfb should be
	 * sufficiant, using static maximum lcfb instead. */
	unsigned char rest_in_data[AES_BLOCK_SIZE];
	unsigned char rest_out_data[AES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % lcfb;
	tmp_data_length = data_length - rest_data_length;

	if (tmp_data_length) {
		rc = __s390_aes_cfb(fc, tmp_data_length, in_data,
				    iv, key, out_data, lcfb);
		if (rc)
			return rc;
	}

	if (rest_data_length) {
		memcpy(rest_in_data, in_data + tmp_data_length,
		       rest_data_length);

		rc = __s390_aes_cfb(fc, lcfb, rest_in_data,
				    iv, key, rest_out_data, lcfb);
		if (rc)
			return rc;

		memcpy(out_data + tmp_data_length,
		       rest_out_data, rest_data_length);
	}

	return rc;
}

static inline int s390_aes_ofb_hw(unsigned int function_code,
				  unsigned long input_length,
				  const unsigned char *input_data,
				  unsigned char *iv,
				  const unsigned char *keys,
				  unsigned char *output_data)
{
	struct {
		ica_aes_vector_t iv;
		ica_aes_key_len_256_t keys;
	} key_buffer;

	unsigned int key_size = (function_code & 0x0f) *
				sizeof(ica_aes_key_single_t);

	memcpy(&key_buffer.iv, iv, sizeof(ica_aes_vector_t));
	memcpy(&key_buffer.keys, keys, key_size);

	int rc = -1;

	rc = s390_kmo(function_code, &key_buffer,
		      output_data, input_data, input_length);

	memset(&key_buffer.keys, 0, key_size);

	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_aes_vector_t));
		return 0;
	} else
		return EIO;
}

static inline int __s390_aes_ofb(unsigned int fc, unsigned long input_length,
				 const unsigned char *input_data,
				 unsigned char *iv, const unsigned char *keys,
				 unsigned char *output_data)
{
	int rc = ENODEV;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_aes_ofb_hw(s390_msa4_functions[fc].hw_fc,
				     input_length, input_data, iv, keys,
				     output_data);
	if (rc)
		return rc;

	stats_increment(ICA_STATS_AES_OFB, ALGO_HW,
			(s390_kmc_functions[fc].hw_fc &
			S390_CRYPTO_DIRECTION_MASK) == 0 ?
			ENCRYPT:DECRYPT);
	return 0;
}

static inline int s390_aes_ofb(unsigned int fc, unsigned long data_length,
			const unsigned char *in_data,
			unsigned char *iv, const unsigned char *key,
			unsigned char *out_data)
{
	int rc = 0;
	unsigned char rest_in_data[AES_BLOCK_SIZE];
	unsigned char rest_out_data[AES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % AES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length;

	if (tmp_data_length) {
		rc = __s390_aes_ofb(fc, tmp_data_length, in_data,
				    iv, key, out_data);
		if (rc)
			return rc;
	}

	if (rest_data_length) {
		memcpy(rest_in_data, in_data + tmp_data_length,
		       rest_data_length);

		rc = __s390_aes_ofb(fc, AES_BLOCK_SIZE,
				    rest_in_data,
				    iv, key, rest_out_data);
		if (rc)
			return rc;

		memcpy(out_data + tmp_data_length,
		       rest_out_data, rest_data_length);
	}

	return rc;
}

static inline int s390_aes_xts_parm(unsigned long function_code,
				    unsigned int key_size, unsigned char *key,
				    unsigned char *xts_parm)
{
	int rc = 0;
	struct {
		unsigned char keys[key_size];
		ica_aes_vector_t tweak;
		unsigned char block_seq[sizeof(ica_aes_vector_t)];
		unsigned char intermediate_bit_idx[sizeof(ica_aes_vector_t)];
		unsigned char xts_parameter[sizeof(ica_aes_vector_t)];
	} parm_block;

	memset(parm_block.block_seq, 0x00, sizeof(parm_block.block_seq));
	memcpy(&parm_block.tweak, xts_parm,
	       sizeof(parm_block.tweak));
	memcpy(&parm_block.keys, key, key_size);
	memset(parm_block.intermediate_bit_idx, 0x00,
	       sizeof(parm_block.intermediate_bit_idx));

	/* In PCC we do not differentiate between encryption and decryption */
	rc = s390_pcc(function_code & 0x7f, &parm_block);

	memset(&parm_block.keys, 0, key_size);

	if (rc >= 0) {
		memcpy(xts_parm, parm_block.xts_parameter,
		       sizeof(ica_aes_vector_t));
		return 0;
	} else
		return EIO;
}

static inline int s390_aes_xts_msg_dec(unsigned long function_code,
				       unsigned long data_length,
				       const unsigned char *in_data,
				       unsigned char *out_data, void *param,
				       unsigned int key_size)
{
	int rc;
	unsigned char tmp_in_data[AES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;
	struct {
		unsigned char keys[key_size];
		ica_aes_vector_t iv;
	} tmp_param;

	rest_data_length = data_length % AES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length - AES_BLOCK_SIZE;

	if (rest_data_length == 0) {
		/* complete msg handling */
		rc = s390_km(function_code, param,
			     out_data, in_data, data_length);
		if (rc < 0)
			return EIO;

		return rc;
	}

	if (tmp_data_length) {
		rc = s390_km(function_code, param,
			     out_data, in_data, tmp_data_length);
		if (rc < 0)
			return EIO;
	}

	/* backup iv n-1 */
	memcpy(&tmp_param, param, sizeof(tmp_param));

	/* dummy step to calculate iv n */
	rc = s390_km(function_code, param, out_data + tmp_data_length, in_data + tmp_data_length, AES_BLOCK_SIZE);
	if (rc < 0)
		return EIO;

	/* block n-1 (with iv n) */
	rc = s390_km(function_code, param, out_data + tmp_data_length, in_data + tmp_data_length, AES_BLOCK_SIZE);
	if (rc < 0)
		return EIO;

	memcpy(tmp_in_data,
	       in_data + tmp_data_length + AES_BLOCK_SIZE,
	       rest_data_length);
	memcpy_r_allign(tmp_in_data, AES_BLOCK_SIZE,
			out_data + tmp_data_length, AES_BLOCK_SIZE,
			AES_BLOCK_SIZE - rest_data_length);
	memcpy(out_data + tmp_data_length + AES_BLOCK_SIZE,
	       out_data + tmp_data_length, rest_data_length);

	/* block n (with iv n-1) */
	rc = s390_km(function_code, &tmp_param,
		     out_data + tmp_data_length,
		     tmp_in_data, AES_BLOCK_SIZE);
	if (rc < 0)
		return EIO;

	return rc;
}

static inline int s390_aes_xts_msg_enc(unsigned long function_code,
				       unsigned long data_length,
				       const unsigned char *in_data,
				       unsigned char *out_data, void *param)
{
	int rc;
	unsigned char tmp_in_data[AES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % AES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length;

	/* tmp_data_length is at least AES_BLOCK_SIZE */
	rc = s390_km(function_code, param,
		     out_data, in_data, tmp_data_length);
	if (rc < 0)
		return EIO;

	if (rest_data_length) {
		/* XTS cipher text stealing for uncomplete blocks */
		memcpy(tmp_in_data,
		       in_data + tmp_data_length,
		       rest_data_length);
		memcpy_r_allign(tmp_in_data, AES_BLOCK_SIZE,
				out_data + (tmp_data_length - AES_BLOCK_SIZE),
				AES_BLOCK_SIZE,
				AES_BLOCK_SIZE - rest_data_length);
		memcpy(out_data + tmp_data_length,
		       out_data + (tmp_data_length - AES_BLOCK_SIZE),
		       rest_data_length);

		rc = s390_km(function_code, param,
			     out_data + (tmp_data_length - AES_BLOCK_SIZE),
			     tmp_in_data, AES_BLOCK_SIZE);
		if (rc < 0)
			return EIO;
	}

	return rc;
}

static inline int s390_aes_xts_hw(unsigned int function_code,
				  unsigned long input_length,
				  const unsigned char *input_data,
				  unsigned char *tweak,
				  unsigned char *key1,
				  unsigned char *key2,
				  unsigned int key_size,
				  unsigned char *output_data)
{
	int rc = -1;
	/* This works similar as AES CBC, but uses km instead of kmc. Also we
	 * need to specify the parameter block in order with key first and
	 * XTS parameter behind. */
	struct {
		unsigned char keys[key_size];
		ica_aes_vector_t iv;
	} key_buffer;

	memcpy(key_buffer.keys, key1, key_size);
	memcpy(&key_buffer.iv, tweak, sizeof(ica_aes_vector_t));

	/* Get XTS parameter through PCC first. */
	rc = s390_aes_xts_parm(function_code, key_size, key2,
			       (unsigned char *) &key_buffer.iv);
	if (rc)
		return EIO;

	if (function_code & S390_CRYPTO_DIRECTION_MASK)
		rc = s390_aes_xts_msg_dec(function_code, input_length,
					  input_data, output_data, &key_buffer,
					  key_size);
	else
		rc = s390_aes_xts_msg_enc(function_code, input_length,
					  input_data, output_data, &key_buffer);

	memset(key_buffer.keys, 0, key_size);

	/* The iv/tweak is not updated for XTS mode. */
	if (rc < 0)
		return EIO;

	return 0;
}

static inline int s390_aes_xts(unsigned int fc, unsigned long data_length,
			const unsigned char *in_data, unsigned char *tweak,
			unsigned char *key1, unsigned char *key2,
			unsigned int key_length, unsigned char *out_data)
{
	int rc = ENODEV;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_aes_xts_hw(s390_msa4_functions[fc].hw_fc,
				     data_length, in_data, tweak,
				     key1, key2, key_length, out_data);
	if (rc)
		return rc;

	stats_increment(ICA_STATS_AES_XTS, ALGO_HW,
			(s390_kmc_functions[fc].hw_fc &
			S390_CRYPTO_DIRECTION_MASK) == 0 ?
			ENCRYPT:DECRYPT);

	return 0;
}
#endif
