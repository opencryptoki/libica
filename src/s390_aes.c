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
 * Copyright IBM Corp. 2009, 2011
 */

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>

#include "ica_api.h"
#include "icastats.h"
#include "init.h"
#include "s390_crypto.h"
#include "s390_aes.h"
#include "s390_aux.h"

static inline void __memcpy_r_allign(void *dest, int dest_bs,
				     void *src, int src_bs, size_t size)
{
	memcpy(dest + (dest_bs - size), src + (src_bs - size), size);
}

static inline int s390_aes_ecb_hw(unsigned int function_code,
				  unsigned long input_length,
				  const unsigned char *input_data,
				  const unsigned char *keys,
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
				  const unsigned char *keys,
				  unsigned char *output_data)
{
	AES_KEY aes_key;
	unsigned int direction;
	unsigned int key_size = (function_code & 0x0f) *
				sizeof(ica_aes_key_single_t);

	if (function_code & S390_CRYPTO_DIRECTION_MASK) {
		AES_set_decrypt_key(keys, key_size * 8, &aes_key);
		direction = AES_DECRYPT;
	} else {
		AES_set_encrypt_key(keys, key_size * 8, &aes_key);
		direction = AES_ENCRYPT;
	}
	int i;
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

	int rc = 0;
	rc = s390_kmc(function_code, &key_buffer,
		      output_data, input_data, input_length);
	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_aes_vector_t));
		return 0;
	} else
		return EIO;
}

static inline int s390_aes_cbc_sw(unsigned int function_code,
				  unsigned long input_length,
				  const unsigned char *input_data,
				  unsigned char *iv,
				  const unsigned char *keys,
				  unsigned char *output_data)
{
	AES_KEY aes_key;
	unsigned int direction;
	unsigned int key_size = (function_code & 0x0f) *
				sizeof(ica_aes_key_single_t);

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

inline int s390_aes_ecb(unsigned int fc, unsigned long data_length,
			const unsigned char *in_data, const unsigned char *key,
			unsigned char *out_data)
{
	int rc = 1;
	int hardware = 1;

	if (*s390_kmc_functions[fc].enabled)
		rc = s390_aes_ecb_hw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, key,
				     out_data);
	if (rc) {
		rc = s390_aes_ecb_sw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, key,
				     out_data);
		hardware = 0;
	}
	stats_increment((s390_kmc_functions[fc].hw_fc &
			 S390_CRYPTO_DIRECTION_MASK) == 0 ?
			 ICA_STATS_AES_ENCRYPT : ICA_STATS_AES_DECRYPT,
			hardware);
	return rc;
}

inline int s390_aes_cbc(unsigned int fc, unsigned long data_length,
			const unsigned char *in_data, unsigned char *iv,
			const unsigned char *key, unsigned char *out_data)
{
	int rc = 1;
	int hardware = 1;
	
	if (*s390_kmc_functions[fc].enabled)
		rc = s390_aes_cbc_hw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data);
	if (rc) {
		hardware = 0;
		rc = s390_aes_cbc_sw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data);
	}
	stats_increment((s390_kmc_functions[fc].hw_fc &
			 S390_CRYPTO_DIRECTION_MASK) == 0 ?
			 ICA_STATS_AES_ENCRYPT : ICA_STATS_AES_DECRYPT,
			hardware);
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
	int rc = 1;
	int hardware = 1;
	if (*s390_msa4_functions[fc].enabled)
		rc = s390_aes_cfb_hw(s390_msa4_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data, lcfb);
	if (rc) {
		hardware = 0;
		return EPERM;
	}
	stats_increment((s390_msa4_functions[fc].hw_fc &
			S390_CRYPTO_DIRECTION_MASK) == 0 ?
			 ICA_STATS_AES_ENCRYPT : ICA_STATS_AES_DECRYPT,
			hardware);
	return rc;
}

inline int s390_aes_cfb(unsigned int fc, unsigned long data_length,
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

		rc = __s390_aes_cfb(fc, rest_data_length,
				    rest_in_data,
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
	int rc = EPERM;
	int hardware = 1;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_aes_ofb_hw(s390_msa4_functions[fc].hw_fc,
				     input_length, input_data, iv, keys,
				     output_data);
	if (rc) {
		hardware = 0;
		return rc;
	}
	stats_increment((s390_msa4_functions[fc].hw_fc &
			 S390_CRYPTO_DIRECTION_MASK) == 0 ?
			 ICA_STATS_AES_ENCRYPT : ICA_STATS_AES_DECRYPT,
			 hardware);
	return rc;
}

inline int s390_aes_ofb(unsigned int fc, unsigned long data_length,
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

		rc = __s390_aes_ofb(fc, rest_data_length,
				    in_data + tmp_data_length,
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
	__memcpy_r_allign(tmp_in_data, AES_BLOCK_SIZE,
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
		__memcpy_r_allign(tmp_in_data, AES_BLOCK_SIZE,
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
				  const unsigned char *key1,
				  const unsigned char *key2,
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


	/* The iv/tweak is not updated for XTS mode. */
	if (rc < 0)
		return EIO;

	return 0;
}

inline int s390_aes_xts(unsigned int fc, unsigned long data_length,
			const unsigned char *in_data, unsigned char *tweak,
			const unsigned char *key1, const unsigned char *key2,
			unsigned int key_length, unsigned char *out_data)
{
	int rc = 1;
	int hardware = 1;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_aes_xts_hw(s390_msa4_functions[fc].hw_fc,
				     data_length, in_data, tweak,
				     key1, key2, key_length, out_data);
	if (rc) {
		hardware = 0;
		return rc;
	}
	stats_increment((s390_msa4_functions[fc].hw_fc &
			S390_CRYPTO_DIRECTION_MASK) == 0 ?
			ICA_STATS_AES_ENCRYPT : ICA_STATS_AES_DECRYPT, hardware);
	return rc;
}
