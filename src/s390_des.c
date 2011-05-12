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

#include <string.h>
#include <errno.h>
#include <openssl/des.h>

#include "ica_api.h"
#include "icastats.h"
#include "init.h"
#include "s390_crypto.h"
#include "s390_des.h"

int s390_des_ecb_hw(unsigned int function_code, unsigned long input_length,
		    const unsigned char *input_data, const unsigned char *keys,
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


int s390_des_ecb_sw(unsigned int function_code, unsigned long input_length,
		    const unsigned char *input_data, const unsigned char *keys,
		    unsigned char *output_data)
{
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

	return 0;
}


static int s390_des_cbc_hw(unsigned int function_code,
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
	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_des_vector_t));
		return 0;
	} else
		return EIO;
}


static int s390_des_cbc_sw(unsigned int function_code,
			   unsigned long input_length,
			   const unsigned char *input_data, unsigned char *iv,
			   const unsigned char *keys, unsigned char *output_data)
{
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

	return 0;
}

int s390_des_ecb(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, const unsigned char *key,
		 unsigned char *out_data)
{
	int rc = 1;
	int hardware = 1;

	if (*s390_kmc_functions[fc].enabled)
		rc = s390_des_ecb_hw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, key,
				     out_data);
	if (rc) {
		rc = s390_des_ecb_sw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, key,
				     out_data);
		hardware = 0;
	}

	switch (s390_kmc_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment((s390_kmc_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_DES_ENCRYPT :
				ICA_STATS_DES_DECRYPT, hardware);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment((s390_kmc_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_3DES_ENCRYPT :
				ICA_STATS_3DES_DECRYPT, hardware);
		break;
	}
	
	return rc;
}

int s390_des_cbc(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, unsigned char *iv,
		 const unsigned char *key, unsigned char *out_data)
{
	int rc = 1;
	int hardware = 1;

	if (*s390_kmc_functions[fc].enabled)
		rc = s390_des_cbc_hw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data);
	if (rc) {
		rc = s390_des_cbc_sw(s390_kmc_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data);
		hardware = 0;
	}

	switch (s390_kmc_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment((s390_kmc_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_DES_ENCRYPT :
				ICA_STATS_DES_DECRYPT, hardware);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment((s390_kmc_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_3DES_ENCRYPT :
				ICA_STATS_3DES_DECRYPT, hardware);
		break;
	}
	return rc;
}

static int s390_des_cfb_hw(unsigned int function_code,
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
	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_des_vector_t));
		return 0;
	} else
		return EIO;
}

static int __s390_des_cfb(unsigned int fc, unsigned long data_length,
			  const unsigned char *in_data, unsigned char *iv,
			  const unsigned char *key, unsigned char *out_data,
			  unsigned int lcfb)
{
	int rc = 1;
	int hardware = 1;
	if (*s390_msa4_functions[fc].enabled)
		rc = s390_des_cfb_hw(s390_msa4_functions[fc].hw_fc,
				     data_length, in_data, iv, key,
				     out_data, lcfb);
	if (rc) {
		hardware = 0;
		return EPERM;
	}
	switch (s390_msa4_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment((s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_DES_ENCRYPT :
				ICA_STATS_DES_DECRYPT, hardware);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment((s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_3DES_ENCRYPT :
				ICA_STATS_3DES_DECRYPT, hardware);
		break;
	}
	return rc;
}

int s390_des_cfb(unsigned int fc, unsigned long data_length,
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

		rc = __s390_des_cfb(fc, rest_data_length,
				    rest_in_data,
				    iv, key, rest_out_data, lcfb);
		if (rc)
			return rc;

		memcpy(out_data + tmp_data_length,
		       rest_out_data, rest_data_length);
	}

	return rc;
}

static int s390_des_ofb_hw(unsigned int function_code,
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
	int rc = 1;
	int hardware = 1;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_des_ofb_hw(s390_msa4_functions[fc].hw_fc,
				     input_length, input_data, iv, keys,
				     output_data);
	if (rc) {
		hardware = 0;
		return rc;
	}
	switch (s390_msa4_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment((s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_DES_ENCRYPT :
				ICA_STATS_DES_DECRYPT, hardware);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment((s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_3DES_ENCRYPT :
				ICA_STATS_3DES_DECRYPT, hardware);
		break;
	}
	return rc;
}

inline int s390_des_ofb(unsigned int fc, unsigned long data_length,
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

		rc = __s390_des_ofb(fc, rest_data_length,
				    rest_in_data,
				    iv, key, rest_out_data);
		if (rc)
			return rc;

		memcpy(out_data + tmp_data_length,
		       rest_out_data, rest_data_length);
	}

	return rc;
}
