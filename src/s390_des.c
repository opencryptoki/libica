/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2009
 */

#include <string.h>
#include <errno.h>
#include <openssl/des.h>
#include <ica_api.h>
#include "include/icastats.h"
#include "include/init.h"
#include "include/s390_crypto.h"
#include "include/s390_des.h"

int s390_des_ecb_hw(unsigned int function_code, unsigned int input_length,
		    unsigned char *input_data, unsigned char *keys,
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


int s390_des_ecb_sw(unsigned int function_code, unsigned int input_length,
		    unsigned char *input_data, unsigned char *keys,
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


static int s390_des_cbc_hw(unsigned int function_code, unsigned int input_length,
			   unsigned char *input_data, ica_des_vector_t *iv,
			   unsigned char *keys, unsigned char *output_data)
{
	struct {
		ica_des_vector_t iv;
		ica_des_key_triple_t keys;
	} key_buffer;

	int rc = 0;
	unsigned int key_size = (function_code & S390_CRYPTO_FUNCTION_MASK) *
	    sizeof(ica_des_key_single_t);
	memcpy(&key_buffer.iv, iv, sizeof(ica_des_vector_t));
	memcpy(&key_buffer.keys, keys, key_size);

	rc = s390_kmc(function_code, &key_buffer, output_data, input_data,
		      input_length);
	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_des_vector_t));
		return 0;
	} else
		rc = EIO;
}


static int s390_des_cbc_sw(unsigned int function_code, unsigned int input_length,
			   unsigned char *input_data, ica_des_vector_t *iv,
			   unsigned char *keys, unsigned char *output_data)
{
	DES_key_schedule key_schedule1;
	DES_key_schedule key_schedule2;
	DES_key_schedule key_schedule3;
	switch (function_code & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		DES_set_key_unchecked((const_DES_cblock *) keys,
				      &key_schedule1);
		DES_ncbc_encrypt(input_data, output_data, input_length,
				 &key_schedule1, iv,
				 (function_code & S390_CRYPTO_DIRECTION_MASK) ?
				 0 : 1);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
		DES_set_key_unchecked((const_DES_cblock *) keys,
				      &key_schedule1);
		DES_set_key_unchecked((const_DES_cblock *) keys + 1,
				      &key_schedule2);
		DES_ede2_cbc_encrypt(input_data, output_data, input_length,
				     &key_schedule1, &key_schedule2, iv,
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
				     &key_schedule3, iv,
				     (function_code &
				      S390_CRYPTO_DIRECTION_MASK) ? 0 : 1);
		break;
	};

	return 0;
}

int s390_des_ecb(unsigned int fc, unsigned int input_length,
		 unsigned char *input_data, unsigned char *keys,
		 unsigned char *output_data)
{
	int rc = 1;
	int hardware = 1;

	if (*s390_kmc_functions[fc].enabled)
		rc = s390_des_ecb_hw(s390_kmc_functions[fc].hw_fc,
				     input_length, input_data, keys,
				     output_data);
	if (rc) {
		rc = s390_des_ecb_sw(s390_kmc_functions[fc].hw_fc,
				     input_length, input_data, keys,
				     output_data);
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

int s390_des_cbc(unsigned int fc, unsigned int input_length,
		 unsigned char *input_data, ica_des_vector_t *iv,
		 unsigned char *keys, unsigned char *output_data)
{
	int rc = 1;
	int hardware = 1;

	if (*s390_kmc_functions[fc].enabled)
		rc = s390_des_cbc_hw(s390_kmc_functions[fc].hw_fc,
				     input_length, input_data, iv, keys,
				     output_data);
	if (rc) {
		rc = s390_des_cbc_sw(s390_kmc_functions[fc].hw_fc,
				     input_length, input_data, iv, keys,
				     output_data);
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

