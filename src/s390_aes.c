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
#include <openssl/aes.h>
#include <ica_api.h>
#include "include/icastats.h"
#include "include/init.h"
#include "include/s390_crypto.h"
#include "include/s390_aes.h"

static int s390_aes_ecb_hw(unsigned int function_code, unsigned int input_length,
			   unsigned char *input_data, unsigned char *keys,
			   unsigned char *output_data)
{
	struct sigaction oldact;
	sigset_t oldset;

	int rc = 0;
	if ((rc = begin_sigill_section(&oldact, &oldset)) == 0) {

		rc = s390_km(function_code, keys, output_data, input_data,
			     input_length);

		end_sigill_section(&oldact, &oldset);

		if (rc >= 0)
			return 0;
		else
			return EIO;
	}
	return rc;
}

static int s390_aes_ecb_sw(unsigned int function_code, unsigned int input_length,
			   unsigned char *input_data, unsigned char *keys,
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

static int s390_aes_cbc_hw(unsigned int function_code,
			   unsigned int input_length,
			   unsigned char *input_data, ica_aes_vector_t *iv,
			   unsigned char *keys, unsigned char *output_data)
{
	struct sigaction oldact;
	sigset_t oldset;
	struct {
		ica_aes_vector_t iv;
		ica_aes_key_len_256_t keys;
	} key_buffer;

	unsigned int key_size = (function_code & 0x0f) *
				sizeof(ica_aes_key_single_t);

	memcpy(&key_buffer.iv, iv, sizeof(ica_aes_vector_t));
	memcpy(&key_buffer.keys, keys, key_size);

	int rc = 0;
	if ((rc = begin_sigill_section(&oldact, &oldset)) != 0)
		return rc;

	rc = s390_kmc(function_code, &key_buffer,
		      output_data, input_data, input_length);
	end_sigill_section(&oldact, &oldset);

	if (rc >= 0) {
		memcpy(iv, &key_buffer.iv, sizeof(ica_aes_vector_t));
		return 0;
	} else
		return EIO;
}

static int s390_aes_cbc_sw(unsigned int function_code, unsigned int input_length,
			   unsigned char *input_data, ica_aes_vector_t *iv,
			   unsigned char *keys, unsigned char *output_data)
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

int s390_aes_ecb(unsigned int fc, unsigned int input_length,
		 unsigned char *input_data, unsigned char *keys,
		 unsigned char *output_data)
{
	int rc = 1;
	int hardware = 1;
	
	if (*s390_kmc_functions[fc].enabled)
		rc = s390_aes_ecb_hw(s390_kmc_functions[fc].hw_fc, input_length,
				     input_data, keys, output_data);
	if (rc) {
		rc = s390_aes_ecb_sw(s390_kmc_functions[fc].hw_fc, input_length,
				     input_data, keys, output_data);
		hardware = 0;
	}
	stats_increment((s390_kmc_functions[fc].hw_fc & S390_CRYPTO_DIRECTION_MASK) == 0 ?
			 ICA_STATS_AES_ENCRYPT : ICA_STATS_AES_DECRYPT,
			hardware);
	return rc;
}

int s390_aes_cbc(unsigned int fc, unsigned int input_length,
		 unsigned char *input_data, ica_aes_vector_t *iv,
		 unsigned char *keys, unsigned char *output_data)
{
	int rc = 1;
	int hardware = 1;
	
	if (*s390_kmc_functions[fc].enabled)
		rc = s390_aes_cbc_hw(s390_kmc_functions[fc].hw_fc, input_length,
				     input_data, iv, keys, output_data);
	if (rc) {
		hardware = 0;
		rc = s390_aes_cbc_sw(s390_kmc_functions[fc].hw_fc, input_length,
				     input_data, iv, keys, output_data);
	}
	stats_increment((s390_kmc_functions[fc].hw_fc & S390_CRYPTO_DIRECTION_MASK) == 0 ?
			 ICA_STATS_AES_ENCRYPT : ICA_STATS_AES_DECRYPT,
			hardware);
	return rc;
}

