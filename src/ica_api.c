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

#define __USE_GNU
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/types.h>
#include "ica_api.h"

#include "include/icastats.h"
#include "include/s390_rsa.h"
#include "include/s390_crypto.h"
#include "include/s390_sha.h"
#include "include/s390_prng.h"
#include "include/s390_des.h"
#include "include/s390_aes.h"

#define DEFAULT_CRYPT_DEVICE "/udev/z90crypt"
#define DEFAULT2_CRYPT_DEVICE "/dev/z90crypt"
#define DEFAULT3_CRYPT_DEVICE "/dev/zcrypt"
#define DRIVER_NOT_LOADED -1

static unsigned int check_des_parms(unsigned int mode,
				    unsigned int data_length,
				    unsigned char *input_data,
				    ica_des_vector_t *iv,
				    ica_des_key_triple_t *des_key,
				    unsigned char *output_data)
{
	/* check for obvious errors in parms */
	/* data_length: Length of the cypher block has to be a multiple of
	 * 8 bytes.
	 */
	if ((input_data == NULL) ||
	    ((iv == NULL) && (mode == MODE_CBC)) ||
	    (des_key == NULL) ||
	    (output_data == NULL) ||
	    (data_length & 0x07) ||
	    ((mode != MODE_ECB) && (mode != MODE_CBC)))
		return EINVAL;

	return 0;
}

static unsigned int check_aes_parms(unsigned int mode,
				    unsigned int data_length,
				    unsigned char *input_data,
				    ica_aes_vector_t *iv,
				    unsigned int key_length,
				    unsigned char *aes_key,
				    unsigned char *output_data)
{
	/* check for obvious errors in parms */
	/* FIPS 197 standard requires a block length of 16 byte */
	if ((input_data == NULL) ||
	    ((iv == NULL) && (mode == MODE_CBC)) ||
	    (key_length < 16) ||
	    (key_length > 32) ||
	    (aes_key == NULL) ||
	    (data_length & 0x0F ) ||
	    (output_data == NULL) ||
	    ((mode != MODE_ECB) && (mode != MODE_CBC)))
		return EINVAL;

	return 0;
}

static unsigned int check_message_part(unsigned int message_part)
{
	if (message_part != SHA_MSG_PART_ONLY &&
	    message_part != SHA_MSG_PART_FIRST &&
	    message_part != SHA_MSG_PART_MIDDLE &&
	    message_part != SHA_MSG_PART_FINAL)
		return EINVAL;
	else
		return 0;
}

unsigned int ica_open_adapter(ica_adapter_handle_t *adapter_handle)
{
	char *name;

	if (!adapter_handle)
		return EINVAL;

	*adapter_handle = DRIVER_NOT_LOADED;
	name = getenv("LIBICA_CRYPT_DEVICE");
	if (name)
		*adapter_handle = open(name, O_RDWR);
	else {
		*adapter_handle = open(DEFAULT_CRYPT_DEVICE, O_RDWR);
		if (*adapter_handle == -1)
			*adapter_handle = open(DEFAULT2_CRYPT_DEVICE, O_RDWR);
		if (*adapter_handle == -1)
			*adapter_handle = open(DEFAULT3_CRYPT_DEVICE, O_RDWR);
	}
	if (*adapter_handle != -1) {
		char status_mask[64];
		/* Test if character device is accessible. */
		if (!ioctl(*adapter_handle, Z90STAT_STATUS_MASK, &status_mask)) {
			return 0;
		}
	}

	/*
	 * Do not fail if crypto device driver is not loaded and CPACF is not
	 * available as the software fallback will still work without an adapter
	 * handle.
	 */
	return 0;
}

unsigned int ica_close_adapter(ica_adapter_handle_t adapter_handle)
{
	if (adapter_handle == DRIVER_NOT_LOADED)
		return 0;
	if (close(adapter_handle))
		return errno;

	return 0;
}

unsigned int ica_sha1(unsigned int message_part,
		      unsigned int input_length,
		      unsigned char *input_data,
		      sha_context_t *sha_context,
		      unsigned char *output_data)
{
	int rc;

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (sha_context == NULL) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/* check for maximum and minimum input data length */
	/* if this is the first or middle part, the input */
	/*   data length must be a multiple of 64 bytes   */
	if ((input_length & 0x3f) &&
	    ((message_part == SHA_MSG_PART_FIRST) ||
	     (message_part == SHA_MSG_PART_MIDDLE)))
		return EINVAL;

	/*
	 * If this is the middle or final part, the running
	 * length should not be zero
	 */
	rc = s390_sha1((unsigned char *) &sha_context->shaHash,
			input_data, input_length, output_data, message_part,
			(uint64_t *) &sha_context->runningLength);

	if (!rc)
		memcpy(&sha_context->shaHash, output_data, LENGTH_SHA_HASH);

	return rc;
}

unsigned int ica_sha224(unsigned int message_part,
	 		unsigned int input_length,
	 		unsigned char *input_data,
	 		sha256_context_t *sha256_context,
			unsigned char *output_data)
{
	unsigned int rc;

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (sha256_context == NULL) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 64 bytes.
	 */
	if (input_length & 0x3f &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE))
		return EINVAL;
	
	return s390_sha224((unsigned char *) &sha256_context->sha256Hash,
			   input_data, input_length, output_data, message_part,
			   (uint64_t *)&sha256_context->runningLength);
}

unsigned int ica_sha256(unsigned int message_part,
			unsigned int input_length,
			unsigned char *input_data,
			sha256_context_t *sha256_context,
			unsigned char *output_data)
{
	unsigned int rc;

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (sha256_context == NULL) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 64 bytes.
	 */
	if (input_length & 0x3f &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE))
		return EINVAL;

	return s390_sha256((unsigned char *) &sha256_context->sha256Hash,
			   input_data, input_length, output_data, message_part,
			   (uint64_t *) &sha256_context->runningLength);
}

unsigned int ica_sha384(unsigned int message_part,
			uint64_t input_length,
			unsigned char *input_data,
			SHA512_CONTEXT *sha512_context,
			unsigned char *output_data)
{
	unsigned int rc;

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (sha512_context == NULL) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 128 bytes.
	 */
	if (input_length & 0x7f &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE))
		return EINVAL;

	return s390_sha384((unsigned char *) &sha512_context->sha512Hash,
			   input_data, input_length, output_data, message_part,
			   (uint64_t *) &(sha512_context->runningLengthLow),
			   (uint64_t *) &(sha512_context->runningLengthHigh));
}

unsigned int ica_sha512(unsigned int message_part,
			uint64_t input_length,
			unsigned char *input_data,
			sha512_context_t *sha512_context,
			unsigned char *output_data)
{
	unsigned int rc;

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (sha512_context == NULL) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 128 bytes.
	 */
	if (input_length & 0x7f &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE))
		return EINVAL;

	return s390_sha512((unsigned char *)&sha512_context->sha512Hash,
			   input_data, input_length, output_data, message_part,
			   (uint64_t *) &sha512_context->runningLengthLow,
			   (uint64_t *) &sha512_context->runningLengthHigh);
}

unsigned int ica_random_number_generate(unsigned int output_length,
					unsigned char *output_data)
{
	/* check for obvious errors in parms */
	if (output_data == NULL)
		return EINVAL;

	return s390_prng(output_data, output_length);	
}

unsigned int ica_rsa_key_generate_mod_expo(ICA_ADAPTER_HANDLE adapter_handle,
                                           unsigned int modulus_bit_length,
                                           ica_rsa_key_mod_expo_t *public_key,
                                           ica_rsa_key_mod_expo_t *private_key)
{
	if (public_key->key_length != private_key->key_length)
		return EINVAL;
	/* Keys should comply with modulus_bit_length */
	if ((modulus_bit_length + 7) / 8 != public_key->key_length)
		return EINVAL;
	/* Minimum length for public exponent is sizeof(unsigned long) */
	if (public_key->key_length < sizeof(unsigned long))
		return EINVAL;

	/* OpenSSL takes only exponents of type unsigned long, so we have to
	 * be sure that we give a value of the right size to OpenSSL.
	 */
	unsigned int num_ignored_bytes = public_key->key_length -
					 sizeof(unsigned long);
	unsigned char *public_exponent = public_key->exponent;

	for (; num_ignored_bytes; --num_ignored_bytes, ++public_exponent)
		if (*public_exponent != 0)
			return EINVAL;

	/* There is no need to zeroize any buffers here. This will be done in
	 * the lower routines.
	 */
	return rsa_key_generate_mod_expo(adapter_handle, modulus_bit_length,
					 public_key, private_key);
}

unsigned int ica_rsa_key_generate_crt(ICA_ADAPTER_HANDLE adapter_handle,
                                      unsigned int modulus_bit_length,
                                      ica_rsa_key_mod_expo_t *public_key,
                                      ica_rsa_key_crt_t *private_key)
{
	if (public_key->key_length != private_key->key_length)
		return EINVAL;
	if ((modulus_bit_length + 7) / 8 != public_key->key_length)
		return EINVAL;
	if (public_key->key_length < sizeof(unsigned long))
		return EINVAL;

	unsigned int num_ignored_bytes = public_key->key_length -
					sizeof(unsigned long);
	unsigned char *public_exponent = public_key->exponent;

	for (; num_ignored_bytes; --num_ignored_bytes, ++public_exponent)
		if (*public_exponent != 0)
			return EINVAL;

	/* There is no need to zeroize any buffers here. This will be done in
	 * the lower routines.
	 */
	return rsa_key_generate_crt(adapter_handle, modulus_bit_length,
				    public_key, private_key);
}

unsigned int ica_rsa_mod_expo(ICA_ADAPTER_HANDLE adapter_handle,
                              unsigned char *input_data,
                              ica_rsa_key_mod_expo_t *rsa_key,
                              unsigned char *output_data)
{
	ica_rsa_modexpo_t rb;
	int rc;

	/* check for obvious errors in parms */
	if (input_data == NULL || rsa_key == NULL || output_data == NULL)
		return EINVAL;

	/* fill driver structure */
	rb.inputdata = (char *)input_data;
	rb.inputdatalength = rsa_key->key_length;
	rb.outputdata = (char *)output_data;
	rb.outputdatalength = rsa_key->key_length;
	rb.b_key = (char *)rsa_key->exponent;
	rb.n_modulus = (char *)rsa_key->modulus;

	int hardware = 0;
	if (adapter_handle == DRIVER_NOT_LOADED)
		rc = rsa_mod_expo_sw(&rb);
	else {
		rc = ioctl(adapter_handle, ICARSAMODEXPO, &rb);
		if (!rc)
			hardware = 1;
		else
			rc = rsa_mod_expo_sw(&rb);
	}
	if (rc == 0)
		stats_increment(ICA_STATS_RSA_MODEXPO, hardware);

	return rc;
}

unsigned int ica_rsa_crt(ICA_ADAPTER_HANDLE adapter_handle,
			 unsigned char *input_data,
			 ica_rsa_key_crt_t *rsa_key,
			 unsigned char *output_data)
{
	ica_rsa_modexpo_crt_t rb;
	int rc;

	/* check for obvious errors in parms */
	if (input_data == NULL || rsa_key == NULL || output_data == NULL)
		return EINVAL;

	/* fill driver structure */
	rb.inputdata = (char *)input_data;
	rb.inputdatalength = rsa_key->key_length;
	rb.outputdata = (char *)output_data;
	rb.outputdatalength = rsa_key->key_length;

	rb.np_prime = (char *)rsa_key->p;
	rb.nq_prime = (char *)rsa_key->q;
	rb.bp_key = (char *)rsa_key->dp;
	rb.bq_key = (char *)rsa_key->dq;
	rb.u_mult_inv = (char *)rsa_key->qInverse;

	int hardware = 0;
	if (adapter_handle == DRIVER_NOT_LOADED)
		rc = rsa_crt_sw(&rb);
	else {
		rc = ioctl(adapter_handle, ICARSACRT, &rb);
		if(!rc)
			hardware = 1;
		else
			rc = rsa_crt_sw(&rb);
	}	
	if (rc == 0)
		stats_increment(ICA_STATS_RSA_CRT, hardware);

	return rc;
}

unsigned int ica_des_encrypt(unsigned int mode,
			     unsigned int data_length,
			     unsigned char *input_data,
			     ica_des_vector_t *iv,
			     ica_des_key_single_t *des_key,
			     unsigned char *output_data)
{
	if (check_des_parms(mode, data_length, input_data, iv,
			    (ica_des_key_triple_t *) des_key, output_data))
		return EINVAL;

	if (mode == MODE_ECB) {
		return s390_des_ecb(DEA_ENCRYPT, data_length,
				    input_data, (unsigned char *)des_key,
				    output_data);
	} else if (mode == MODE_CBC) {
		return s390_des_cbc(DEA_ENCRYPT, data_length,
				    input_data, iv, (unsigned char *)des_key,
				    output_data);
	}
	return EINVAL;
}

unsigned int ica_des_decrypt(unsigned int mode,
			     unsigned int data_length,
			     unsigned char *input_data,
			     ica_des_vector_t *iv,
			     ica_des_key_single_t *des_key,
			     unsigned char *output_data)
{
	if (check_des_parms(mode, data_length, input_data, iv,
			    (ica_des_key_triple_t *) des_key, output_data))
		return EINVAL;

	if (mode == MODE_ECB) {
		return s390_des_ecb(DEA_DECRYPT, data_length,
				    input_data, (unsigned char *)des_key,
				    output_data);
	} else if (mode == MODE_CBC) {
		return s390_des_cbc(DEA_DECRYPT, data_length,
				    input_data, iv, (unsigned char *)des_key,
				    output_data);
	}
	return EINVAL;
}

unsigned int ica_3des_encrypt(unsigned int mode,
			      unsigned int data_length,
			      unsigned char *input_data,
			      ica_des_vector_t *iv,
			      ica_des_key_triple_t *des_key,
			      unsigned char *output_data)
{
	if (check_des_parms(mode, data_length, input_data, iv,
			    (ica_des_key_triple_t *) des_key, output_data))
		return EINVAL;

	if (mode == MODE_ECB) {
		return s390_des_ecb(TDEA_192_ENCRYPT, data_length,
				    input_data,(unsigned char *)des_key,
				    output_data);
	} else if (mode == MODE_CBC) {
		return s390_des_cbc(TDEA_192_ENCRYPT, data_length,
				    input_data, iv, (unsigned char *)des_key,
				    output_data);
	}
	return EINVAL;
}

unsigned int ica_3des_decrypt(unsigned int mode,
			      unsigned int data_length,
			      unsigned char *input_data,
			      ica_des_vector_t *iv,
			      ica_des_key_triple_t *des_key,
			      unsigned char *output_data)
{
	if (check_des_parms(mode, data_length, input_data, iv,
			    (ica_des_key_triple_t *) des_key, output_data))
		return EINVAL;

	if (mode == MODE_ECB) {
		return s390_des_ecb(TDEA_192_DECRYPT, data_length,
				    input_data, (unsigned char *)des_key,
				    output_data);
	} else if (mode == MODE_CBC) {
		return s390_des_cbc(TDEA_192_DECRYPT, data_length,
				    input_data, iv, (unsigned char *)des_key,
				    output_data);
	}
	return EINVAL;
}

unsigned int ica_aes_encrypt(unsigned int mode,
			     unsigned int data_length,
			     unsigned char *input_data,
			     ica_aes_vector_t *iv,
			     unsigned int key_length,
			     unsigned char *aes_key,
			     unsigned char *output_data)
{
	/* check for obvious errors in parms */
	if (check_aes_parms(mode, data_length, input_data, iv, key_length,
			    aes_key, output_data))
		return EINVAL;

	unsigned int function_code;
	switch (key_length) {
	case AES_KEY_LEN128:
		function_code = AES_128_ENCRYPT;
		break;
	case  AES_KEY_LEN192:
		function_code = AES_192_ENCRYPT;
		break;
	case AES_KEY_LEN256:
		function_code = AES_256_ENCRYPT;
		break;
	default:
		return EINVAL;
	}	
	switch (mode) {
        case MODE_CBC:
		return s390_aes_cbc(function_code, data_length, input_data, iv,
				    aes_key, output_data);
        case MODE_ECB:
		return s390_aes_ecb(function_code, data_length, input_data,
				    aes_key, output_data);
        default:
		return EINVAL;
        }

	return EINVAL;
}

unsigned int ica_aes_decrypt(unsigned int mode,
			     unsigned int data_length,
			     unsigned char *input_data,
			     ica_aes_vector_t *iv,
			     unsigned int key_length,
			     unsigned char *aes_key,
			     unsigned char *output_data)
{
	/* check for obvious errors in parms */
	if (check_aes_parms(mode, data_length, input_data, iv,
			    key_length, aes_key, output_data))
		return EINVAL;

	unsigned int function_code;
	switch (key_length) {
	case AES_KEY_LEN128:
		function_code = AES_128_DECRYPT;
		break;
	case  AES_KEY_LEN192:
		function_code = AES_192_DECRYPT;
		break;
	case AES_KEY_LEN256:
		function_code = AES_256_DECRYPT;
		break;
	default:
		return EINVAL;
	}	

	switch (mode) {
        case MODE_CBC:
		return s390_aes_cbc(function_code, data_length, input_data, iv,
				    aes_key, output_data);
        case MODE_ECB:
		return s390_aes_ecb(function_code, data_length, input_data,
				    aes_key, output_data);
        default:
		return EINVAL;
        }

	return EINVAL;
}

