/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *	    Rainer Wolafka <rwolafka@de.ibm.com>
 *	    Holger Dengler <hd@linux.vnet.ibm.com>
 *	    Ingo Tuchscherer <ingo.tuchscherer@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2010, 2011, 2013
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
#include "icastats.h"
#include "s390_rsa.h"
#include "s390_crypto.h"
#include "s390_sha.h"
#include "s390_prng.h"
#include "s390_des.h"
#include "s390_aes.h"
#include "s390_cmac.h"
#include "s390_cbccs.h"
#include "s390_ccm.h"
#include "s390_gcm.h"

#define DEFAULT_CRYPT_DEVICE "/udev/z90crypt"
#define DEFAULT2_CRYPT_DEVICE "/dev/z90crypt"
#define DEFAULT3_CRYPT_DEVICE "/dev/zcrypt"

#define MAX_VERSION_LENGTH 16

static unsigned int check_des_parms(unsigned int mode,
				    unsigned long data_length,
				    const unsigned char *in_data,
				    const unsigned char *iv,
				    const unsigned char *des_key,
				    const unsigned char *out_data)
{
	if ((in_data == NULL) ||
	    (out_data == NULL) ||
	    (des_key == NULL))
		return EINVAL;

	switch (mode) {
	case MODE_ECB:
		if (data_length & 0x07)
			return EINVAL;
		break;
	case MODE_CBC:
		if (iv == NULL)
			return EINVAL;
		if (data_length & 0x07)
			return EINVAL;
		break;
	case MODE_CBCCS:
		if (iv == NULL)
			return EINVAL;
		if (data_length <= DES_BLOCK_SIZE)
			return EINVAL;
	case MODE_CFB:
		if (iv == NULL)
			return EINVAL;
		break;
	case MODE_CTR:
		if (iv == NULL)
			return EINVAL;
		break;
	case MODE_OFB:
		if (iv == NULL)
			return EINVAL;
		break;
	default:
		/* unsupported mode */
		return EINVAL;
	}

	return 0;
}

static unsigned int check_aes_parms(unsigned int mode,
				    unsigned int data_length,
				    const unsigned char *in_data,
				    const unsigned char *iv,
				    unsigned int key_length,
				    const unsigned char *aes_key,
				    const unsigned char *out_data)
{
	if ((in_data == NULL) ||
	    (out_data == NULL) ||
	    (aes_key == NULL))
		return EINVAL;

	if ((key_length != AES_KEY_LEN128) &&
	    (key_length != AES_KEY_LEN192) &&
	    (key_length != AES_KEY_LEN256))
		return EINVAL;

	switch (mode) {
	case MODE_ECB:
		if (data_length & 0x0F)
			return EINVAL;
		break;
	case MODE_CBC:
		if (iv == NULL)
			return EINVAL;
		if (data_length & 0x0F)
			return EINVAL;
		break;
	case MODE_CBCCS:
		if (iv == NULL)
			return EINVAL;
		if (data_length <= AES_BLOCK_SIZE)
			return EINVAL;
	case MODE_CFB:
		if (iv == NULL)
			return EINVAL;
		break;
	case MODE_CTR:
		if (iv == NULL)
			return EINVAL;
		break;
	case MODE_OFB:
		if (iv == NULL)
			return EINVAL;
		break;
	case MODE_XTS:
		if (iv == NULL)
			return EINVAL;
		if (key_length == AES_KEY_LEN192)
			return EINVAL;
		if (data_length < AES_BLOCK_SIZE)
			return EINVAL;
		break;
	case MODE_CCM:
	case MODE_GCM:
		if (iv == NULL)
			return EINVAL;
		break;
	default:
		/* unsupported mode */
		return EINVAL;
	}

	return 0;
}

static unsigned int check_cmac_parms(unsigned int block_size,
				     const unsigned char *message, unsigned int message_length,
				     unsigned char *mac, unsigned int mac_length,
				     const unsigned char *keys, unsigned int key_length,
				     unsigned char *iv)
{

	if (keys == NULL)
		return EINVAL;

	if (mac == NULL) {		/* intermediate */
		if (iv == NULL)
			return EINVAL;

		if (message_length % block_size)
			return EINVAL;
	}

	if ((mac_length == 0) ||
	    (mac_length > block_size))
		return EINVAL;

	if ((message_length != 0) &&
	    (message == NULL))
		return EINVAL;

	switch (block_size) {
	case DES_BLOCK_SIZE:
		break;
	case AES_BLOCK_SIZE:
		if ((key_length != AES_KEY_LEN128) &&
		    (key_length != AES_KEY_LEN192) &&
		    (key_length != AES_KEY_LEN256))
			return EINVAL;
		break;
	default:
		return EINVAL;
	}

	return 0;
}

static unsigned int check_gcm_parms(unsigned long text_length,
				    const unsigned char *aad,
				    unsigned long aad_length,
				    const unsigned char *tag, unsigned int tag_length,
				    unsigned int iv_length)
{
	if ((text_length > S390_GCM_MAX_TEXT_LENGTH) ||
	    (aad_length  > S390_GCM_MAX_AAD_LENGTH) ||
	    (iv_length   > S390_GCM_MAX_IV_LENGTH) ||
	    (iv_length == 0))
		return EINVAL;

	if (tag == NULL)
		return EINVAL;

	switch (tag_length) {
	case 4:
	case 8:
	case 12:
	case 13:
	case 14:
	case 15:
	case 16:
		break;
	default:
		return EINVAL;
	}

	return 0;
}

static unsigned int check_ccm_parms(unsigned long payload_length,
				    const unsigned char *assoc_data,
				    unsigned long assoc_data_length,
				    const unsigned char *mac,
				    unsigned int mac_length,
				    unsigned int nonce_length)
{
	if ((payload_length == 0) && (assoc_data_length == 0))
		return EINVAL;

	if ((nonce_length > S390_CCM_MAX_NONCE_LENGTH) ||
	    (nonce_length < S390_CCM_MIN_NONCE_LENGTH))
		return EINVAL;

	/* if nonce_length is equal S390_CCM_MIN_NONCE_LENGTH, payload_length
	 * is only limited by the value range of its data type unsigned long
	 * and need no further checking */
	if ((nonce_length > S390_CCM_MIN_NONCE_LENGTH) &&
	    (payload_length > ((1ul << (8*(15-nonce_length))))))
		return EINVAL;

	if (mac == NULL)
		return EINVAL;

	if ((mac_length > S390_CCM_MAX_MAC_LENGTH) ||
	    (mac_length < S390_CCM_MIN_MAC_LENGTH) ||
	    (mac_length % 2))
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

static inline unsigned int des_directed_fc(int direction)
{
	if (direction)
		return DEA_ENCRYPT;
	return DEA_DECRYPT;
}

static inline unsigned int tdes_directed_fc(int direction)
{
	if (direction)
		return TDEA_192_ENCRYPT;
	return TDEA_192_DECRYPT;
}

static inline unsigned int aes_directed_fc(unsigned int key_length, int direction) {
	switch (key_length) {
	case AES_KEY_LEN128:
		return (direction == ICA_DECRYPT) ?
			AES_128_DECRYPT : AES_128_ENCRYPT;
	case AES_KEY_LEN192:
		return (direction == ICA_DECRYPT) ?
			AES_192_DECRYPT : AES_192_ENCRYPT;
	case AES_KEY_LEN256:
		return (direction == ICA_DECRYPT) ?
			AES_256_DECRYPT : AES_256_ENCRYPT;
	}
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
	if (check_des_parms(mode, data_length, input_data,
			    (unsigned char *) iv, (unsigned char *) des_key,
			     output_data))
		return EINVAL;

	if (mode == MODE_ECB) {
		return s390_des_ecb(DEA_ENCRYPT, data_length,
				    input_data, (unsigned char *) des_key,
				    output_data);
	} else if (mode == MODE_CBC) {
		return s390_des_cbc(DEA_ENCRYPT, data_length,
				    input_data, (unsigned char *) iv,
				    (unsigned char *) des_key, output_data);
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
	if (check_des_parms(mode, data_length, input_data,
			    (unsigned char *) iv, (unsigned char *) des_key,
			     output_data))
		return EINVAL;

	if (mode == MODE_ECB) {
		return s390_des_ecb(DEA_DECRYPT, data_length,
				    input_data, (unsigned char *) des_key,
				    output_data);
	} else if (mode == MODE_CBC) {
		return s390_des_cbc(DEA_DECRYPT, data_length,
				    input_data, (unsigned char *) iv,
				    (unsigned char *) des_key, output_data);
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
	if (check_des_parms(mode, data_length, input_data,
			    (unsigned char *) iv, (unsigned char *) des_key,
			     output_data))
		return EINVAL;

	if (mode == MODE_ECB) {
		return s390_des_ecb(TDEA_192_ENCRYPT, data_length,
				    input_data,(unsigned char *) des_key,
				    output_data);
	} else if (mode == MODE_CBC) {
		return s390_des_cbc(TDEA_192_ENCRYPT, data_length,
				    input_data, (unsigned char *) iv,
				    (unsigned char *) des_key, output_data);
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
	if (check_des_parms(mode, data_length, input_data,
			    (unsigned char *) iv, (unsigned char *) des_key,
			     output_data))
		return EINVAL;

	if (mode == MODE_ECB) {
		return s390_des_ecb(TDEA_192_DECRYPT, data_length,
				    input_data, (unsigned char *) des_key,
				    output_data);
	} else if (mode == MODE_CBC) {
		return s390_des_cbc(TDEA_192_DECRYPT, data_length,
				    input_data, (unsigned char *) iv,
				    (unsigned char *) des_key, output_data);
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
	if (check_aes_parms(mode, data_length, input_data,
			    (unsigned char *) iv, key_length, aes_key,
			    output_data))
		return EINVAL;

	unsigned int function_code;
	function_code = aes_directed_fc(key_length, ICA_ENCRYPT);

	switch (mode) {
	case MODE_CBC:
		return s390_aes_cbc(function_code, data_length, input_data,
				    (unsigned char *) iv, aes_key,
				    output_data);
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
	if (check_aes_parms(mode, data_length, input_data,
			    (unsigned char *) iv, key_length, aes_key,
			    output_data))
		return EINVAL;

	unsigned int function_code;
	function_code = aes_directed_fc(key_length, ICA_DECRYPT);

	switch (mode) {
	case MODE_CBC:
		return s390_aes_cbc(function_code, data_length, input_data,
				    (unsigned char *) iv, aes_key,
				    output_data);
	case MODE_ECB:
		return s390_aes_ecb(function_code, data_length, input_data,
				    aes_key, output_data);
	default:
		return EINVAL;
	}

	return EINVAL;
}

unsigned int ica_des_ecb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned int direction)
{
	if (check_des_parms(MODE_ECB, data_length, in_data, NULL, key, out_data))
		return EINVAL;

	return s390_des_ecb(des_directed_fc(direction), data_length,
			    in_data, key, out_data);
}

unsigned int ica_des_cbc(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned char *iv,
			 unsigned int direction)
{
	if (check_des_parms(MODE_CBC, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_cbc(des_directed_fc(direction), data_length,
			    in_data, iv, key, out_data);
}

unsigned int ica_des_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			    unsigned long data_length,
			    const unsigned char *key, unsigned char *iv,
			    unsigned int direction, unsigned int variant)
{
	if (check_des_parms(MODE_CBCCS, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_cbccs(des_directed_fc(direction),
			      in_data, out_data, data_length,
			      key, iv, variant);
}

unsigned int ica_des_cfb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned char *iv, unsigned int lcfb,
			 unsigned int direction)
{
	if (check_des_parms(MODE_CFB, data_length, in_data, iv, key, out_data))
		return EINVAL;
	/* The cipher feedback has to be between 1 and cipher block size. */
	if ((lcfb == 0) || (lcfb > DES_BLOCK_SIZE))
		return EINVAL;

	return s390_des_cfb(des_directed_fc(direction), data_length,
			    in_data, iv, key, out_data, lcfb);
}

unsigned int ica_des_ofb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned char *iv, unsigned int direction)
{
	if (check_des_parms(MODE_OFB, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_ofb(des_directed_fc(direction), data_length,
			    in_data, iv, key, out_data);
}

unsigned int ica_des_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 const unsigned char *key,
			 unsigned char *ctr, unsigned int ctr_width,
			 unsigned int direction)
{
	if (check_des_parms(MODE_CTR, data_length, in_data, ctr, key, out_data))
		return EINVAL;

	if ((ctr_width & (8 - 1)) ||
	    (ctr_width < 8) ||
	    (ctr_width > (DES_BLOCK_SIZE*8)))
		return EINVAL;

	return s390_des_ctr(des_directed_fc(direction),
			    in_data, out_data, data_length,
			    key, ctr, ctr_width);
}

unsigned int ica_des_ctrlist(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     const unsigned char *key,
			     const unsigned char *ctrlist,
			     unsigned int direction)
{
	if (check_des_parms(MODE_CTR, data_length, in_data, ctrlist, key, out_data))
		return EINVAL;

	return s390_des_ctrlist(des_directed_fc(direction),
				data_length, in_data, ctrlist,
				key, out_data);
}

unsigned int ica_des_cmac(const unsigned char *message, unsigned long message_length,
			  unsigned char *mac, unsigned int mac_length,
			  const unsigned char *key,
			  unsigned int direction)
{
	return ica_des_cmac_last(message, message_length,
				 mac, mac_length,
				 key,
				 NULL,
				 direction);
}

unsigned int ica_des_cmac_intermediate(const unsigned char *message,
				       unsigned long message_length,
				       const unsigned char *key,
				       unsigned char *iv)
{
	unsigned long function_code;
	int rc;

	if (check_cmac_parms(DES_BLOCK_SIZE,
			     message, message_length,
			     NULL, DES_BLOCK_SIZE,	/* no mac available (intermediate) */
			     key, DES_BLOCK_SIZE,
			     iv))
		return EINVAL;

	function_code = des_directed_fc(ICA_DECRYPT);
	rc = s390_cmac(function_code, message, message_length,
		       DES_BLOCK_SIZE, key,
		       DES_BLOCK_SIZE, NULL,	/* no mac available (intermediate) */
		       iv);

	return rc;
}

unsigned int ica_des_cmac_last(const unsigned char *message, unsigned long message_length,
			       unsigned char *mac, unsigned int mac_length,
			       const unsigned char *key,
			       unsigned char *iv,
			       unsigned int direction)
{
	unsigned char tmp_mac[DES_BLOCK_SIZE];
	unsigned long function_code;
	int rc;

	if (check_cmac_parms(DES_BLOCK_SIZE,
			     message, message_length,
			     mac, mac_length,
			     key, DES_BLOCK_SIZE,
			     iv))
		return EINVAL;

	function_code = des_directed_fc(direction);
	if (direction) {
		/* generate */
		rc = s390_cmac(function_code, message, message_length,
			       DES_BLOCK_SIZE, key, mac_length, mac, iv);
		if (rc)
			return rc;
	} else {
		/* verify */
		rc = s390_cmac(function_code, message, message_length,
			       DES_BLOCK_SIZE, key, mac_length, tmp_mac, iv);
		if (rc)
			return rc;
		if (memcmp(tmp_mac, mac, mac_length))
			return EFAULT;
	}

	return 0;
}

unsigned int ica_3des_ecb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, const unsigned char *key,
			  unsigned int direction)
{
	if (check_des_parms(MODE_ECB, data_length, in_data, NULL, key, out_data))
		return EINVAL;

	return s390_des_ecb(tdes_directed_fc(direction), data_length,
			    in_data, key, out_data);
}

unsigned int ica_3des_cbc(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, const unsigned char *key,
			  unsigned char *iv,
			  unsigned int direction)
{
	if (check_des_parms(MODE_CBC, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_cbc(tdes_directed_fc(direction), data_length,
			    in_data, iv, key, out_data);
}

unsigned int ica_3des_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     const unsigned char *key, unsigned char *iv,
			     unsigned int direction, unsigned int variant)
{
	if (check_des_parms(MODE_CBCCS, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_cbccs(tdes_directed_fc(direction),
			      in_data, out_data, data_length,
			      key, iv, variant);
}

unsigned int ica_3des_cfb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, const unsigned char *key,
			  unsigned char *iv, unsigned int lcfb,
			  unsigned int direction)
{
	if (check_des_parms(MODE_CFB, data_length, in_data, iv, key, out_data))
		return EINVAL;
	/* The cipher feedback has to be between 1 and cipher block size. */
	if ((lcfb == 0) || (lcfb > DES_BLOCK_SIZE))
		return EINVAL;

	return s390_des_cfb(tdes_directed_fc(direction), data_length,
			    in_data, iv, key, out_data, lcfb);
}

unsigned int ica_3des_ofb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, const unsigned char *key,
			  unsigned char *iv, unsigned int direction)
{
	if (check_des_parms(MODE_OFB, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_ofb(tdes_directed_fc(direction), data_length,
			    in_data, iv, key, out_data);
}

unsigned int ica_3des_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 const unsigned char *key,
			 unsigned char *ctr, unsigned int ctr_width,
			 unsigned int direction)
{
	if (check_des_parms(MODE_CTR, data_length, in_data, ctr, key, out_data))
		return EINVAL;

	if ((ctr_width & (8 - 1)) ||
	    (ctr_width < 8) ||
	    (ctr_width > (DES_BLOCK_SIZE*8)))
		return EINVAL;

	return s390_des_ctr(tdes_directed_fc(direction),
			    in_data, out_data, data_length,
			    key, ctr, ctr_width);
}

unsigned int ica_3des_ctrlist(const unsigned char *in_data, unsigned char *out_data,
			      unsigned long data_length,
			      const unsigned char *key,
			      const unsigned char *ctrlist,
			      unsigned int direction)
{
	if (check_des_parms(MODE_CTR, data_length, in_data, ctrlist, key, out_data))
		return EINVAL;

	return s390_des_ctrlist(tdes_directed_fc(direction),
				data_length, in_data, ctrlist,
				key, out_data);
}

unsigned int ica_3des_cmac(const unsigned char *message, unsigned long message_length,
			   unsigned char *mac, unsigned int mac_length,
			   const unsigned char *key,
			   unsigned int direction)
{
	return ica_3des_cmac_last(message, message_length,
				  mac, mac_length,
				  key,
				  NULL,
				  direction);
}

unsigned int ica_3des_cmac_intermediate(const unsigned char *message,
					unsigned long message_length,
					const unsigned char *key,
					unsigned char *iv)
{
	unsigned long function_code;
	int rc;

	if (check_cmac_parms(DES_BLOCK_SIZE,
			     message, message_length,
			     NULL, DES_BLOCK_SIZE,	/* no mac available (intermediate) */
			     key, 3*DES_BLOCK_SIZE,
			     iv))
		return EINVAL;

	function_code = tdes_directed_fc(ICA_DECRYPT);
	rc = s390_cmac(function_code, message, message_length,
		       3*DES_BLOCK_SIZE, key,
		       DES_BLOCK_SIZE, NULL,	/* no mac available (intermediate) */
		       iv);

	return rc;
}

unsigned int ica_3des_cmac_last(const unsigned char *message, unsigned long message_length,
				unsigned char *mac, unsigned int mac_length,
				const unsigned char *key,
				unsigned char *iv,
				unsigned int direction)
{
	unsigned char tmp_mac[DES_BLOCK_SIZE];
	unsigned long function_code;
	int rc;

	if (check_cmac_parms(DES_BLOCK_SIZE,
			     message, message_length,
			     mac, mac_length,
			     key, 3*DES_BLOCK_SIZE,
			     iv))
		return EINVAL;

	function_code = tdes_directed_fc(direction);
	if (direction) {
		/* generate */
		rc = s390_cmac(function_code, message, message_length,
			       3*DES_BLOCK_SIZE, key, mac_length, mac, iv);
		if (rc)
			return rc;
	} else {
		/* verify */
		rc = s390_cmac(function_code, message, message_length,
			       3*DES_BLOCK_SIZE, key, mac_length, tmp_mac, iv);
		if (rc)
			return rc;
		if (memcmp(tmp_mac, mac, mac_length))
			return EFAULT;
	}

	return 0;
}

unsigned int ica_aes_ecb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned int key_length,
			 unsigned int direction)
{
	unsigned int function_code;
	if (check_aes_parms(MODE_ECB, data_length, in_data, NULL, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_ecb(function_code, data_length, in_data, key, out_data);
}

unsigned int ica_aes_cbc(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned int key_length, unsigned char *iv,
			 unsigned int direction)
{
	unsigned int function_code;
	if (check_aes_parms(MODE_CBC, data_length, in_data, iv, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_cbc(function_code, data_length, in_data, iv, key, out_data);
}

unsigned int ica_aes_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			    unsigned long data_length,
			    const unsigned char *key, unsigned int key_length,
			    unsigned char *iv,
			    unsigned int direction, unsigned int variant)
{
	unsigned int function_code;
	if (check_aes_parms(MODE_CBCCS, data_length, in_data, iv, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_cbccs(function_code, in_data, out_data, data_length,
			      key, key_length, iv, variant);
}

unsigned int ica_aes_cfb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned int key_length, unsigned char *iv, unsigned int lcfb,
			 unsigned int direction)
{
	unsigned int function_code;
	if (check_aes_parms(MODE_CFB, data_length, in_data, iv, key_length,
			    key, out_data))
		return EINVAL;
	/* The cipher feedback has to be between 1 and cipher block size. */
	if ((lcfb == 0) || (lcfb > AES_BLOCK_SIZE))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_cfb(function_code, data_length, in_data, iv, key, out_data,
			    lcfb);
}

unsigned int ica_aes_ofb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned int key_length, unsigned char *iv,
			 unsigned int direction)
{
	unsigned int function_code;

	if (check_aes_parms(MODE_OFB, data_length, in_data, iv, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_ofb(function_code, data_length, in_data, iv, key, out_data);
}

unsigned int ica_aes_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 const unsigned char *key, unsigned int key_length,
			 unsigned char *ctr, unsigned int ctr_width,
			 unsigned int direction)
{
	unsigned int function_code;

	if (check_aes_parms(MODE_CTR, data_length, in_data, ctr, key_length,
			    key, out_data))
		return EINVAL;

	if ((ctr_width & (8 - 1)) ||
	    (ctr_width < 8) ||
	    (ctr_width > (AES_BLOCK_SIZE*8)))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_ctr(function_code,
			    in_data, out_data, data_length,
			    key, ctr, ctr_width);
}

unsigned int ica_aes_ctrlist(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     const unsigned char *key, unsigned int key_length,
			     const unsigned char *ctrlist,
			     unsigned int direction)
{
	unsigned int function_code;
	if (check_aes_parms(MODE_CTR, data_length, in_data, ctrlist, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_ctrlist(function_code, data_length, in_data, ctrlist,
			    key, out_data);
}

unsigned int ica_aes_xts(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 const unsigned char *key1, const unsigned char *key2,
			 unsigned int key_length, unsigned char *tweak,
			 unsigned int direction)
{
	unsigned int function_code;

	if (check_aes_parms(MODE_XTS, data_length, in_data, tweak, key_length,
			    key1, out_data))
		return EINVAL;

	if (key2 == NULL)
		return EINVAL;

	switch (key_length) {
	case AES_KEY_LEN128:
		function_code = (direction == ICA_DECRYPT) ?
			AES_128_XTS_DECRYPT : AES_128_XTS_ENCRYPT;
		break;
	case AES_KEY_LEN256:
		function_code = (direction == ICA_DECRYPT) ?
			AES_256_XTS_DECRYPT : AES_256_XTS_ENCRYPT;
		break;
	default:
		return EINVAL;
	}

	return s390_aes_xts(function_code, data_length, in_data, tweak,
			    key1, key2, key_length, out_data);
}

unsigned int ica_aes_cmac(const unsigned char *message, unsigned long message_length,
			  unsigned char *mac, unsigned int mac_length,
			  const unsigned char *key, unsigned int key_length,
			  unsigned int direction)
{
	return ica_aes_cmac_last(message, message_length,
				 mac, mac_length,
				 key, key_length,
				 NULL,
				 direction);
}

unsigned int ica_aes_cmac_intermediate(const unsigned char *message,
				       unsigned long message_length,
				       const unsigned char *key, unsigned int key_length,
				       unsigned char *iv)
{
	unsigned long function_code;
	int rc;

	if (check_cmac_parms(AES_BLOCK_SIZE,
			     message, message_length,
			     NULL, AES_BLOCK_SIZE,	/* no mac available (intermediate) */
			     key, key_length,
			     iv))
		return EINVAL;

	function_code = aes_directed_fc(key_length, ICA_DECRYPT);
	rc = s390_cmac(function_code, message, message_length,
		       key_length, key,
		       AES_BLOCK_SIZE, NULL,	/* no mac available (intermediate) */
		       iv);

	return rc;
}

unsigned int ica_aes_cmac_last(const unsigned char *message, unsigned long message_length,
			       unsigned char *mac, unsigned int mac_length,
			       const unsigned char *key, unsigned int key_length,
			       unsigned char *iv,
			       unsigned int direction)
{
	unsigned char tmp_mac[AES_BLOCK_SIZE];
	unsigned long function_code;
	int rc;

	if (check_cmac_parms(AES_BLOCK_SIZE,
			     message, message_length,
			     mac, mac_length,
			     key, key_length,
			     iv))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	if (direction) {
		/* generate */
		rc = s390_cmac(function_code, message, message_length,
			       key_length, key, mac_length, mac, iv);
		if (rc)
			return rc;
	} else {
		/* verify */
		rc = s390_cmac(function_code, message, message_length,
			       key_length, key, mac_length, tmp_mac, iv);
		if (rc)
			return rc;
		if (memcmp(tmp_mac, mac, mac_length))
			return EFAULT;
	}

	return 0;
}

unsigned int ica_aes_ccm(unsigned char *payload, unsigned long payload_length,
			 unsigned char *ciphertext_n_mac, unsigned int mac_length,
			 const unsigned char *assoc_data, unsigned long assoc_data_length,
			 const unsigned char *nonce, unsigned int nonce_length,
			 const unsigned char *key, unsigned int key_length,
			 unsigned int direction)
{
	unsigned char tmp_mac[AES_BLOCK_SIZE];
	unsigned char *mac;
	unsigned long function_code;
	int rc;

	if (check_aes_parms(MODE_CCM, payload_length, payload, nonce, key_length,
			    key, ciphertext_n_mac))
		return EINVAL;
	if (check_ccm_parms(payload_length,
			    assoc_data, assoc_data_length,
			    ciphertext_n_mac + payload_length, mac_length,
			    nonce_length))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	mac = (direction == ICA_ENCRYPT) ?
		(unsigned char *)(ciphertext_n_mac + payload_length) :
		tmp_mac;

	rc = s390_ccm(function_code,
		      payload, payload_length,
		      ciphertext_n_mac,
		      assoc_data, assoc_data_length,
		      nonce, nonce_length,
		      mac, mac_length,
		      key);
	if (rc)
		return rc;

	if (direction == ICA_DECRYPT) {
		/* verify */
		if (memcmp((unsigned char *)(ciphertext_n_mac + payload_length),
			   tmp_mac, mac_length))
			return EFAULT;
	}

	return 0;
}

unsigned int ica_aes_gcm(unsigned char *plaintext, unsigned long plaintext_length,
			 unsigned char *ciphertext,
			 const unsigned char *iv, unsigned int iv_length,
			 const unsigned char *aad, unsigned long aad_length,
			 unsigned char *tag, unsigned int tag_length,
			 const unsigned char *key, unsigned int key_length,
			 unsigned int direction)
{
	unsigned char tmp_tag[AES_BLOCK_SIZE];
	unsigned long function_code;
	int rc;

	if (check_aes_parms(MODE_GCM, plaintext_length, plaintext, iv, key_length,
			    key, ciphertext))
		return EINVAL;
	if (check_gcm_parms(plaintext_length, aad, aad_length, tag, tag_length, iv_length))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	if (direction) {
		/* encrypt & generate */
		rc = s390_gcm(function_code,
			      plaintext, plaintext_length,
			      ciphertext,
			      iv, iv_length,
			      aad, aad_length,
			      tag, tag_length,
			      key);
		if (rc)
			return rc;
	} else {
		/* decrypt & verify */
		rc = s390_gcm(function_code,
			      plaintext, plaintext_length,
			      ciphertext,
			      iv, iv_length,
			      aad, aad_length,
			      tmp_tag, AES_BLOCK_SIZE,
			      key);
		if (rc)
			return rc;

		if (memcmp(tmp_tag, tag, tag_length))
			return EFAULT;
	}

	return 0;
}

unsigned int ica_get_version(libica_version_info *version_info)
{
#ifdef VERSION
	int length;
	int rc;
	int i;
	char *pch;
	char *saveptr;

	if (version_info == NULL) {
		return EINVAL;
	}

	length = strnlen(VERSION, MAX_VERSION_LENGTH);
	char buffer[length+1];

	rc = snprintf(buffer, (length+1), "%s", VERSION);
	if (rc <= 0) {
		return EIO;
	}

	for (pch = strtok_r(buffer, ".", &saveptr), i = 1;
	     pch != NULL;
	     pch = strtok_r(NULL, ".", &saveptr), i++)
	{
		switch(i) {
		case 1:
			version_info->major_version = atoi(pch);
			break;
		case 2:
			version_info->minor_version = atoi(pch);
			break;
		case 3:
			version_info->fixpack_version = atoi(pch);
			break;
		default:
			return EIO;
		}
	}

	if (i < 3)
		return EIO;

	return 0;
#else
	/* We expect the libica version information in the format x.y.z
	 * defined in the macro VERSION as part of the build process. */
	return EIO;
#endif
}

unsigned int ica_get_functionlist(libica_func_list_element *pmech_list,
					  unsigned int *pmech_list_len)
{
	return s390_get_functionlist(pmech_list, pmech_list_len);
}
