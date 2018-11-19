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
#include <stdint.h>
#include <linux/types.h>
#include <stdbool.h>
#include <assert.h>

#include "init.h"
#include "ica_api.h"
#include "icastats.h"
#include "fips.h"
#include "s390_rsa.h"
#include "s390_ecc.h"
#include "s390_crypto.h"
#include "s390_sha.h"
#include "s390_prng.h"
#include "s390_des.h"
#include "s390_aes.h"
#include "s390_cmac.h"
#include "s390_cbccs.h"
#include "s390_ccm.h"
#include "s390_gcm.h"
#include "s390_drbg.h"

#define DEFAULT_CRYPT_DEVICE "/udev/z90crypt"
#define DEFAULT2_CRYPT_DEVICE "/dev/z90crypt"
#define DEFAULT3_CRYPT_DEVICE "/dev/zcrypt"

#define MAX_VERSION_LENGTH 16

int ica_fallbacks_enabled = 1;

void ica_set_fallback_mode(int fallback_mode)
{
	if (fallback_mode)
		ica_fallbacks_enabled = 1;
	else
		ica_fallbacks_enabled = 0;
}

int ica_offload_enabled = 0;

void ica_set_offload_mode(int offload_mode)
{
	ica_offload_enabled = offload_mode ? 1 : 0;
}

int ica_stats_enabled = 1;

void ica_set_stats_mode(int stats_mode)
{
	ica_stats_enabled = stats_mode ? 1 : 0;
}

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
		break;
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

#ifdef ICA_FIPS
static unsigned int fips_check_3des_key(const ica_des_key_triple_t *key) {
	if (!CRYPTO_memcmp(key->key1, key->key2, DES_KEY_LENGTH)
	    | !CRYPTO_memcmp(key->key1, key->key3, DES_KEY_LENGTH)
	    | !CRYPTO_memcmp(key->key2, key->key3, DES_KEY_LENGTH))
		return EINVAL;

	return 0;
}
#endif

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
		break;
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
				     unsigned char *keys, unsigned int key_length,
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
				    unsigned long aad_length,
				    const unsigned char *tag, unsigned int tag_length,
				    unsigned int iv_length)
{
#ifdef __s390x__
	/*
	 * The following comparisions are alaways false on s390 targets
	 * due to limited range of data type.
	 */
	if ((text_length > S390_GCM_MAX_TEXT_LENGTH) ||
	    (aad_length > S390_GCM_MAX_AAD_LENGTH))
		return EINVAL;
#else
	(void)text_length;	/* supporess unused param warning */
	(void)aad_length;
#endif
	/*
	 * The following check must be done but is commented out because
	 * comparison is always false due to limited range of data type.
	 *
	 * if (iv_length   > S390_GCM_MAX_IV_LENGTH)
	 *	return EINVAL;
	 */

	if (iv_length == 0)
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
	    (payload_length > ((1ull << (8*(15-nonce_length))))))
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

unsigned int ica_open_adapter(ica_adapter_handle_t *adapter_handle)
{
	char *name, status_mask[64];

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

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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
		memcpy(&sha_context->shaHash, output_data, SHA_HASH_LENGTH);

	return rc;
}

unsigned int ica_sha224(unsigned int message_part,
			unsigned int input_length,
			unsigned char *input_data,
			sha256_context_t *sha256_context,
			unsigned char *output_data)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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
			sha512_context_t *sha512_context,
			unsigned char *output_data)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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

unsigned int ica_sha512_224(unsigned int message_part,
			    uint64_t input_length,
			    unsigned char *input_data,
			    sha512_context_t *sha512_context,
			    unsigned char *output_data)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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

	return s390_sha512_224((unsigned char *)&sha512_context->sha512Hash,
			       input_data, input_length, output_data, message_part,
			       (uint64_t *) &sha512_context->runningLengthLow,
			       (uint64_t *) &sha512_context->runningLengthHigh);
}

unsigned int ica_sha512_256(unsigned int message_part,
			    uint64_t input_length,
			    unsigned char *input_data,
			    sha512_context_t *sha512_context,
			    unsigned char *output_data)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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

	return s390_sha512_256((unsigned char *)&sha512_context->sha512Hash,
			       input_data, input_length, output_data, message_part,
			       (uint64_t *) &sha512_context->runningLengthLow,
			       (uint64_t *) &sha512_context->runningLengthHigh);
}

unsigned int ica_sha3_224(unsigned int message_part,
			unsigned int input_length,
			unsigned char *input_data,
			sha3_224_context_t *sha3_224_context,
			unsigned char *output_data)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (sha3_224_context == NULL) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 144 bytes.
	 */
	if ((input_length % 144 != 0) &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE))
		return EINVAL;

	return s390_sha3_224((unsigned char *) &sha3_224_context->sha3_224Hash,
			   input_data, input_length, output_data, message_part,
			   (uint64_t *)&sha3_224_context->runningLength);
}

unsigned int ica_sha3_256(unsigned int message_part,
			unsigned int input_length,
			unsigned char *input_data,
			sha3_256_context_t *sha3_256_context,
			unsigned char *output_data)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (sha3_256_context == NULL) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 136 bytes.
	 */
	if ((input_length % 136 != 0) &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE))
		return EINVAL;

	return s390_sha3_256((unsigned char *) &sha3_256_context->sha3_256Hash,
			   input_data, input_length, output_data, message_part,
			   (uint64_t *) &sha3_256_context->runningLength);
}

unsigned int ica_sha3_384(unsigned int message_part,
			uint64_t input_length,
			unsigned char *input_data,
			sha3_384_context_t *sha3_384_context,
			unsigned char *output_data)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (sha3_384_context == NULL) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 104 bytes.
	 */
	if ((input_length % 104 != 0) &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE))
		return EINVAL;

	return s390_sha3_384((unsigned char *) &sha3_384_context->sha3_384Hash,
			   input_data, input_length, output_data, message_part,
			   (uint64_t *) &(sha3_384_context->runningLengthLow),
			   (uint64_t *) &(sha3_384_context->runningLengthHigh));
}

unsigned int ica_sha3_512(unsigned int message_part,
			uint64_t input_length,
			unsigned char *input_data,
			sha3_512_context_t *sha3_512_context,
			unsigned char *output_data)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (sha3_512_context == NULL) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 72 bytes.
	 */
	if ((input_length % 72 != 0) &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE))
		return EINVAL;

	return s390_sha3_512((unsigned char *)&sha3_512_context->sha3_512Hash,
			   input_data, input_length, output_data, message_part,
			   (uint64_t *) &sha3_512_context->runningLengthLow,
			   (uint64_t *) &sha3_512_context->runningLengthHigh);
}

unsigned int ica_shake_128(unsigned int message_part,
			uint64_t input_length,
			unsigned char *input_data,
			shake_128_context_t *shake_128_context,
			unsigned char *output_data, unsigned int output_length)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (shake_128_context == NULL) ||
	    (output_length == 0) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 168 bytes.
	 */
	if ((input_length % 168 != 0) &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE)) {
		return EINVAL;
	}

	/* set output_length in context for first call and only call */
	if ((message_part == SHA_MSG_PART_FIRST || message_part == SHA_MSG_PART_ONLY))
		shake_128_context->output_length = output_length;

	return s390_shake_128((unsigned char *)&shake_128_context->shake_128Hash,
			   input_data, input_length, output_data, shake_128_context->output_length,
			   message_part, (uint64_t *) &shake_128_context->runningLengthLow,
			   (uint64_t *) &shake_128_context->runningLengthHigh);
}

unsigned int ica_shake_256(unsigned int message_part,
			uint64_t input_length,
			unsigned char *input_data,
			shake_256_context_t *shake_256_context,
			unsigned char *output_data, unsigned int output_length)
{
	unsigned int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if ((input_data == NULL) ||
	    (shake_256_context == NULL) ||
	    (output_length == 0) ||
	    (output_data == NULL))
		return EINVAL;

	/* make sure some message part is specified */
	rc = check_message_part(message_part);
	if (rc)
		return rc;

	/*
	 * for FIRST or MIDDLE calls the input
	 * data length must be a multiple of 136 bytes.
	 */
	if ((input_length % 136 != 0) &&
	    (message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE))
		return EINVAL;

	/* set output_length in context for first call and only call */
	if ((message_part == SHA_MSG_PART_FIRST || message_part == SHA_MSG_PART_ONLY))
		shake_256_context->output_length = output_length;

	return s390_shake_256((unsigned char *)&shake_256_context->shake_256Hash,
			   input_data, input_length, output_data, shake_256_context->output_length,
			   message_part, (uint64_t *) &shake_256_context->runningLengthLow,
			   (uint64_t *) &shake_256_context->runningLengthHigh);
}

unsigned int ica_random_number_generate(unsigned int output_length,
					unsigned char *output_data)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (output_data == NULL)
		return EINVAL;

	return s390_prng(output_data, output_length);
}

unsigned int ica_rsa_key_generate_mod_expo(ica_adapter_handle_t adapter_handle,
					   unsigned int modulus_bit_length,
					   ica_rsa_key_mod_expo_t *public_key,
					   ica_rsa_key_mod_expo_t *private_key)
{
	unsigned int num_ignored_bytes;
	unsigned char *public_exponent;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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
	num_ignored_bytes = public_key->key_length - sizeof(unsigned long);
	public_exponent = public_key->exponent;

	for (; num_ignored_bytes; --num_ignored_bytes, ++public_exponent)
		if (*public_exponent != 0)
			return EINVAL;

	/* There is no need to zeroize any buffers here. This will be done in
	 * the lower routines.
	 */
	return rsa_key_generate_mod_expo(adapter_handle, modulus_bit_length,
					 public_key, private_key);
}

unsigned int ica_rsa_key_generate_crt(ica_adapter_handle_t adapter_handle,
				      unsigned int modulus_bit_length,
				      ica_rsa_key_mod_expo_t *public_key,
				      ica_rsa_key_crt_t *private_key)
{
	unsigned int num_ignored_bytes;
	unsigned char *public_exponent;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (public_key->key_length != private_key->key_length)
		return EINVAL;
	if ((modulus_bit_length + 7) / 8 != public_key->key_length)
		return EINVAL;
	if (public_key->key_length < sizeof(unsigned long))
		return EINVAL;

	num_ignored_bytes = public_key->key_length - sizeof(unsigned long);
	public_exponent = public_key->exponent;

	for (; num_ignored_bytes; --num_ignored_bytes, ++public_exponent)
		if (*public_exponent != 0)
			return EINVAL;

	/* There is no need to zeroize any buffers here. This will be done in
	 * the lower routines.
	 */
	return rsa_key_generate_crt(adapter_handle, modulus_bit_length,
				    public_key, private_key);
}

unsigned int ica_rsa_mod_expo(ica_adapter_handle_t adapter_handle,
			      unsigned char *input_data,
			      ica_rsa_key_mod_expo_t *rsa_key,
			      unsigned char *output_data)
{
	ica_rsa_modexpo_t rb;
	int hardware, rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (input_data == NULL || rsa_key == NULL || output_data == NULL)
		return EINVAL;

	if (rsa_key->key_length < sizeof(unsigned long))
		return EINVAL;

	/* fill driver structure */
	rb.inputdata = (char *)input_data;
	rb.inputdatalength = rsa_key->key_length;
	rb.outputdata = (char *)output_data;
	rb.outputdatalength = rsa_key->key_length;
	rb.b_key = (char *)rsa_key->exponent;
	rb.n_modulus = (char *)rsa_key->modulus;

	hardware = ALGO_SW;
	if (adapter_handle == DRIVER_NOT_LOADED)
		rc = ica_fallbacks_enabled ?
			rsa_mod_expo_sw(&rb) : ENODEV;
	else {
		rc = ioctl(adapter_handle, ICARSAMODEXPO, &rb);
		if (!rc)
			hardware = ALGO_HW;
		else
			rc = ica_fallbacks_enabled ?
				rsa_mod_expo_sw(&rb) : ENODEV;
	}
	if (rc == 0)
		stats_increment(ICA_STATS_RSA_ME, hardware, ENCRYPT);

	return rc;
}

unsigned int ica_rsa_crt_key_check(ica_rsa_key_crt_t *rsa_key)
{
	int pq_comp;
	int keyfmt = 1;
	BIGNUM *bn_p;
	BIGNUM *bn_q;
	BIGNUM *bn_invq;
	BN_CTX *ctx;
	unsigned char *tmp_buf = NULL;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check if p > q  */
	pq_comp = memcmp( (rsa_key->p + 8), (rsa_key->q), rsa_key->key_length/2);
	if (pq_comp < 0) /* unprivileged key format */
		keyfmt = 0;

	if (!keyfmt) {
		/* swap p and q */
		tmp_buf = calloc(1, rsa_key->key_length/2);
		if (!tmp_buf)
			return ENOMEM;
		memcpy(tmp_buf, rsa_key->p + 8, rsa_key->key_length/2);
		memcpy(rsa_key->p + 8, rsa_key->q, rsa_key->key_length/2);
		memcpy(rsa_key->q, tmp_buf, rsa_key->key_length/2);

		/* swap dp and dq */
		memcpy(tmp_buf, rsa_key->dp + 8, rsa_key->key_length/2);
		memcpy(rsa_key->dp + 8, rsa_key->dq, rsa_key->key_length/2);
		memcpy(rsa_key->dq, tmp_buf, rsa_key->key_length/2);

		/* calculate new qInv */
		bn_p = BN_new();
		bn_q = BN_new();
		bn_invq = BN_new();
		ctx = BN_CTX_new();

		BN_bin2bn(rsa_key->p, rsa_key->key_length/2+8, bn_p);
		BN_bin2bn(rsa_key->q, rsa_key->key_length/2, bn_q);

		/* qInv = (1/q) mod p */
		BN_mod_inverse(bn_invq, bn_q, bn_p, ctx);
		memset(tmp_buf, 0, rsa_key->key_length/2);
		BN_bn2bin(bn_invq, tmp_buf);

		memcpy(rsa_key->qInverse + 8, tmp_buf, rsa_key->key_length/2);

		free(tmp_buf);

		return 1;
	}
	return 0;
}

unsigned int ica_rsa_crt(ica_adapter_handle_t adapter_handle,
			 unsigned char *input_data,
			 ica_rsa_key_crt_t *rsa_key,
			 unsigned char *output_data)
{
	ica_rsa_modexpo_crt_t rb;
	int hardware, rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (input_data == NULL || rsa_key == NULL || output_data == NULL)
		return EINVAL;

	if (rsa_key->key_length < sizeof(unsigned long))
		return EINVAL;

	/* fill driver structure */
	rb.inputdata = (char *)input_data;
	rb.inputdatalength = rsa_key->key_length;
	rb.outputdata = (char *)output_data;
	rb.outputdatalength = rsa_key->key_length;

	ica_rsa_crt_key_check(rsa_key);

	rb.np_prime = (char *)rsa_key->p;
	rb.nq_prime = (char *)rsa_key->q;
	rb.bp_key = (char *)rsa_key->dp;
	rb.bq_key = (char *)rsa_key->dq;
	rb.u_mult_inv = (char *)rsa_key->qInverse;

	hardware = ALGO_SW;
	if (adapter_handle == DRIVER_NOT_LOADED)
		rc = ica_fallbacks_enabled ?
			rsa_crt_sw(&rb) : ENODEV;
	else {
		rc = ioctl(adapter_handle, ICARSACRT, &rb);
		if(!rc)
			hardware = ALGO_HW;
		else
			rc = ica_fallbacks_enabled ?
				rsa_crt_sw(&rb) : ENODEV;
	}
	if (rc == 0)
		stats_increment(ICA_STATS_RSA_CRT, hardware, ENCRYPT);

	return rc;
}

/*******************************************************************************
 *
 *                          Begin of ECC API
 */

ICA_EC_KEY* ica_ec_key_new(unsigned int nid, unsigned int *privlen)
{
	ICA_EC_KEY *key;
	int len;

#ifdef ICA_FIPS
	if (fips >> 1)
		return NULL;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (!curve_supported(nid))
		return NULL;

	if ((key = malloc(sizeof(ICA_EC_KEY))) == NULL)
		return NULL;

	/* allocate clear memory for the 3 key parts */
	len = privlen_from_nid(nid);
	key->X = calloc(1, 3*len);
	if (!key->X)
		return NULL;

	key->nid = nid;
	key->Y = key->X + len;
	key->D = key->Y + len;

	*privlen = len;

	return key;
}

int ica_ec_key_init(const unsigned char *X, const unsigned char *Y,
		const unsigned char *D, ICA_EC_KEY *key)
{
	unsigned int privlen = privlen_from_nid(key->nid);

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (key == NULL)
		return EINVAL;

	if ((X == NULL && Y != NULL) || (X != NULL && Y == NULL))
		return EINVAL;

	if (X != NULL && Y != NULL) {
		memcpy(key->X, X, privlen);
		memcpy(key->Y, Y, privlen);
	}

	if (D != NULL)
		memcpy(key->D, D, privlen);

	return 0;
}

int ica_ec_key_generate(ica_adapter_handle_t adapter_handle, ICA_EC_KEY *key)
{
	int hardware, rc;
	unsigned int icapath = 0;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (key == NULL)
		return EINVAL;

	icapath = getenv_icapath();
	switch (icapath) {
	case 1: /* hw only */
		hardware = ALGO_HW;
		rc = eckeygen_hw(adapter_handle, key);
		break;
	case 2: /* sw only */
		hardware = ALGO_SW;
		rc = eckeygen_sw(key);
		break;
	default: /* hw with sw fallback (default) */
		hardware = ALGO_SW;
		rc = eckeygen_hw(adapter_handle, key);
		if (rc == 0)
			hardware = ALGO_HW;
		else
			rc = ica_fallbacks_enabled ?
				eckeygen_sw(key) : ENODEV;
	}

	if (rc == 0)
		stats_increment(ICA_STATS_ECKGEN, hardware, ENCRYPT);

	return rc;
}

int ica_ecdh_derive_secret(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey_A, const ICA_EC_KEY *pubkey_B,
		unsigned char *z, unsigned int z_length)
{
	int hardware, rc;
	unsigned int privlen = privlen_from_nid(privkey_A->nid);
	unsigned int icapath = 0;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (z == NULL || z_length < privlen || privkey_A->nid != pubkey_B->nid)
		return EINVAL;

	icapath = getenv_icapath();
	switch (icapath) {
	case 1: /* hw only */
		hardware = ALGO_HW;
		rc = ecdh_hw(adapter_handle, privkey_A, pubkey_B, z);
		break;
	case 2: /* sw only */
		hardware = ALGO_SW;
		rc = ecdh_sw(privkey_A, pubkey_B, z);
		break;
	default: /* hw with sw fallback (default) */
		hardware = ALGO_SW;
		rc = ecdh_hw(adapter_handle, privkey_A, pubkey_B, z);
		if (rc == 0)
			hardware = ALGO_HW;
		else
			rc = ica_fallbacks_enabled ?
				ecdh_sw(privkey_A, pubkey_B, z) : ENODEV;
	}

	if (rc == 0)
		stats_increment(ICA_STATS_ECDH, hardware, ENCRYPT);

	return rc;
}

int ica_ecdsa_sign(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey, const unsigned char *hash, unsigned int hash_length,
		unsigned char *signature, unsigned int signature_length)
{
	int hardware, rc;
	unsigned int privlen = privlen_from_nid(privkey->nid);
	unsigned int icapath = 0;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (privkey == NULL || hash == NULL || !hash_length_valid(hash_length) ||
		signature == NULL || signature_length < 2*privlen)
		return EINVAL;

	icapath = getenv_icapath();
	switch (icapath) {
	case 1: /* hw only */
		hardware = ALGO_HW;
		rc = ecdsa_sign_hw(adapter_handle, privkey, hash, hash_length, signature);
		break;
	case 2: /* sw only */
		hardware = ALGO_SW;
		rc = ecdsa_sign_sw(privkey, hash, hash_length, signature);
		break;
	default: /* hw with sw fallback (default) */
		hardware = ALGO_SW;
		rc = ecdsa_sign_hw(adapter_handle, privkey, hash, hash_length, signature);
		if (rc == 0)
			hardware = ALGO_HW;
		else
			rc = ica_fallbacks_enabled ?
				ecdsa_sign_sw(privkey, hash, hash_length, signature) : ENODEV;
	}

	if (rc == 0)
		stats_increment(ICA_STATS_ECDSA_SIGN, hardware, ENCRYPT);

	return rc;
}

int ica_ecdsa_verify(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *pubkey, const unsigned char *hash, unsigned int hash_length,
		const unsigned char *signature, unsigned int signature_length)
{
	int hardware, rc;
	unsigned int privlen = privlen_from_nid(pubkey->nid);
	unsigned int icapath = 0;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (pubkey == NULL || hash == NULL || !hash_length_valid(hash_length) ||
		signature == NULL || signature_length < 2*privlen)
		return EINVAL;

	icapath = getenv_icapath();
	switch (icapath) {
	case 1: /* hw only */
		hardware = ALGO_HW;
		rc = ecdsa_verify_hw(adapter_handle, pubkey, hash, hash_length, signature);
		break;
	case 2: /* sw only */
		hardware = ALGO_SW;
		rc = ecdsa_verify_sw(pubkey, hash, hash_length, signature);
		break;
	default: /* hw with sw fallback (default) */
		hardware = ALGO_SW;
		rc = ecdsa_verify_hw(adapter_handle, pubkey, hash, hash_length, signature);
		if (rc == 0) {
			hardware = ALGO_HW;
		} else if (rc != EFAULT) {
			rc = ica_fallbacks_enabled ?
			     ecdsa_verify_sw(pubkey, hash, hash_length,
					     signature) : ENODEV;
		}
	}

	if (rc == 0)
		stats_increment(ICA_STATS_ECDSA_VERIFY, hardware, ENCRYPT);

	return rc;
}

int ica_ec_key_get_public_key(const ICA_EC_KEY *key, unsigned char *q, unsigned int *q_len)
{
	if (!key || !(key->X) || privlen_from_nid(key->nid) < 0)
		return EINVAL;

	memcpy(q, key->X, 2*privlen_from_nid(key->nid));
	*q_len = 2*privlen_from_nid(key->nid);

	return 0;
}

int ica_ec_key_get_private_key(const ICA_EC_KEY *key, unsigned char *d, unsigned int *d_len)
{
	if (!key || !(key->D) || privlen_from_nid(key->nid) < 0)
		return EINVAL;

	memcpy(d, key->D, privlen_from_nid(key->nid));
	*d_len = privlen_from_nid(key->nid);

	return 0;
}

void ica_ec_key_free(ICA_EC_KEY *key)
{
	if (!key)
		return;

	if (key->X) {
		/* free 1 block of memory for X, Y, and D */
		OPENSSL_cleanse((void *)key->X, 3*privlen_from_nid(key->nid));
		free(key->X);
	}

	OPENSSL_cleanse((void *)key, sizeof(ICA_EC_KEY));
	free(key);
}

/*
 *                             End of ECC API
 *
 ******************************************************************************/

unsigned int ica_des_encrypt(unsigned int mode,
			     unsigned int data_length,
			     unsigned char *input_data,
			     ica_des_vector_t *iv,
			     ica_des_key_single_t *des_key,
			     unsigned char *output_data)
{
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

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
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

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
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key(des_key))
		return EINVAL;
#endif /* ICA_FIPS */

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
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key(des_key))
		return EINVAL;
#endif /* ICA_FIPS */

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
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (check_aes_parms(mode, data_length, input_data,
			    (unsigned char *) iv, key_length, aes_key,
			    output_data))
		return EINVAL;

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
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	/* check for obvious errors in parms */
	if (check_aes_parms(mode, data_length, input_data,
			    (unsigned char *) iv, key_length, aes_key,
			    output_data))
		return EINVAL;

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
			 unsigned long data_length, unsigned char *key,
			 unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_ECB, data_length, in_data, NULL, key, out_data))
		return EINVAL;

	return s390_des_ecb(des_directed_fc(direction), data_length,
			    in_data, key, out_data);
}

unsigned int ica_des_cbc(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned char *iv,
			 unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_CBC, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_cbc(des_directed_fc(direction), data_length,
			    in_data, iv, key, out_data);
}

unsigned int ica_des_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			    unsigned long data_length,
			    unsigned char *key, unsigned char *iv,
			    unsigned int direction, unsigned int variant)
{
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_CBCCS, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_cbccs(des_directed_fc(direction),
			      in_data, out_data, data_length,
			      key, iv, variant);
}

unsigned int ica_des_cfb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned char *iv, unsigned int lcfb,
			 unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_CFB, data_length, in_data, iv, key, out_data))
		return EINVAL;
	/* The cipher feedback has to be between 1 and cipher block size. */
	if ((lcfb == 0) || (lcfb > DES_BLOCK_SIZE))
		return EINVAL;

	return s390_des_cfb(des_directed_fc(direction), data_length,
			    in_data, iv, key, out_data, lcfb);
}

unsigned int ica_des_ofb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned char *iv, unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_OFB, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_ofb(des_directed_fc(direction), data_length,
			    in_data, iv, key, out_data);
}

unsigned int ica_des_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 unsigned char *key,
			 unsigned char *ctr, unsigned int ctr_width,
			 unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

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
			     unsigned char *key,
			     const unsigned char *ctrlist,
			     unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_CTR, data_length, in_data, ctrlist, key, out_data))
		return EINVAL;

	return s390_des_ctrlist(des_directed_fc(direction),
				data_length, in_data, ctrlist,
				key, out_data);
}

unsigned int ica_des_cmac(const unsigned char *message, unsigned long message_length,
			  unsigned char *mac, unsigned int mac_length,
			  unsigned char *key,
			  unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

	return ica_des_cmac_last(message, message_length,
				 mac, mac_length,
				 key,
				 NULL,
				 direction);
}

unsigned int ica_des_cmac_intermediate(const unsigned char *message,
				       unsigned long message_length,
				       unsigned char *key,
				       unsigned char *iv)
{
	unsigned long function_code;
	int rc;

#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

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

	if(!rc)
		stats_increment(ICA_STATS_DES_CMAC, ALGO_HW, ICA_DECRYPT);
	return rc;
}

unsigned int ica_des_cmac_last(const unsigned char *message, unsigned long message_length,
			       unsigned char *mac, unsigned int mac_length,
			       unsigned char *key,
			       unsigned char *iv,
			       unsigned int direction)
{
	unsigned char tmp_mac[DES_BLOCK_SIZE];
	unsigned long function_code;
	int rc;

#ifdef ICA_FIPS
	if (fips)
		return EACCES;
#endif /* ICA_FIPS */

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
		else
			stats_increment(ICA_STATS_DES_CMAC, ALGO_HW, direction);
	} else {
		/* verify */
		rc = s390_cmac(function_code, message, message_length,
			       DES_BLOCK_SIZE, key, mac_length, tmp_mac, iv);
		if (rc)
			return rc;
		if (CRYPTO_memcmp(tmp_mac, mac, mac_length))
			return EFAULT;
		else
			stats_increment(ICA_STATS_DES_CMAC, ALGO_HW, direction);
	}

	return 0;
}

unsigned int ica_3des_ecb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, unsigned char *key,
			  unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_ECB, data_length, in_data, NULL, key, out_data))
		return EINVAL;

	return s390_des_ecb(tdes_directed_fc(direction), data_length,
			    in_data, key, out_data);
}

unsigned int ica_3des_cbc(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, unsigned char *key,
			  unsigned char *iv,
			  unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_CBC, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_cbc(tdes_directed_fc(direction), data_length,
			    in_data, iv, key, out_data);
}

unsigned int ica_3des_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     unsigned char *key, unsigned char *iv,
			     unsigned int direction, unsigned int variant)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_CBCCS, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_cbccs(tdes_directed_fc(direction),
			      in_data, out_data, data_length,
			      key, iv, variant);
}

unsigned int ica_3des_cfb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, unsigned char *key,
			  unsigned char *iv, unsigned int lcfb,
			  unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_CFB, data_length, in_data, iv, key, out_data))
		return EINVAL;
	/* The cipher feedback has to be between 1 and cipher block size. */
	if ((lcfb == 0) || (lcfb > DES_BLOCK_SIZE))
		return EINVAL;

	return s390_des_cfb(tdes_directed_fc(direction), data_length,
			    in_data, iv, key, out_data, lcfb);
}

unsigned int ica_3des_ofb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, unsigned char *key,
			  unsigned char *iv, unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_OFB, data_length, in_data, iv, key, out_data))
		return EINVAL;

	return s390_des_ofb(tdes_directed_fc(direction), data_length,
			    in_data, iv, key, out_data);
}

unsigned int ica_3des_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 unsigned char *key,
			 unsigned char *ctr, unsigned int ctr_width,
			 unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

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
			      unsigned char *key,
			      const unsigned char *ctrlist,
			      unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

	if (check_des_parms(MODE_CTR, data_length, in_data, ctrlist, key, out_data))
		return EINVAL;

	return s390_des_ctrlist(tdes_directed_fc(direction),
				data_length, in_data, ctrlist,
				key, out_data);
}

unsigned int ica_3des_cmac(const unsigned char *message, unsigned long message_length,
			   unsigned char *mac, unsigned int mac_length,
			   unsigned char *key,
			   unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

	return ica_3des_cmac_last(message, message_length,
				  mac, mac_length,
				  key,
				  NULL,
				  direction);
}

unsigned int ica_3des_cmac_intermediate(const unsigned char *message,
					unsigned long message_length,
					unsigned char *key,
					unsigned char *iv)
{
	unsigned long function_code;
	int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

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

	if (!rc)
		stats_increment(ICA_STATS_3DES_CMAC, ALGO_HW, DECRYPT);
	return rc;
}

unsigned int ica_3des_cmac_last(const unsigned char *message, unsigned long message_length,
				unsigned char *mac, unsigned int mac_length,
				unsigned char *key,
				unsigned char *iv,
				unsigned int direction)
{
	unsigned char tmp_mac[DES_BLOCK_SIZE];
	unsigned long function_code;
	int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (fips_check_3des_key((ica_des_key_triple_t *)key))
		return EINVAL;
#endif /* ICA_FIPS */

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
		else
			stats_increment(ICA_STATS_3DES_CMAC, ALGO_HW, direction);
	} else {
		/* verify */
		rc = s390_cmac(function_code, message, message_length,
			       3*DES_BLOCK_SIZE, key, mac_length, tmp_mac, iv);
		if (rc)
			return rc;
		if (CRYPTO_memcmp(tmp_mac, mac, mac_length))
			return EFAULT;
		else
			stats_increment(ICA_STATS_3DES_CMAC, ALGO_HW, direction);
	}

	return 0;
}

unsigned int ica_aes_ecb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned int key_length,
			 unsigned int direction)
{
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_aes_parms(MODE_ECB, data_length, in_data, NULL, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_ecb(function_code, data_length, in_data, key, out_data);
}

unsigned int ica_aes_cbc(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned int key_length, unsigned char *iv,
			 unsigned int direction)
{
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_aes_parms(MODE_CBC, data_length, in_data, iv, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_cbc(function_code, data_length, in_data, iv, key, out_data);
}

unsigned int ica_aes_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			    unsigned long data_length,
			    unsigned char *key, unsigned int key_length,
			    unsigned char *iv,
			    unsigned int direction, unsigned int variant)
{
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_aes_parms(MODE_CBCCS, data_length, in_data, iv, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_cbccs(function_code, in_data, out_data, data_length,
			      key, iv, variant);
}

unsigned int ica_aes_cfb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned int key_length, unsigned char *iv, unsigned int lcfb,
			 unsigned int direction)
{
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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
			 unsigned long data_length, unsigned char *key,
			 unsigned int key_length, unsigned char *iv,
			 unsigned int direction)
{
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_aes_parms(MODE_OFB, data_length, in_data, iv, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_ofb(function_code, data_length, in_data, iv, key, out_data);
}

unsigned int ica_aes_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 unsigned char *key, unsigned int key_length,
			 unsigned char *ctr, unsigned int ctr_width,
			 unsigned int direction)
{
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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
			     unsigned char *key, unsigned int key_length,
			     const unsigned char *ctrlist,
			     unsigned int direction)
{
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_aes_parms(MODE_CTR, data_length, in_data, ctrlist, key_length,
			    key, out_data))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	return s390_aes_ctrlist(function_code, data_length, in_data, ctrlist,
			    key, out_data);
}

unsigned int ica_aes_xts(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 unsigned char *key1, unsigned char *key2,
			 unsigned int key_length, unsigned char *tweak,
			 unsigned int direction)
{
	unsigned int function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
	if (!CRYPTO_memcmp(key1, key2, key_length))
		return EINVAL;
#endif /* ICA_FIPS */

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
			  unsigned char *key, unsigned int key_length,
			  unsigned int direction)
{
#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	return ica_aes_cmac_last(message, message_length,
				 mac, mac_length,
				 key, key_length,
				 NULL,
				 direction);
}

unsigned int ica_aes_cmac_intermediate(const unsigned char *message,
				       unsigned long message_length,
				       unsigned char *key, unsigned int key_length,
				       unsigned char *iv)
{
	unsigned long function_code;
	int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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

	if (!rc)
		stats_increment(ICA_STATS_AES_CMAC, ALGO_HW, ICA_DECRYPT);
	return rc;
}

unsigned int ica_aes_cmac_last(const unsigned char *message, unsigned long message_length,
			       unsigned char *mac, unsigned int mac_length,
			       unsigned char *key, unsigned int key_length,
			       unsigned char *iv,
			       unsigned int direction)
{
	unsigned char tmp_mac[AES_BLOCK_SIZE];
	unsigned long function_code;
	int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

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
		else
			stats_increment(ICA_STATS_AES_CMAC, ALGO_HW, direction);
	} else {
		/* verify */
		rc = s390_cmac(function_code, message, message_length,
			       key_length, key, mac_length, tmp_mac, iv);
		if (rc)
			return rc;
		if (CRYPTO_memcmp(tmp_mac, mac, mac_length))
			return EFAULT;
		else
			stats_increment(ICA_STATS_AES_CMAC, ALGO_HW, direction);
	}

	return 0;
}

unsigned int ica_aes_ccm(unsigned char *payload, unsigned long payload_length,
			 unsigned char *ciphertext_n_mac, unsigned int mac_length,
			 const unsigned char *assoc_data, unsigned long assoc_data_length,
			 const unsigned char *nonce, unsigned int nonce_length,
			 unsigned char *key, unsigned int key_length,
			 unsigned int direction)
{
	unsigned char tmp_mac[AES_BLOCK_SIZE];
	unsigned char *mac;
	unsigned long function_code;
	int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (check_aes_parms(MODE_CCM, payload_length, payload, nonce, key_length,
			    key, ciphertext_n_mac))
		return EINVAL;
	if (check_ccm_parms(payload_length, assoc_data_length,
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
		if (CRYPTO_memcmp((unsigned char *)(ciphertext_n_mac + payload_length),
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
			 unsigned char *key, unsigned int key_length,
			 unsigned int direction)
{
	unsigned char tmp_tag[AES_BLOCK_SIZE];
	unsigned long function_code;
	int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (plaintext_length != 0) {
		if (check_aes_parms(MODE_GCM, plaintext_length, plaintext, iv, key_length,
				    key, ciphertext))
			return EINVAL;
	} else {
		/* If only aad is processed (ghash), pt/ct may be NULL. */
		if (check_aes_parms(MODE_GCM, plaintext_length, (unsigned char *)1,
				    iv, key_length, key, (unsigned char *)1))
			return EINVAL;
	}
	if (check_gcm_parms(plaintext_length, aad_length, tag, tag_length, iv_length))
		return EINVAL;

	memset(tmp_tag, 0, sizeof(tmp_tag));

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

		if (CRYPTO_memcmp(tmp_tag, tag, tag_length))
			return EFAULT;
	}
	return 0;
}

unsigned int ica_aes_gcm_initialize(const unsigned char *iv,
				    unsigned int iv_length,
				    unsigned char *key,
				    unsigned int key_length,
				    unsigned char *icb,
				    unsigned char *ucb,
				    unsigned char *subkey,
				    unsigned int direction)
{
	unsigned long function_code;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	function_code = aes_directed_fc(key_length, direction);

	return s390_gcm_initialize(function_code, iv, iv_length,
							   key, icb, ucb, subkey);
}

unsigned int ica_aes_gcm_intermediate(unsigned char *plaintext,
			 unsigned long plaintext_length,
			 unsigned char *ciphertext,
			 unsigned char *cb,
			 unsigned char *aad, unsigned long aad_length,
			 unsigned char *tag, unsigned int tag_length,
			 unsigned char *key, unsigned int key_length,
			 unsigned char *subkey, unsigned int direction)
{
	unsigned long function_code;
	int rc, iv_length_dummy = 12;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (plaintext_length != 0) {
		if (check_aes_parms(MODE_GCM, plaintext_length, plaintext, cb, key_length,
				    key, ciphertext))
			return EINVAL;
	} else {
		/* If only aad is processed (ghash), pt/ct may be NULL. */
		if (check_aes_parms(MODE_GCM, plaintext_length, (unsigned char *)1,
				    cb, key_length, key, (unsigned char *)1))
			return EINVAL;
	}
	if (check_gcm_parms(plaintext_length, aad_length, tag, tag_length,
			    iv_length_dummy))
		return EINVAL;

	function_code = aes_directed_fc(key_length, direction);
	if (direction) {
		/* encrypt & generate */
		rc = s390_gcm_intermediate(function_code, plaintext, plaintext_length,
		    ciphertext, cb, aad, aad_length, tag, key, subkey);
		if (rc)
			return rc;
	} else {
		/* decrypt & verify */
		rc = s390_gcm_intermediate(function_code, plaintext, plaintext_length,
		    ciphertext, cb, aad, aad_length, tag, key, subkey);
		if (rc)
			return rc;
	}
	return 0;
}

unsigned int ica_aes_gcm_last( unsigned char *icb,
			 unsigned long aad_length, unsigned long ciph_length,
			 unsigned char *tag,
			 unsigned char *final_tag, unsigned int final_tag_length,
			 unsigned char *key, unsigned int key_length,
			 unsigned char *subkey, unsigned int direction)
{
	unsigned long function_code;
	int rc;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	function_code = aes_directed_fc(key_length, direction);
	if (direction) {
		/* encrypt & generate */
		rc = s390_gcm_last(function_code, icb, aad_length, ciph_length,
						   tag, AES_BLOCK_SIZE, key, subkey);
		if (rc)
			return rc;
	} else {
		/* decrypt & verify */
		rc = s390_gcm_last(function_code, icb, aad_length, ciph_length,
			      tag, AES_BLOCK_SIZE, key, subkey);
		if (rc)
			return rc;

		if (CRYPTO_memcmp(tag, final_tag, final_tag_length))
			return EFAULT;
	}
	return 0;
}

/*************************************************************************************
 *
 *                                     GCM(2) API
 */

kma_ctx* ica_aes_gcm_kma_ctx_new(void)
{
	kma_ctx* ctx = malloc(sizeof(kma_ctx));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(kma_ctx));

	return ctx;
}

int ica_aes_gcm_kma_init(unsigned int direction,
		const unsigned char *iv, unsigned int iv_length,
		const unsigned char *key, unsigned int key_length,
		kma_ctx* ctx)
{
	int rc = 0;
	unsigned long function_code = aes_directed_fc(key_length, direction);

	/* Check for obvious errors */
	if (!ctx || !key || iv_length == 0 || !is_valid_aes_key_length(key_length) ||
		!is_valid_direction(direction)) {
		return EINVAL;
	}

	memset(ctx, 0, sizeof(kma_ctx));
	ctx->version = 0x00;
	ctx->direction = direction;
	ctx->key_length = key_length;
	ctx->iv = (unsigned char*)iv;
	ctx->iv_length = iv_length;
	memcpy(&(ctx->key), key, key_length);

	/* Calculate subkey_h and j0 depending on iv_length */
	if (*s390_kma_functions[function_code].enabled && iv_length == GCM_RECOMMENDED_IV_LENGTH) {
		/* let KMA provide the subkey_h, j0 = iv || 00000001 */
		memcpy(&(ctx->j0), iv, iv_length);
		ctx->cv = 1;
		unsigned int* cv = (unsigned int*)&(ctx->j0[GCM_RECOMMENDED_IV_LENGTH]);
		*cv = 1;
	} else {
		/* Calculate subkey H and initial counter, based on iv */
		rc = s390_aes_ecb(UNDIRECTED_FC(function_code),
				AES_BLOCK_SIZE, zero_block,
				(unsigned char*)key, (unsigned char*)&(ctx->subkey_h));
		if (rc)
			return rc;
		__compute_j0(iv, iv_length, (const unsigned char*)&(ctx->subkey_h),
				(unsigned char*)&(ctx->j0));
		unsigned int *cv = (unsigned int*)&(ctx->j0[GCM_RECOMMENDED_IV_LENGTH]);
		ctx->cv = *cv;
		ctx->subkey_provided = 1;
	}

	return rc;
}

int ica_aes_gcm_kma_update(const unsigned char *in_data,
		unsigned char *out_data, unsigned long data_length,
		const unsigned char *aad, unsigned long aad_length,
		unsigned int end_of_aad, unsigned int end_of_data,
		kma_ctx* ctx)
{
	unsigned int function_code = aes_directed_fc(ctx->key_length, ctx->direction);

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if (data_length > 0 && (!in_data || !out_data))
		return EFAULT;

	if (!(*s390_kma_functions[function_code].enabled)) {

		if (end_of_aad && end_of_data && !ctx->intermediate) {
			ctx->done = 1;
			return s390_aes_gcm_simulate_kma_full(in_data, out_data, data_length,
									aad, aad_length, ctx);
		} else {
			ctx->intermediate = 1;
			return s390_aes_gcm_simulate_kma_intermediate(in_data, out_data, data_length,
									aad, aad_length, ctx);
		}

	} else {

		return s390_aes_gcm_kma(in_data, out_data, data_length,
								aad, aad_length, end_of_aad, end_of_data, ctx);
	}
}

int ica_aes_gcm_kma_get_tag(unsigned char *tag, unsigned int tag_length, const kma_ctx* ctx)
{
	int rc=0;
	unsigned int function_code = aes_directed_fc(ctx->key_length, ctx->direction);

	if (!ctx || !tag || !is_valid_tag_length(tag_length))
		return EINVAL;

	if (ctx->direction == ICA_DECRYPT)
		return EFAULT;

	if (!(*s390_kma_functions[function_code].enabled) && !ctx->done) {
		rc = s390_gcm_last(function_code, (unsigned char*)ctx->j0,
				ctx->total_aad_length, ctx->total_input_length,
				(unsigned char*)ctx->tag, AES_BLOCK_SIZE,
				(unsigned char*)ctx->key, (unsigned char*)ctx->subkey_h);
		if (rc)
			return rc;
	}

	memcpy(tag, ctx->tag, tag_length);

	return 0;
}

int ica_aes_gcm_kma_verify_tag(const unsigned char* known_tag, unsigned int tag_length, const kma_ctx* ctx)
{
	int rc;
	unsigned int function_code = aes_directed_fc(ctx->key_length, ctx->direction);

	if (!ctx || !known_tag || !is_valid_tag_length(tag_length))
		return EINVAL;

	if (ctx->direction == ICA_ENCRYPT)
		return EFAULT;

	if (!(*s390_kma_functions[function_code].enabled) && !ctx->done) {
		rc = s390_gcm_last(function_code, (unsigned char*)ctx->j0,
				ctx->total_aad_length, ctx->total_input_length,
				(unsigned char*)ctx->tag, AES_BLOCK_SIZE,
				(unsigned char*)ctx->key, (unsigned char*)ctx->subkey_h);
		if (rc)
			return rc;
	}

	if (CRYPTO_memcmp(ctx->tag, known_tag, tag_length) != 0)
		return EFAULT;

	return 0;
}

void ica_aes_gcm_kma_ctx_free(kma_ctx* ctx)
{
    if (!ctx)
	return;

    OPENSSL_cleanse((void *)ctx, sizeof(kma_ctx));

    free(ctx);
}

/**
 *                             End of GCM(2) API
 *
 ***************************************************************************************/

unsigned int ica_get_version(libica_version_info *version_info)
{
#ifdef VERSION
	int rc;
	int i;
	char *pch;
	char *saveptr;

	int length = strnlen(VERSION, MAX_VERSION_LENGTH);
	char buffer[length+1];

	if (version_info == NULL) {
		return EINVAL;
	}

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

/*
 * ica_drbg: libica's Deterministic Random Bit Generator
 *	     (conforming to NIST SP 800-90A)
 */
ica_drbg_mech_t *const ICA_DRBG_SHA512 = &DRBG_SHA512;

static inline int ica_drbg_error(int status)
{
	switch(status){
	case 0:
		return 0;
	case DRBG_RESEED_REQUIRED:
	case DRBG_NONCE_INV:
		return EPERM;
	case DRBG_NOMEM:
		return ENOMEM;
	case DRBG_SH_INV:
	case DRBG_MECH_INV:
	case DRBG_PERS_INV:
	case DRBG_ADD_INV:
	case DRBG_REQUEST_INV:
		return EINVAL;
	case DRBG_SEC_NOTSUPP:
	case DRBG_PR_NOTSUPP:
		return ENOTSUP;
	case DRBG_HEALTH_TEST_FAIL:
		return ICA_DRBG_HEALTH_TEST_FAIL;
	case DRBG_ENTROPY_SOURCE_FAIL:
		return ICA_DRBG_ENTROPY_SOURCE_FAIL;
	default:
		return -1;	/* unreachable */
	}
}

int ica_drbg_instantiate(ica_drbg_t **sh,
			 int sec,
			 bool pr,
			 ica_drbg_mech_t *mech,
			 const unsigned char *pers,
			 size_t pers_len)
{
	int status;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	status = drbg_mech_valid(mech);
	if(status)
		return ica_drbg_error(status);

	/* Run instantiate health test (11.3.2). */
	pthread_rwlock_wrlock(&mech->lock);
	status = drbg_health_test(drbg_instantiate, sec, pr, mech);
	pthread_rwlock_unlock(&mech->lock);
	if(status)
		return ica_drbg_error(status);

	/* Instantiate. */
	status = drbg_instantiate(sh, sec, pr, mech, pers, pers_len, false,
				  NULL, 0, NULL, 0);
	if(0 > status)
		mech->error_state = status;

	return ica_drbg_error(status);
}

int ica_drbg_reseed(ica_drbg_t *sh,
		    bool pr,
		    const unsigned char *add,
		    size_t add_len)
{
	int status;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if(!sh)
		return ica_drbg_error(DRBG_SH_INV);
	status = drbg_mech_valid(sh->mech);
	if(status)
		return ica_drbg_error(status);

	/* Reseed health test runs whenever generate is tested (11.3.4). */

	/* Reseed. */
	status = drbg_reseed(sh, pr, add, add_len, false, NULL, 0);
	if(0 > status)
		sh->mech->error_state = status;

	return ica_drbg_error(status);
}

int ica_drbg_generate(ica_drbg_t *sh,
		      int sec,
		      bool pr,
		      const unsigned char *add,
		      size_t add_len,
		      unsigned char *prnd,
		      size_t prnd_len)
{
	int status;

#ifdef ICA_FIPS
	if (fips >> 1)
		return EACCES;
#endif /* ICA_FIPS */

	if(!sh)
		return ica_drbg_error(DRBG_SH_INV);
	status = drbg_mech_valid(sh->mech);
	if(status)
		return ica_drbg_error(status);

	/* Run generate and reseed health tests before first use of these
	 * functions and when indicated by the test counter (11.3.3). */
	pthread_rwlock_wrlock(&sh->mech->lock);
	if(!(sh->mech->test_ctr %= sh->mech->test_intervall)){
		status = drbg_health_test(drbg_reseed, sec, pr, sh->mech);
		if(!status)
			status = drbg_health_test(drbg_generate, sec, pr,
						  sh->mech);
		if(status){
			pthread_rwlock_unlock(&sh->mech->lock);
			return ica_drbg_error(status);
		}
	}
	sh->mech->test_ctr++;
	pthread_rwlock_unlock(&sh->mech->lock);

	/* Generate. */
	status = pthread_rwlock_rdlock(&sh->mech->lock);
	if(EAGAIN == status)
		return ica_drbg_error(DRBG_REQUEST_INV);
	status = drbg_generate(sh, sec, pr, add, add_len, false, NULL, 0, prnd,
			       prnd_len);
	pthread_rwlock_unlock(&sh->mech->lock);
	if(0 > status)
		sh->mech->error_state = status;

	/* Inhibit output if mechanism is in error state (11.3.6). */
	if(sh->mech->error_state)
		drbg_zmem(prnd, prnd_len);

	return ica_drbg_error(status);
}

int ica_drbg_uninstantiate(ica_drbg_t **sh)
{
	/* Uninstantiate health test runs whenever other functions are
	 * tested (11.3.5). */

	/* Uninstantiate. */
	return ica_drbg_error(drbg_uninstantiate(sh, false));
}

int ica_drbg_health_test(void *func,
			 int sec,
			 bool pr,
			 ica_drbg_mech_t *mech)
{
	int status;

	status = drbg_mech_valid(mech);
	if(status)
		return ica_drbg_error(status);

	/* Health test. */
	pthread_rwlock_wrlock(&mech->lock);
	if(ica_drbg_instantiate == func)
		status = drbg_health_test(drbg_instantiate, sec, pr, mech);
	else if(ica_drbg_reseed == func)
		status = drbg_health_test(drbg_reseed, sec, pr, mech);
	else if(ica_drbg_generate == func){
		status = drbg_health_test(drbg_reseed, sec, pr, mech);
		if(!status)
			status = drbg_health_test(drbg_generate, sec, pr,
						  mech);
		mech->test_ctr = 1; /* reset test counter */
	}
	else
		status = DRBG_REQUEST_INV;
	pthread_rwlock_unlock(&mech->lock);

	return ica_drbg_error(status);
}

#ifdef ICA_FIPS

int
ica_fips_status(void)
{
	return fips;
}

void
ica_fips_powerup_tests(void)
{
	fips_powerup_tests();
}

#endif /* ICA_FIPS */
