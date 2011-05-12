/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 * 	    Holger Dengler <hd@linux.vnet.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2011
 */

#include <string.h>
#include <errno.h>
#include <openssl/sha.h>

#include "s390_crypto.h"
#include "s390_sha.h"
#include "init.h"
#include "icastats.h"

unsigned char SHA_1_DEFAULT_IV[] = {
	0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe,
	0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0 };

unsigned char SHA_224_DEFAULT_IV[] = {
	0xc1, 0x05, 0x9e, 0xd8, 0x36, 0x7c, 0xd5, 0x07, 0x30, 0x70, 0xdd, 0x17,
	0xf7, 0x0e, 0x59, 0x39, 0xff, 0xc0, 0x0b, 0x31, 0x68, 0x58, 0x15, 0x11,
	0x64, 0xf9, 0x8f, 0xa7, 0xbe, 0xfa, 0x4f, 0xa4 };

unsigned char SHA_256_DEFAULT_IV[]  = {
	0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72,
	0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
	0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19 };

unsigned char SHA_384_DEFAULT_IV[] = {
	0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8, 0x62, 0x9a, 0x29, 0x2a,
	0x36, 0x7c, 0xd5, 0x07, 0x91, 0x59, 0x01, 0x5a, 0x30, 0x70, 0xdd, 0x17,
	0x15, 0x2f, 0xec, 0xd8, 0xf7, 0x0e, 0x59, 0x39, 0x67, 0x33, 0x26, 0x67,
	0xff, 0xc0, 0x0b, 0x31, 0x8e, 0xb4, 0x4a, 0x87, 0x68, 0x58, 0x15, 0x11,
	0xdb, 0x0c, 0x2e, 0x0d, 0x64, 0xf9, 0x8f, 0xa7, 0x47, 0xb5, 0x48, 0x1d,
	0xbe, 0xfa, 0x4f, 0xa4 };

unsigned char SHA_512_DEFAULT_IV[] = {
	0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85,
	0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
	0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f,
	0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
	0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19,
	0x13, 0x7e, 0x21, 0x79 };

typedef struct {
	unsigned int hw_function_code;
	unsigned int hash_length;
	unsigned int vector_length;
	unsigned int block_length;
	unsigned char *default_iv;
} SHA_CONSTANTS;

static const SHA_CONSTANTS sha_constants[] = {
	{S390_CRYPTO_SHA_1, 20, 20, 64, SHA_1_DEFAULT_IV},
	{S390_CRYPTO_SHA_256, 28, 32, 64, SHA_224_DEFAULT_IV},
	{S390_CRYPTO_SHA_256, 32, 32, 64, SHA_256_DEFAULT_IV},
	{S390_CRYPTO_SHA_512, 48, 64, 128, SHA_384_DEFAULT_IV},
	{S390_CRYPTO_SHA_512, 64, 64, 128, SHA_512_DEFAULT_IV}
};

static int s390_sha_hw(unsigned char *iv, unsigned char *input_data,
		       uint64_t input_length, unsigned char *output_data,
		       unsigned int message_part, uint64_t *running_length_lo,
		       uint64_t *running_length_hi, kimd_functions_t sha_function)
{
	int rc = 0;

	uint64_t sum_lo = 0, sum_hi = 0;
	unsigned long remnant = 0;
	int complete_blocks_length = 0;

	unsigned char *default_iv  = sha_constants[sha_function].default_iv;
	unsigned int hash_length   = sha_constants[sha_function].hash_length;
	unsigned int vector_length = sha_constants[sha_function].vector_length;

	/* A internal buffer for the SHA hash and stream bit length. For SHA512
	 * this can be at most 128 byte for the hash plus 16 byte for the
	 * stream length. */
	unsigned char shabuff[128 + 16];

	if (input_length) {
		remnant = input_length % sha_constants[sha_function].block_length;
		complete_blocks_length = input_length - remnant;
	}

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FIRST) {
		memcpy(shabuff, default_iv, vector_length);
		*running_length_lo = 0;
		if (running_length_hi)
			*running_length_hi = 0;
	}
	else
		memcpy(shabuff, (void *)iv, vector_length);

	sum_lo = *running_length_lo;
	if(running_length_hi)
		sum_hi = *running_length_hi;

	if ((message_part == SHA_MSG_PART_FIRST ||
	     message_part == SHA_MSG_PART_MIDDLE) && (remnant != 0))
		return EINVAL;

	unsigned int hw_function_code;
	hw_function_code = sha_constants[sha_function].hw_function_code;
	if (complete_blocks_length) {
		rc = s390_kimd(hw_function_code, shabuff, input_data,
			       complete_blocks_length);
		if (rc > 0) {
		/* Check for overflow in sum_lo */
			sum_lo += rc;
			if(sum_lo < *running_length_lo || sum_lo < rc)
				sum_hi += 1;
			rc = 0;
		}
	}

	if (rc == 0 && (message_part == SHA_MSG_PART_ONLY ||
			message_part == SHA_MSG_PART_FINAL)) {
		sum_lo += (uint64_t)remnant;
		if(sum_lo < remnant)
			sum_hi += 1;

		if(running_length_hi){
			sum_hi = (sum_hi << 3) + (sum_lo >> (64 - 3));
			sum_lo = sum_lo << 3;
			memcpy(shabuff + vector_length,
			       (unsigned char *)&sum_hi, sizeof(sum_hi));
			memcpy(shabuff + vector_length + sizeof(sum_hi),
			       (unsigned char *)&sum_lo, sizeof(sum_lo));
		}
		else {
			sum_lo = sum_lo << 3;
			memcpy(shabuff + vector_length,
			       (unsigned char *)&sum_lo, sizeof(sum_lo));
		}
		rc = s390_klmd(hw_function_code, shabuff,
			       input_data + complete_blocks_length, remnant);
		if (rc > 0)
			rc = 0;
	}

	if (rc == 0) {
		memcpy((void *)output_data, shabuff, hash_length);
		if (message_part != SHA_MSG_PART_FINAL &&
		    message_part != SHA_MSG_PART_ONLY) {
			memcpy((void *)iv, shabuff, vector_length);
			*running_length_lo = sum_lo;
			if(running_length_hi)
				*running_length_hi = sum_hi;
		}
	}

	if (rc < 0)
		return EIO;

	return rc;
}

static int s390_sha1_sw(unsigned char *iv, unsigned char *input_data,
			unsigned int input_length, unsigned char *output_data,
			unsigned int message_part, uint64_t *running_length)
{
	SHA_CTX ctx;
	unsigned int vector_length = 20;

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FIRST) {
		SHA1_Init(&ctx);
	} else {
		memcpy((unsigned char *) &ctx.Nl,
		       (unsigned char *) running_length,
		       sizeof(*running_length));
		memcpy((unsigned char *) &ctx.h0, iv, vector_length);
		ctx.num = 0;
	}

	SHA1_Update(&ctx, input_data, input_length);
	
	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FINAL) {
		SHA1_Final(output_data, &ctx);
	} else {
		memcpy((unsigned char *) running_length,
		       (unsigned char *) &ctx.Nl,
		       sizeof(*running_length));
		memcpy(output_data, (unsigned char *) &ctx.h0,
		       SHA_DIGEST_LENGTH);
		memcpy(iv, (unsigned char *) &ctx.h0, vector_length);
	}
	
	return 0;
}

static int s390_sha224_sw(unsigned char *iv, unsigned char *input_data,
			  unsigned int input_length,
			  unsigned char *output_data,
			  unsigned int message_part, uint64_t *running_length)
{
	SHA256_CTX ctx;
	unsigned int vector_length = 32;

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FIRST) {
		SHA224_Init(&ctx);
	} else {
		ctx.Nl = *running_length;
		memcpy((unsigned char *) &ctx.h[0], iv, vector_length);
		ctx.md_len = SHA224_DIGEST_LENGTH;
		ctx.num = 0;
	}

	int rc = SHA224_Update(&ctx, input_data, input_length);
	
	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FINAL) {
		rc = SHA224_Final(output_data, &ctx);
	} else {
		*running_length = ctx.Nl;
		memcpy(output_data, (unsigned char *) &ctx.h[0],
		       SHA224_DIGEST_LENGTH);
		memcpy(iv, (unsigned char *) &ctx.h[0], vector_length);
	}
	
	return 0;
}

static int s390_sha256_sw(unsigned char *iv, unsigned char *input_data,
			  unsigned int input_length,
			  unsigned char *output_data,
			  unsigned int message_part, uint64_t *running_length)
{
	SHA256_CTX ctx;
	unsigned int vector_length = 32;

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FIRST) {
		SHA256_Init(&ctx);
	} else {
		ctx.Nl = *running_length;
		memcpy((unsigned char *) &ctx.h[0], iv, vector_length);
		ctx.md_len = SHA256_DIGEST_LENGTH;
		ctx.num = 0;
	}

	int rc = SHA256_Update(&ctx, input_data, input_length);
	
	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FINAL) {
		rc = SHA256_Final(output_data, &ctx);
	} else {
		*running_length = ctx.Nl;
		memcpy(output_data, (unsigned char *) &ctx.h[0],
		       SHA256_DIGEST_LENGTH);
		memcpy(iv, (unsigned char *) &ctx.h[0], vector_length);
	}
	
	return 0;
}

static int s390_sha384_sw(unsigned char *iv, unsigned char *input_data,
			  uint64_t input_length,
			  unsigned char *output_data,
			  unsigned int message_part,
			  uint64_t *running_length_lo,
			  uint64_t *running_length_hi)
{
	SHA512_CTX ctx;
	unsigned int vector_length = 64;

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FIRST) {
		SHA384_Init(&ctx);
	} else {
		ctx.Nl = *running_length_lo;
		ctx.Nh = *running_length_hi;
		ctx.num = 0;
		ctx.md_len = SHA384_DIGEST_LENGTH;
		memcpy((unsigned char *) &ctx.h[0], iv, vector_length);
	}

	int rc = SHA384_Update(&ctx, input_data, input_length);
	
	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FINAL)
		rc = SHA384_Final(output_data, &ctx);
	else {
		*running_length_lo = ctx.Nl;
		*running_length_hi = ctx.Nh;
		memcpy(output_data, (unsigned char *) &ctx.h[0],
		       SHA384_DIGEST_LENGTH);
		memcpy(iv, (unsigned char *) &ctx.h[0], vector_length);
	}
	
	return 0;
}
int s390_sha512_sw(unsigned char *iv, unsigned char *input_data,
		   uint64_t input_length, unsigned char *output_data,
		   unsigned int message_part, uint64_t *running_length_lo,
		   uint64_t *running_length_hi)
{
	SHA512_CTX ctx;
	unsigned int vector_length = 64;

	if (message_part == SHA_MSG_PART_ONLY || message_part == SHA_MSG_PART_FIRST) {
		SHA512_Init(&ctx);
	} else {
		ctx.md_len = SHA512_DIGEST_LENGTH;
		ctx.Nl = *running_length_lo;
		ctx.Nh = *running_length_hi;
		ctx.num = 0;
		memcpy((unsigned char *) &ctx.h[0], iv, vector_length);
	}

	SHA512_Update(&ctx, input_data, input_length);
	
	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FINAL)
		SHA512_Final(output_data, &ctx);
	else {
		*running_length_lo = ctx.Nl;
		*running_length_hi = ctx.Nh;
		memcpy(output_data, (unsigned char *) &ctx.h[0],
		       SHA512_DIGEST_LENGTH);
		memcpy(iv, (unsigned char *) &ctx.h[0], vector_length);
	}
	
	return 0;
}

int s390_sha1(unsigned char *iv, unsigned char *input_data,
	      unsigned int input_length, unsigned char *output_data,
	      unsigned int message_part, uint64_t *running_length)
{
	int rc = 1;
	if (sha1_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				 message_part, running_length, NULL, SHA_1);
	if (rc) {
		rc = s390_sha1_sw(iv, input_data, input_length, output_data,
				  message_part, running_length);
		stats_increment(ICA_STATS_SHA1, 0);
	} else
		stats_increment(ICA_STATS_SHA1, 1);

	return rc;
}

int s390_sha224(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length)
{
	int rc = 1;
	if (sha256_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				 message_part, running_length, NULL, SHA_224);
	if (rc) {
		rc = s390_sha224_sw(iv, input_data, input_length, output_data,
				  message_part, running_length);
		stats_increment(ICA_STATS_SHA224, 0);
	} else
		stats_increment(ICA_STATS_SHA224, 1);

	return rc;
}

int s390_sha256(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length)
{
	int rc = 1;
	if (sha256_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				 message_part, running_length, NULL, SHA_256);
	if (rc) {
		rc = s390_sha256_sw(iv, input_data, input_length, output_data,
				    message_part, running_length);
		stats_increment(ICA_STATS_SHA256, 0);
	} else
		stats_increment(ICA_STATS_SHA256, 1);

	return rc;
}
int s390_sha384(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi)
{
	int rc = 1;
	if (sha512_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				 message_part, running_length_lo,
				 running_length_hi, SHA_384);
	if (rc) {
		rc = s390_sha384_sw(iv, input_data, input_length, output_data,
				    message_part, running_length_lo,
				    running_length_hi);
		stats_increment(ICA_STATS_SHA384, 0);
	} else
		stats_increment(ICA_STATS_SHA384, 1);

	return rc;
}

int s390_sha512(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi)
{
	int rc = 1;
	if (sha512_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				 message_part, running_length_lo,
				 running_length_hi, SHA_512);
	if (rc) {
		rc = s390_sha512_sw(iv, input_data, input_length, output_data,
				    message_part, running_length_lo,
				    running_length_hi);
		stats_increment(ICA_STATS_SHA512, 0);
	} else
		stats_increment(ICA_STATS_SHA512, 1);

	return rc;
}
