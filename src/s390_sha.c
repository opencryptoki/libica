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
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "fips.h"
#include "s390_crypto.h"
#include "s390_sha.h"
#include "init.h"
#include "icastats.h"

static int s390_sha1_sw(unsigned char *iv, unsigned char *input_data,
			unsigned int input_length, unsigned char *output_data,
			unsigned int message_part, uint64_t *running_length)
{
	SHA_CTX ctx;
	unsigned int vector_length = 20;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

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

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FIRST) {
		SHA224_Init(&ctx);
	} else {
		ctx.Nl = *running_length;
		memcpy((unsigned char *) &ctx.h[0], iv, vector_length);
		ctx.md_len = SHA224_DIGEST_LENGTH;
		ctx.num = 0;
	}

	SHA224_Update(&ctx, input_data, input_length);

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FINAL) {
		SHA224_Final(output_data, &ctx);
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

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FIRST) {
		SHA256_Init(&ctx);
	} else {
		ctx.Nl = *running_length;
		memcpy((unsigned char *) &ctx.h[0], iv, vector_length);
		ctx.md_len = SHA256_DIGEST_LENGTH;
		ctx.num = 0;
	}

	SHA256_Update(&ctx, input_data, input_length);

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FINAL) {
		SHA256_Final(output_data, &ctx);
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

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

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

	SHA384_Update(&ctx, input_data, input_length);

	if (message_part == SHA_MSG_PART_ONLY ||
	    message_part == SHA_MSG_PART_FINAL)
		SHA384_Final(output_data, &ctx);
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

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

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

int s390_sha512_224_sw(unsigned char *iv, unsigned char *input_data,
		       uint64_t input_length, unsigned char *output_data,
		       unsigned int message_part, uint64_t *running_length_lo,
		       uint64_t *running_length_hi)
{
	SHA512_CTX ctx;
	unsigned int vector_length = 64;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	if (message_part == SHA_MSG_PART_ONLY || message_part == SHA_MSG_PART_FIRST) {
		SHA512_Init(&ctx);
		/* SHA-512/224 uses a distinct initial hash value */
		ctx.h[0] = U64(0x8c3d37c819544da2);
		ctx.h[1] = U64(0x73e1996689dcd4d6);
		ctx.h[2] = U64(0x1dfab7ae32ff9c82);
		ctx.h[3] = U64(0x679dd514582f9fcf);
		ctx.h[4] = U64(0x0f6d2b697bd44da8);
		ctx.h[5] = U64(0x77e36f7304c48942);
		ctx.h[6] = U64(0x3f9d85a86a1d36c8);
		ctx.h[7] = U64(0x1112e6ad91d692a1);
	} else {
		ctx.md_len = SHA224_DIGEST_LENGTH;
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
		       SHA224_DIGEST_LENGTH);
		memcpy(iv, (unsigned char *) &ctx.h[0], vector_length);
	}

	return 0;
}

int s390_sha512_256_sw(unsigned char *iv, unsigned char *input_data,
		       uint64_t input_length, unsigned char *output_data,
		       unsigned int message_part, uint64_t *running_length_lo,
		       uint64_t *running_length_hi)
{
	SHA512_CTX ctx;
	unsigned int vector_length = 64;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	if (message_part == SHA_MSG_PART_ONLY || message_part == SHA_MSG_PART_FIRST) {
		SHA512_Init(&ctx);
		/* SHA-512/256 uses a distinct initial hash value */
		ctx.h[0] = U64(0x22312194fc2bf72c);
		ctx.h[1] = U64(0x9f555fa3c84c64c2);
		ctx.h[2] = U64(0x2393b86b6f53b151);
		ctx.h[3] = U64(0x963877195940eabd);
		ctx.h[4] = U64(0x96283ee2a88effe3);
		ctx.h[5] = U64(0xbe5e1e2553863992);
		ctx.h[6] = U64(0x2b0199fc2c85b8aa);
		ctx.h[7] = U64(0x0eb72ddc81c52ca2);
	} else {
		ctx.md_len = SHA256_DIGEST_LENGTH;
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
		       SHA256_DIGEST_LENGTH);
		memcpy(iv, (unsigned char *) &ctx.h[0], vector_length);
	}

	return 0;
}

int s390_sha1(unsigned char *iv, unsigned char *input_data,
	      unsigned int input_length, unsigned char *output_data,
	      unsigned int message_part, uint64_t *running_length)
{
	int rc = ENODEV;
	if (sha1_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_1].hash_length,
				 message_part, running_length, NULL, SHA_1);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_sha1_sw(iv, input_data, input_length, output_data,
				  message_part, running_length);
		stats_increment(ICA_STATS_SHA1, ALGO_SW, ENCRYPT);
	} else
		stats_increment(ICA_STATS_SHA1, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_sha224(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length)
{
	int rc = ENODEV;
	if (sha256_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_224].hash_length,
				 message_part, running_length, NULL, SHA_224);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_sha224_sw(iv, input_data, input_length, output_data,
				  message_part, running_length);
		stats_increment(ICA_STATS_SHA224, ALGO_SW, ENCRYPT);
	} else
		stats_increment(ICA_STATS_SHA224, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_sha256(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length)
{
	int rc = ENODEV;
	if (sha256_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_256].hash_length,
				 message_part, running_length, NULL, SHA_256);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_sha256_sw(iv, input_data, input_length, output_data,
				    message_part, running_length);
		stats_increment(ICA_STATS_SHA256, ALGO_SW, ENCRYPT);
	} else
		stats_increment(ICA_STATS_SHA256, ALGO_HW, ENCRYPT);

	return rc;
}
int s390_sha384(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi)
{
	int rc = ENODEV;
	if (sha512_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				 sha_constants[SHA_384].hash_length,
				 message_part, running_length_lo,
				 running_length_hi, SHA_384);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_sha384_sw(iv, input_data, input_length, output_data,
				    message_part, running_length_lo,
				    running_length_hi);
		stats_increment(ICA_STATS_SHA384, ALGO_SW, ENCRYPT);
	} else
		stats_increment(ICA_STATS_SHA384, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_sha512(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi)
{
	int rc = ENODEV;
	if (sha512_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_512].hash_length,
				 message_part, running_length_lo,
				 running_length_hi, SHA_512);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_sha512_sw(iv, input_data, input_length, output_data,
				    message_part, running_length_lo,
				    running_length_hi);
		stats_increment(ICA_STATS_SHA512, ALGO_SW, ENCRYPT);
	} else
		stats_increment(ICA_STATS_SHA512, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_sha512_224(unsigned char *iv, unsigned char *input_data,
		    uint64_t input_length, unsigned char *output_data,
		    unsigned int message_part, uint64_t *running_length_lo,
		    uint64_t *running_length_hi)
{
	int rc = ENODEV;
	if (sha512_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_512_224].hash_length,
				 message_part, running_length_lo,
				 running_length_hi, SHA_512_224);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_sha512_224_sw(iv, input_data, input_length, output_data,
					message_part, running_length_lo,
					running_length_hi);
		stats_increment(ICA_STATS_SHA512_224, ALGO_SW, ENCRYPT);
	} else
		stats_increment(ICA_STATS_SHA512_224, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_sha512_256(unsigned char *iv, unsigned char *input_data,
		    uint64_t input_length, unsigned char *output_data,
		    unsigned int message_part, uint64_t *running_length_lo,
		    uint64_t *running_length_hi)
{
	int rc = ENODEV;
	if (sha512_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_512_256].hash_length,
				 message_part, running_length_lo,
				 running_length_hi, SHA_512_256);
	if (rc) {
		if (!ica_fallbacks_enabled)
			return rc;
		rc = s390_sha512_256_sw(iv, input_data, input_length, output_data,
					message_part, running_length_lo,
					running_length_hi);
		stats_increment(ICA_STATS_SHA512_256, ALGO_SW, ENCRYPT);
	} else
		stats_increment(ICA_STATS_SHA512_256, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_sha3_224(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length)
{
	int rc = ENODEV;

	if (sha3_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_3_224].hash_length,
				 message_part, running_length, NULL, SHA_3_224);
	if (rc == 0)
		stats_increment(ICA_STATS_SHA3_224, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_sha3_256(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length)
{
	int rc = ENODEV;

	if (sha3_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_3_256].hash_length,
				 message_part, running_length, NULL, SHA_3_256);
	if (rc == 0)
		stats_increment(ICA_STATS_SHA3_256, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_sha3_384(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi)
{
	int rc = ENODEV;

	if (sha3_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_3_384].hash_length,
				 message_part, running_length_lo,
				 running_length_hi, SHA_3_384);
	if (rc == 0)
		stats_increment(ICA_STATS_SHA3_384, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_sha3_512(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi)
{
	int rc = ENODEV;

	if (sha3_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_3_512].hash_length,
				 message_part, running_length_lo,
				 running_length_hi, SHA_3_512);
	if (rc == 0)
		stats_increment(ICA_STATS_SHA3_512, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_shake_128(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data, unsigned int output_length,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi)
{
	int rc = ENODEV;

	if (sha3_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data, output_length,
				 message_part, running_length_lo,
				 running_length_hi, SHAKE_128);
	if (rc == 0)
		stats_increment(ICA_STATS_SHAKE_128, ALGO_HW, ENCRYPT);

	return rc;
}

int s390_shake_256(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data, unsigned int output_length,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi)
{
	int rc = ENODEV;

	if (sha3_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data, output_length,
				 message_part, running_length_lo,
				 running_length_hi, SHAKE_256);
	if (rc == 0)
		stats_increment(ICA_STATS_SHAKE_256, ALGO_HW, ENCRYPT);

	return rc;
}
