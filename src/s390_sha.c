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
 * Copyright IBM Corp. 2009, 2021
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

int s390_sha1(unsigned char *iv, unsigned char *input_data,
	      unsigned int input_length, unsigned char *output_data,
	      unsigned int message_part, uint64_t *running_length)
{
	int rc = ENODEV;
	if (sha1_switch)
		rc = s390_sha_hw(iv, input_data, input_length, output_data,
				sha_constants[SHA_1].hash_length,
				 message_part, running_length, NULL, SHA_1);

	if (rc == 0)
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

	if (rc == 0)
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

	if (rc == 0)
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

	if (rc == 0)
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

	if (rc == 0)
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

	if (rc == 0)
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

	if (rc == 0)
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
