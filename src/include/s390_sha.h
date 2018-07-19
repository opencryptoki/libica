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

#ifndef S390_SHA_H
#define S390_SHA_H

static unsigned char SHA_1_DEFAULT_IV[] = {
	0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe,
	0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0 };

static unsigned char SHA_224_DEFAULT_IV[] = {
	0xc1, 0x05, 0x9e, 0xd8, 0x36, 0x7c, 0xd5, 0x07, 0x30, 0x70, 0xdd, 0x17,
	0xf7, 0x0e, 0x59, 0x39, 0xff, 0xc0, 0x0b, 0x31, 0x68, 0x58, 0x15, 0x11,
	0x64, 0xf9, 0x8f, 0xa7, 0xbe, 0xfa, 0x4f, 0xa4 };

static unsigned char SHA_256_DEFAULT_IV[]  = {
	0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72,
	0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
	0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19 };

static unsigned char SHA_384_DEFAULT_IV[] = {
	0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8, 0x62, 0x9a, 0x29, 0x2a,
	0x36, 0x7c, 0xd5, 0x07, 0x91, 0x59, 0x01, 0x5a, 0x30, 0x70, 0xdd, 0x17,
	0x15, 0x2f, 0xec, 0xd8, 0xf7, 0x0e, 0x59, 0x39, 0x67, 0x33, 0x26, 0x67,
	0xff, 0xc0, 0x0b, 0x31, 0x8e, 0xb4, 0x4a, 0x87, 0x68, 0x58, 0x15, 0x11,
	0xdb, 0x0c, 0x2e, 0x0d, 0x64, 0xf9, 0x8f, 0xa7, 0x47, 0xb5, 0x48, 0x1d,
	0xbe, 0xfa, 0x4f, 0xa4 };

static unsigned char SHA_512_DEFAULT_IV[] = {
	0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85,
	0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
	0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f,
	0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
	0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19,
	0x13, 0x7e, 0x21, 0x79 };

static unsigned char SHA_512_224_DEFAULT_IV[] = {
	0x8C, 0x3D, 0x37, 0xC8, 0x19, 0x54, 0x4D, 0xA2, 0x73, 0xE1, 0x99, 0x66,
	0x89, 0xDC, 0xD4, 0xD6, 0x1D, 0xFA, 0xB7, 0xAE, 0x32, 0xFF, 0x9C, 0x82,
	0x67, 0x9D, 0xD5, 0x14, 0x58, 0x2F, 0x9F, 0xCF, 0x0F, 0x6D, 0x2B, 0x69,
	0x7B, 0xD4, 0x4D, 0xA8, 0x77, 0xE3, 0x6F, 0x73, 0x04, 0xC4, 0x89, 0x42,
	0x3F, 0x9D, 0x85, 0xA8, 0x6A, 0x1D, 0x36, 0xC8, 0x11, 0x12, 0xE6, 0xAD,
	0x91, 0xD6, 0x92, 0xA1 };

static unsigned char SHA_512_256_DEFAULT_IV[] = {
	0x22, 0x31, 0x21, 0x94, 0xFC, 0x2B, 0xF7, 0x2C, 0x9F, 0x55, 0x5F, 0xA3,
	0xC8, 0x4C, 0x64, 0xC2, 0x23, 0x93, 0xB8, 0x6B, 0x6F, 0x53, 0xB1, 0x51,
	0x96, 0x38, 0x77, 0x19, 0x59, 0x40, 0xEA, 0xBD, 0x96, 0x28, 0x3E, 0xE2,
	0xA8, 0x8E, 0xFF, 0xE3, 0xBE, 0x5E, 0x1E, 0x25, 0x53, 0x86, 0x39, 0x92,
	0x2B, 0x01, 0x99, 0xFC, 0x2C, 0x85, 0xB8, 0xAA, 0x0E, 0xB7, 0x2D, 0xDC,
	0x81, 0xC5, 0x2C, 0xA2 };

static unsigned char SHA_3_DEFAULT_IV[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

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
	{S390_CRYPTO_SHA_512, 64, 64, 128, SHA_512_DEFAULT_IV},
	{S390_CRYPTO_SHA_3_224, 28, 200, 144, SHA_3_DEFAULT_IV},
	{S390_CRYPTO_SHA_3_256, 32, 200, 136, SHA_3_DEFAULT_IV},
	{S390_CRYPTO_SHA_3_384, 48, 200, 104, SHA_3_DEFAULT_IV},
	{S390_CRYPTO_SHA_3_512, 64, 200, 72, SHA_3_DEFAULT_IV},
	{S390_CRYPTO_SHAKE_128, 0, 200, 168, SHA_3_DEFAULT_IV},
	{S390_CRYPTO_SHAKE_256, 0, 200, 136, SHA_3_DEFAULT_IV},
	{ 0, 0, 0, 0, NULL }, /* Dummy line for GHASH */
	{S390_CRYPTO_SHA_512, 28, 64, 128, SHA_512_224_DEFAULT_IV},
	{S390_CRYPTO_SHA_512, 32, 64, 128, SHA_512_256_DEFAULT_IV},
};

int s390_sha1(unsigned char *iv, unsigned char *input_data,
	      unsigned int input_length, unsigned char *output_data,
	      unsigned int message_part, uint64_t *running_length);

int s390_sha224(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length);

int s390_sha256(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length);

int s390_sha384(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi);

int s390_sha512(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi);

int s390_sha512_224(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi);

int s390_sha512_256(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi);

int s390_sha3_224(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length);

int s390_sha3_256(unsigned char *iv, unsigned char *input_data,
		unsigned int input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length);

int s390_sha3_384(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi);

int s390_sha3_512(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi);

int s390_shake_128(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data, unsigned int output_length,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi);

int s390_shake_256(unsigned char *iv, unsigned char *input_data,
		uint64_t input_length, unsigned char *output_data, unsigned int output_length,
		unsigned int message_part, uint64_t *running_length_lo,
		uint64_t *running_length_hi);

int s390_shake_hw(unsigned char *iv, unsigned char *input_data,
		       uint64_t input_length, unsigned char *output_data, unsigned int output_length,
		       unsigned int message_part, uint64_t *running_length_lo,
		       uint64_t *running_length_hi, kimd_functions_t sha_function);

static inline int is_shake(unsigned int n)
{
	return (n >= SHAKE_128 && n <= SHAKE_256 ? 1 : 0);
}

static inline int is_sha3(unsigned int n)
{
	return (n >= SHA_3_224 && n <= SHA_3_512 ? 1 : 0);
}

static inline int s390_sha_hw(unsigned char *iv, unsigned char *input_data,
		       uint64_t input_length, unsigned char *output_data, unsigned int output_length,
		       unsigned int message_part, uint64_t *running_length_lo,
		       uint64_t *running_length_hi, kimd_functions_t sha_function)
{
	int rc = 0;

	uint64_t sum_lo = 0, sum_hi = 0;
	unsigned long remnant = 0;
	int complete_blocks_length = 0;

	unsigned char *default_iv  = sha_constants[sha_function].default_iv;
	unsigned int hash_length   = output_length;
	unsigned int vector_length = sha_constants[sha_function].vector_length;
	unsigned int hw_function_code
	    = sha_constants[sha_function].hw_function_code;

	/* A internal buffer for the SHA hash and stream bit length. For SHA3/SHAKE
	 * this can be at most 200 bytes for the parmblock plus 16 bytes for the
	 * stream length. */
	unsigned char shabuff[200+16];

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

	if (complete_blocks_length) {
		if (is_shake(sha_function))
			rc = s390_kimd_shake(hw_function_code, shabuff, output_data,
					   output_length, input_data,
					   complete_blocks_length);
		else
			rc = s390_kimd(hw_function_code, shabuff, input_data,
					   complete_blocks_length);

		if (rc > 0) {
			/* Check for overflow in sum_lo */
			sum_lo += rc;
			if (sum_lo < *running_length_lo
			    || sum_lo < (uint64_t)rc)
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

		if (is_shake(sha_function))
			rc = s390_klmd_shake(hw_function_code, shabuff, output_data,
					   output_length,
					   input_data + complete_blocks_length, remnant);
		else
			rc = s390_klmd(hw_function_code, shabuff,
					   input_data + complete_blocks_length, remnant);

		if (rc > 0)
			rc = 0;
	}

	if (rc == 0) {

		/**
		 * Here we copy the correct final hash to the caller provided buffer.
		 * But not for SHAKE. In this case s390_klmd_shake already copied the output
		 * (that may be longer than shabuff!) directly to output_data.
		 */
		if (!is_shake(sha_function))
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

#endif

