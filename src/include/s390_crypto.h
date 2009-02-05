/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 *  Support for s390 cryptographic instructions.
 *
 *  Author(s): Thomas Spatzier
 *             Jan Glauber <jan.glauber@de.ibm.com>
 *             Ralph Wuerthner <rwuerthn@de.ibm.com>
 *	       Felix Beck <felix.beck@de.ibm.com>
 *	       Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2007, 2009
 */

#ifndef S390_CRYPTO_H
#define S390_CRYPTO_H

#define S390_CRYPTO_TEST_MASK(mask, function) \
	(((unsigned char *)(mask))[((function) & 0x7F) >> 3] & \
        (0x80 >> ((function) & 0x07)))

enum s390_crypto_instruction {
	S390_CRYPTO_DIRECTION_MASK = 0x80,
	S390_CRYPTO_FUNCTION_MASK = 0x7f
};

enum s390_crypto_function {
	/*
	 * The S390_QUERY function is always available for all 4 KM, KMC, KIMD and
	 * KLMD instructions to query the available functions.
	 */
	S390_CRYPTO_QUERY = 0x00,
	/*
	 * The S390_SHA_* functions are available for KIMD and KLMD instructions.
	 */
	S390_CRYPTO_SHA_1 = 0x01,
	S390_CRYPTO_SHA_256 = 0x02,
	S390_CRYPTO_SHA_512 = 0x03,
	/*
	 * The following functions are available for KM and KMC instructions.
	 */
	S390_CRYPTO_DEA_ENCRYPT = 0x01,
	S390_CRYPTO_DEA_DECRYPT = 0x01 | 0x80,
	S390_CRYPTO_TDEA_128_ENCRYPT = 0x02,
	S390_CRYPTO_TDEA_128_DECRYPT = 0x02 | 0x80,
	S390_CRYPTO_TDEA_192_ENCRYPT = 0x03,
	S390_CRYPTO_TDEA_192_DECRYPT = 0x03 | 0x80,
	S390_CRYPTO_AES_128_ENCRYPT = 0x12,
	S390_CRYPTO_AES_128_DECRYPT = 0x12 | 0x80,
	S390_CRYPTO_AES_192_ENCRYPT = 0x13,
	S390_CRYPTO_AES_192_DECRYPT = 0x13 | 0x80,
	S390_CRYPTO_AES_256_ENCRYPT = 0x14,
	S390_CRYPTO_AES_256_DECRYPT = 0x14 | 0x80,
	/*
	 * The S390_PRNG is only available for the KMC instruction.
	 */
	S390_CRYPTO_PRNG = 0x43
};

unsigned int sha1_switch, sha256_switch, sha512_switch, des_switch,
	     tdes_switch, aes128_switch, aes192_switch, aes192_switch,
	     aes256_switch, prng_switch;

typedef struct {
	unsigned int dummy_fc;
	unsigned int hw_fc;
	unsigned int *enabled;
} s390_supported_function_t;

/* Append new dummy fc codes to the end of enumeration. They are used as index
 * to get the right fc code for the hardware. */
typedef enum {
	SHA_1,
	SHA_224,
	SHA_256,
	SHA_384,
	SHA_512
} kimd_functions_t;
typedef enum {
	DEA_ENCRYPT,
	DEA_DECRYPT,
	TDEA_192_ENCRYPT,
	TDEA_192_DECRYPT,
	AES_128_ENCRYPT,
	AES_128_DECRYPT,
	AES_192_ENCRYPT,
	AES_192_DECRYPT,
	AES_256_ENCRYPT,
	AES_256_DECRYPT,
	PRNG
} kmc_functions_t;

s390_supported_function_t s390_kmc_functions[PRNG + 1]; 
s390_supported_function_t s390_kimd_functions[SHA_512 + 1]; 

int s390_kimd(long func, void *param, const unsigned char *src, long src_len);
int s390_klmd(long func, void *param, const unsigned char *src, long src_len);
int s390_km(long func, void *param, unsigned char *dest,
	    const unsigned char *src, long src_len);
int s390_kmc(long func, void *param, unsigned char *dest,
	     const unsigned char *src, long src_len);
int s390_stckf_hw(void *buf);
void s390_crypto_switches_init(void);

#endif

