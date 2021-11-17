/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Christian Maaser <cmaaser@de.ibm.com>
 * 	    Benedikt Klotz   <benedikt.klotz@de.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2013
 */

#ifndef __ICA_STATS_H__
#define __ICA_STATS_H__

#include <stdint.h>

#include <openssl/obj_mac.h>

#include "ica_api.h"

typedef struct crypt_opts{
	uint64_t hw;
	uint64_t sw;
} crypt_opts_t;

typedef struct statis_entry {
	crypt_opts_t  enc;
	crypt_opts_t  dec;
} stats_entry_t;


typedef enum stats_fields {
	/* crypt counter */
	ICA_STATS_SHA1 = 0,
	ICA_STATS_SHA224,
	ICA_STATS_SHA256,
	ICA_STATS_SHA384,
	ICA_STATS_SHA512,
	ICA_STATS_SHA512_224,
	ICA_STATS_SHA512_256,
	ICA_STATS_SHA3_224,
	ICA_STATS_SHA3_256,
	ICA_STATS_SHA3_384,
	ICA_STATS_SHA3_512,
	ICA_STATS_SHAKE_128,
	ICA_STATS_SHAKE_256,
	ICA_STATS_GHASH,
	ICA_STATS_PRNG,
	ICA_STATS_DRBGSHA512,
	ICA_STATS_ECDH,
	ICA_STATS_ECDH_160,
	ICA_STATS_ECDH_192,
	ICA_STATS_ECDH_224,
	ICA_STATS_ECDH_256,
	ICA_STATS_ECDH_320,
	ICA_STATS_ECDH_384,
	ICA_STATS_ECDH_512,
	ICA_STATS_ECDH_521,
	ICA_STATS_ECDSA_SIGN,
	ICA_STATS_ECDSA_SIGN_160,
	ICA_STATS_ECDSA_SIGN_192,
	ICA_STATS_ECDSA_SIGN_224,
	ICA_STATS_ECDSA_SIGN_256,
	ICA_STATS_ECDSA_SIGN_320,
	ICA_STATS_ECDSA_SIGN_384,
	ICA_STATS_ECDSA_SIGN_512,
	ICA_STATS_ECDSA_SIGN_521,
	ICA_STATS_ECDSA_VERIFY,
	ICA_STATS_ECDSA_VERIFY_160,
	ICA_STATS_ECDSA_VERIFY_192,
	ICA_STATS_ECDSA_VERIFY_224,
	ICA_STATS_ECDSA_VERIFY_256,
	ICA_STATS_ECDSA_VERIFY_320,
	ICA_STATS_ECDSA_VERIFY_384,
	ICA_STATS_ECDSA_VERIFY_512,
	ICA_STATS_ECDSA_VERIFY_521,
	ICA_STATS_ECKGEN,
	ICA_STATS_ECKGEN_160,
	ICA_STATS_ECKGEN_192,
	ICA_STATS_ECKGEN_224,
	ICA_STATS_ECKGEN_256,
	ICA_STATS_ECKGEN_320,
	ICA_STATS_ECKGEN_384,
	ICA_STATS_ECKGEN_512,
	ICA_STATS_ECKGEN_521,
	ICA_STATS_ED25519_KEYGEN,
	ICA_STATS_ED25519_SIGN,
	ICA_STATS_ED25519_VERIFY,
	ICA_STATS_ED448_KEYGEN,
	ICA_STATS_ED448_SIGN,
	ICA_STATS_ED448_VERIFY,
	ICA_STATS_X25519_KEYGEN,
	ICA_STATS_X25519_DERIVE,
	ICA_STATS_X448_KEYGEN,
	ICA_STATS_X448_DERIVE,
	ICA_STATS_RSA_ME,
	ICA_STATS_RSA_ME_512,
	ICA_STATS_RSA_ME_1024,
	ICA_STATS_RSA_ME_2048,
	ICA_STATS_RSA_ME_4096,
	ICA_STATS_RSA_CRT,
	ICA_STATS_RSA_CRT_512,
	ICA_STATS_RSA_CRT_1024,
	ICA_STATS_RSA_CRT_2048,
	ICA_STATS_RSA_CRT_4096, /* add new crypt counters above RSA_CRT_4096
			      (see print_stats function) */

	/* enc and dec counter  */
	ICA_STATS_DES_ECB,
	ICA_STATS_DES_CBC,
	ICA_STATS_DES_OFB,
	ICA_STATS_DES_CFB,
	ICA_STATS_DES_CTR,
	ICA_STATS_DES_CMAC,
	ICA_STATS_3DES_ECB,
	ICA_STATS_3DES_CBC,
	ICA_STATS_3DES_OFB,
	ICA_STATS_3DES_CFB,
	ICA_STATS_3DES_CTR,
	ICA_STATS_3DES_CMAC,
	ICA_STATS_AES_ECB,
	ICA_STATS_AES_ECB_128,
	ICA_STATS_AES_ECB_192,
	ICA_STATS_AES_ECB_256,
	ICA_STATS_AES_CBC,
	ICA_STATS_AES_CBC_128,
	ICA_STATS_AES_CBC_192,
	ICA_STATS_AES_CBC_256,
	ICA_STATS_AES_OFB,
	ICA_STATS_AES_OFB_128,
	ICA_STATS_AES_OFB_192,
	ICA_STATS_AES_OFB_256,
	ICA_STATS_AES_CFB,
	ICA_STATS_AES_CFB_128,
	ICA_STATS_AES_CFB_192,
	ICA_STATS_AES_CFB_256,
	ICA_STATS_AES_CTR,
	ICA_STATS_AES_CTR_128,
	ICA_STATS_AES_CTR_192,
	ICA_STATS_AES_CTR_256,
	ICA_STATS_AES_CMAC,
	ICA_STATS_AES_CMAC_128,
	ICA_STATS_AES_CMAC_192,
	ICA_STATS_AES_CMAC_256,
	ICA_STATS_AES_XTS,
	ICA_STATS_AES_XTS_128,
	ICA_STATS_AES_XTS_256,
	ICA_STATS_AES_GCM,
	ICA_STATS_AES_GCM_128,
	ICA_STATS_AES_GCM_192,
	ICA_STATS_AES_GCM_256,

	/* number of counters */
	ICA_NUM_STATS
} stats_fields_t;

#define STAT_STRINGS	\
	"SHA-1",      	\
	"SHA-224",    	\
	"SHA-256",    	\
	"SHA-384",    	\
	"SHA-512",    	\
	"SHA-512/224",	\
	"SHA-512/256",	\
	"SHA3-224",    	\
	"SHA3-256",    	\
	"SHA3-384",    	\
	"SHA3-512",    	\
	"SHAKE-128",   	\
	"SHAKE-256",   	\
	"GHASH",      	\
	"P_RNG",      	\
	"DRBG-SHA-512",	\
	"ECDH",		\
	"- 160",	\
	"- 192",	\
	"- 224",	\
	"- 256",	\
	"- 320",	\
	"- 384",	\
	"- 512",	\
	"- 521",	\
	"ECDSA Sign",	\
	"- 160",	\
	"- 192",	\
	"- 224",	\
	"- 256",	\
	"- 320",	\
	"- 384",	\
	"- 512",	\
	"- 521",	\
	"ECDSA Verify",	\
	"- 160",	\
	"- 192",	\
	"- 224",	\
	"- 256",	\
	"- 320",	\
	"- 384",	\
	"- 512",	\
	"- 521",	\
	"EC Keygen",	\
	"- 160",	\
	"- 192",	\
	"- 224",	\
	"- 256",	\
	"- 320",	\
	"- 384",	\
	"- 512",	\
	"- 521",	\
	"Ed25519 Keygen",\
	"Ed25519 Sign", \
	"Ed25519 Verify",\
	"Ed448 Keygen",\
	"Ed448 Sign", \
	"Ed448 Verify",\
	"X25519 Keygen",\
	"X25519 Derive",\
	"X448 Keygen",  \
	"X448 Derive",  \
	"RSA-ME",	\
	"- 512",	\
	"- 1024",	\
	"- 2048",	\
	"- 4096",	\
	"RSA-CRT",	\
	"- 512",	\
	"- 1024",	\
	"- 2048",	\
	"- 4096",	\
	"DES ECB",    	\
	"DES CBC",    	\
	"DES OFB",    	\
	"DES CFB",    	\
	"DES CTR",    	\
	"DES CMAC",   	\
	"3DES ECB",   	\
	"3DES CBC",   	\
	"3DES OFB",   	\
	"3DES CFB",   	\
	"3DES CTR",   	\
	"3DES CMAC",	\
	"AES ECB",	\
	"- 128",	\
	"- 192",	\
	"- 256",	\
	"AES CBC",	\
	"- 128",	\
	"- 192",	\
	"- 256",	\
	"AES OFB",	\
	"- 128",	\
	"- 192",	\
	"- 256",	\
	"AES CFB",	\
	"- 128",	\
	"- 192",	\
	"- 256",	\
	"AES CTR",	\
	"- 128",	\
	"- 192",	\
	"- 256",	\
	"AES CMAC",	\
	"- 128",	\
	"- 192",	\
	"- 256",	\
	"AES XTS",	\
	"- 128",	\
	"- 256",	\
	"AES GCM",	\
	"- 128",	\
	"- 192",	\
	"- 256"

#define STATS_SHM_SIZE (sizeof(stats_entry_t) * ICA_NUM_STATS)
#define ENCRYPT 1
#define DECRYPT 0

#define ALGO_SW 0
#define ALGO_HW 1

#define SHM_CLOSE 0
#define SHM_DESTROY 1


int stats_mmap(int user);
void stats_munmap(int unlink);
uint64_t stats_query(stats_fields_t field, int hardware, int direction);
void get_stats_data(stats_entry_t *entries);
void stats_increment(stats_fields_t field, int hardware, int direction);
int get_stats_sum(stats_entry_t *sum);
char *get_next_usr();
void stats_reset();
int delete_all();

static inline int aes_directed_fc_stats_ofs(unsigned int fc)
{
	switch (fc) {
	case AES_128_DECRYPT:
	case AES_128_ENCRYPT:
		return 0;
	case AES_192_DECRYPT:
	case AES_192_ENCRYPT:
		return 1;
	case AES_256_DECRYPT:
	case AES_256_ENCRYPT:
		return 2;
	case AES_128_XTS_ENCRYPT:
	case AES_128_XTS_DECRYPT:
		return 0;
	case AES_256_XTS_ENCRYPT:
	case AES_256_XTS_DECRYPT:
		return 1;
	}
	return 0;
}

static inline int rsa_keysize_stats_ofs(unsigned int key_length)
{
	if (key_length >= 4096 / 8)
		return 3;
	if (key_length >= 2048 / 8)
		return 2;
	if (key_length >= 1024 / 8)
		return 1;
	return 0;
}

static inline int ecc_keysize_stats_ofs(int nid)
{
	switch (nid) {
	case NID_brainpoolP160r1:
		return 0;
	case NID_X9_62_prime192v1:
	case NID_brainpoolP192r1:
		return 1;
	case NID_secp224r1:
	case NID_brainpoolP224r1:
		return 2;
	case NID_X9_62_prime256v1:
	case NID_brainpoolP256r1:
		return 3;
	case NID_brainpoolP320r1:
		return 4;
	case NID_secp384r1:
	case NID_brainpoolP384r1:
		return 5;
	case NID_brainpoolP512r1:
		return 6;
	case NID_secp521r1:
		return 7;
	}
	return 0;
}

#endif
