/*
 * This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * Copyright IBM Corp. 2015
 */
#ifndef TEST_VEC_H
#define TEST_VEC_H

#include <stdbool.h>
#include <stddef.h>

#include "s390_ecc.h"

#define AES128_KEYLEN	(128 / 8)
#define AES192_KEYLEN	(192 / 8)
#define AES256_KEYLEN	(256 / 8)
#define DES3_KEYLEN	(192 / 8)

#define AES_BLKSIZE	(128 / 8)
#define DES3_BLKSIZE	( 64 / 8)

struct aes_ecb_tv {
	size_t keylen;
	size_t len;
	unsigned char *key;
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct aes_cbc_tv {
	size_t keylen;
	size_t len;
	unsigned char *key;
	unsigned char iv[AES_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct aes_cbc_cs_tv {
	size_t keylen;
	size_t len;
	unsigned char *key;
	unsigned char iv[AES_BLKSIZE];
	unsigned char iv_out[AES_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
	int variant;
};

struct aes_cfb_tv {
	size_t keylen;
	size_t len;
	int lcfb;
	unsigned char *key;
	unsigned char iv[AES_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct aes_ofb_tv {
	size_t keylen;
	size_t len;
	unsigned char *key;
	unsigned char iv[AES_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct aes_ctr_tv {
	size_t keylen;
	size_t len;
	unsigned char *key;
	unsigned char ctr[AES_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct aes_ccm_tv {
	size_t keylen;
	size_t noncelen;
	size_t adatalen;
	size_t payloadlen;
	size_t taglen;
	unsigned char *key;
	unsigned char *nonce;
	unsigned char *adata;
	unsigned char *payload;
	unsigned char *ciphertext;
	unsigned int rv;
};

struct aes_gcm_tv {
	size_t keylen;
	size_t ivlen;
	size_t len;
	size_t aadlen;
	size_t taglen;
	unsigned char *key;
	unsigned char *iv;
	unsigned char *plaintext;
	unsigned char *aad;
	unsigned char *tag;
	unsigned char *ciphertext;
	unsigned int rv;
};

struct aes_xts_tv {
	size_t len;
	size_t keylen;
	unsigned char *key1;
	unsigned char *key2;
	unsigned char tweak[16];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct aes_cmac_tv {
	size_t keylen;
	size_t msglen;
	size_t maclen;
	unsigned char *key;
	unsigned char *msg;
	unsigned char *mac;
	unsigned int rv;
};

struct des3_ecb_tv {
	size_t len;
	unsigned char key[DES3_KEYLEN];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct des3_cbc_tv {
	size_t len;
	unsigned char key[DES3_KEYLEN];
	unsigned char iv[DES3_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct des3_cbc_cs_tv {
	size_t len;
	unsigned char key[DES3_KEYLEN];
	unsigned char iv[DES3_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
	int variant;
};

struct des3_cfb_tv {
	size_t len;
	int lcfb;
	unsigned char key[DES3_KEYLEN];
	unsigned char iv[DES3_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct des3_ofb_tv {
	size_t len;
	unsigned char key[DES3_KEYLEN];
	unsigned char iv[DES3_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct des3_ctr_tv {
	size_t len;
	unsigned char key[DES3_KEYLEN];
	unsigned char ctr[DES3_BLKSIZE];
	unsigned char *plaintext;
	unsigned char *ciphertext;
};

struct des3_cmac_tv {
	size_t msglen;
	size_t maclen;
	unsigned char key[DES3_KEYLEN];
	unsigned char *msg;
	unsigned char *mac;
	unsigned int rv;
};

struct rsa_tv {
	unsigned char *n;
	unsigned char *p;
	unsigned char *dp;
	unsigned char *q;
	unsigned char *dq;
	unsigned char *qinv;
	unsigned char *e;
	unsigned char *d;
	unsigned char *plaintext;
	unsigned char *ciphertext;
	int mod;
};

struct sha_tv {
	size_t msg_len;
	unsigned char *msg;
	unsigned char *md;
};

struct drbg_sha512_tv {
	bool no_reseed;
	bool pr;
	size_t entropy_len;
	size_t nonce_len;
	size_t pers_len;
	size_t add_len;
	size_t prnd_len;

	struct{
		unsigned char *entropy;
		unsigned char *nonce;
		unsigned char *pers;

		unsigned char *v;
		unsigned char *c;
		unsigned int reseed_ctr;
	} inst;

	struct {
		unsigned char *entropy;
		unsigned char *add;

		unsigned char *v;
		unsigned char *c;
		unsigned int reseed_ctr;
	} res, gen1, gen2;

	unsigned char *prnd;
};

struct ecdsa_tv {
	/* sign inputs */
	const ICA_EC_KEY *key;
	int hash;
	unsigned char *msg; /* should be qualified const,
			        but sha api lacks const ... */
	size_t msglen;
	const unsigned char *k;
	/* sign expected outputs */
	const unsigned char *r;
	const unsigned char *s;
	size_t siglen;
};

struct scalar_mul_tv {
	/* scalar mul inputs */
	int curve_nid;
	size_t len;
	const unsigned char *scalar;

	/* scalar mul outputs */
	const unsigned char *x;
	const unsigned char *y;
};

#ifdef ICA_FIPS
extern const struct aes_ecb_tv AES_ECB_TV[];
extern const size_t AES_ECB_TV_LEN;

extern const struct aes_cbc_tv AES_CBC_TV[];
extern const size_t AES_CBC_TV_LEN;

extern const struct aes_cbc_cs_tv AES_CBC_CS_TV[];
extern const size_t AES_CBC_CS_TV_LEN;

extern const struct aes_cfb_tv AES_CFB_TV[];
extern const size_t AES_CFB_TV_LEN;

extern const struct aes_ofb_tv AES_OFB_TV[];
extern const size_t AES_OFB_TV_LEN;

extern const struct aes_ctr_tv AES_CTR_TV[];
extern const size_t AES_CTR_TV_LEN;

extern const struct aes_ccm_tv AES_CCM_TV[];
extern const size_t AES_CCM_TV_LEN;

extern const struct aes_gcm_tv AES_GCM_TV[];
extern const size_t AES_GCM_TV_LEN;

extern const struct aes_xts_tv AES_XTS_TV[];
extern const size_t AES_XTS_TV_LEN;

extern const struct aes_cmac_tv AES_CMAC_TV[];
extern const size_t AES_CMAC_TV_LEN;

extern const struct des3_ecb_tv DES3_ECB_TV[];
extern const size_t DES3_ECB_TV_LEN;

extern const struct des3_cbc_tv DES3_CBC_TV[];
extern const size_t DES3_CBC_TV_LEN;

extern const struct des3_cbc_cs_tv DES3_CBC_CS_TV[];
extern const size_t DES3_CBC_CS_TV_LEN;

extern const struct des3_cfb_tv DES3_CFB_TV[];
extern const size_t DES3_CFB_TV_LEN;

extern const struct des3_ofb_tv DES3_OFB_TV[];
extern const size_t DES3_OFB_TV_LEN;

extern const struct des3_ctr_tv DES3_CTR_TV[];
extern const size_t DES3_CTR_TV_LEN;

extern const struct des3_cmac_tv DES3_CMAC_TV[];
extern const size_t DES3_CMAC_TV_LEN;

extern const struct rsa_tv RSA_TV[];
extern const size_t RSA_TV_LEN;

extern const struct sha_tv SHA1_TV[];
extern const size_t SHA1_TV_LEN;

extern const struct sha_tv SHA224_TV[];
extern const size_t SHA224_TV_LEN;

extern const struct sha_tv SHA256_TV[];
extern const size_t SHA256_TV_LEN;

extern const struct sha_tv SHA384_TV[];
extern const size_t SHA384_TV_LEN;

extern const struct sha_tv SHA512_TV[];
extern const size_t SHA512_TV_LEN;
#endif /* ICA_FIPS */

#ifdef ICA_INTERNAL_TEST_EC
extern const struct ecdsa_tv ECDSA_TV[];
extern const size_t ECDSA_TV_LEN;

extern const struct scalar_mul_tv SCALAR_MUL_TV[];
extern const size_t SCALAR_MUL_TV_LEN;
#endif /* ICA_INTERNAL_TEST_EC */

extern const struct drbg_sha512_tv DRBG_SHA512_TV[];
extern const size_t DRBG_SHA512_TV_LEN;

#endif /* TEST_VEC_H */
