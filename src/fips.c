/*
 * This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * Author(s): Patrick Steuer <patrick.steuer@de.ibm.com>
 *
 * Copyright IBM Corp. 2015
 */

#ifdef ICA_FIPS

#include <errno.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "fips.h"
#include "ica_api.h"
#include "test_vec.h"

int fips;

static int aes_ecb_kat(void);
static int aes_cbc_kat(void);
static int aes_cbc_cs_kat(void);
static int aes_cfb_kat(void);
static int aes_ofb_kat(void);
static int aes_ctr_kat(void);
static int aes_ccm_kat(void);
static int aes_gcm_kat(void);
static int aes_xts_kat(void);
static int aes_cmac_kat(void);

static int des3_ecb_kat(void);
static int des3_cbc_kat(void);
static int des3_cbc_cs_kat(void);
static int des3_cfb_kat(void);
static int des3_ofb_kat(void);
static int des3_ctr_kat(void);
static int des3_cmac_kat(void);

static int rsa_kat(void);

#define SHA_KAT(_sha_, _ctx_)						\
static int sha##_sha_##_kat(void) {					\
	sha##_ctx_##_context_t ctx;					\
	size_t i;							\
	unsigned char out[SHA##_sha_##_HASH_LENGTH];			\
	for (i = 0; i < SHA##_sha_##_TV_LEN; i++) {			\
		if (ica_sha##_sha_(SHA_MSG_PART_ONLY,			\
		    SHA##_sha_##_TV[i].msg_len, SHA##_sha_##_TV[i].msg,	\
		    &ctx, out) || memcmp(SHA##_sha_##_TV[i].md, out,	\
		    SHA##_sha_##_HASH_LENGTH)) {			\
			syslog(LOG_ERR, "Libica SHA-%d test failed.",	\
			    _sha_);					\
			return 1;					\
		}							\
	}								\
	return 0;							\
}
SHA_KAT(1, );
SHA_KAT(224, 256);
SHA_KAT(256, 256);
SHA_KAT(384, 512);
SHA_KAT(512, 512);
#undef SHA_KAT

void
fips_init(void)
{
	FILE *fd;
	char fips_flag;

	if ((fd = fopen(FIPS_FLAG, "r")) == NULL)
		return;

	if (fread(&fips_flag, sizeof(fips_flag), 1, fd) != 1) {
		fclose(fd);
		return;
	}
	fclose(fd);

	if (fips_flag - '0') {
		/* Set libica into FIPS mode. */
		fips |= ICA_FIPS_MODE;

		/* Try to set OpenSSL into FIPS mode. If this is not possible,
		 * all software fallbacks (including RSA key generation) will
		 * be disabled. OpenSSL FIPS mode can be queried using the
		 * FIPS_mode() function. */
		FIPS_mode_set(1);
	}
}

void
fips_powerup_tests(void)
{
	/* Cryptographic algorithm test. */
	if (ica_drbg_health_test(ica_drbg_generate, 256, true, ICA_DRBG_SHA512)
	    || sha1_kat() || sha224_kat() || sha256_kat() || sha384_kat()
	    || sha512_kat() || des3_ecb_kat() || des3_cbc_kat()
	    || des3_cbc_cs_kat() || des3_cfb_kat() || des3_ofb_kat()
	    || des3_ctr_kat() || des3_cmac_kat() || aes_ecb_kat()
	    || aes_cbc_kat() || aes_cbc_cs_kat() || aes_cfb_kat()
	    || aes_ctr_kat() || aes_ofb_kat() || aes_ccm_kat() || aes_gcm_kat()
	    || aes_xts_kat() || aes_cmac_kat() || rsa_kat()) {
		fips |= ICA_FIPS_CRYPTOALG;
		return;
	}
}

static int
aes_ecb_kat(void) {
	const struct aes_ecb_tv *tv;
	size_t i;
	unsigned char *out;

	for (i = 0; i < AES_ECB_TV_LEN; i++) {
		tv = &AES_ECB_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		if (ica_aes_ecb(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, ICA_ENCRYPT) || memcmp(tv->ciphertext, out,
		    tv->len) || ica_aes_ecb(tv->ciphertext, out, tv->len,
		    tv->key, tv->keylen, ICA_DECRYPT) || memcmp(tv->plaintext,
		    out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica AES-ECB test failed.");
	return 1;
}

static int
aes_cbc_kat(void) {
	const struct aes_cbc_tv *tv;
	size_t i;
	unsigned char iv[AES_BLKSIZE], *out;

	for (i = 0; i < AES_CBC_TV_LEN; i++) {
		tv = &AES_CBC_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_cbc(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_ENCRYPT) || memcmp(tv->ciphertext, out,
		    tv->len))
			goto _err_;

		memcpy(iv, AES_CBC_TV[i].iv, AES_BLKSIZE);
		if (ica_aes_cbc(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_DECRYPT) || memcmp(tv->plaintext, out,
		    tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica AES-CBC test failed.");
	return 1;
}

static int
aes_cbc_cs_kat(void)
{
	const struct aes_cbc_cs_tv *tv;
	size_t i;
	unsigned char iv[AES_BLKSIZE], *out;

	for (i = 0; i < AES_CBC_CS_TV_LEN; i++) {
		tv = &AES_CBC_CS_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_cbc_cs(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_ENCRYPT, tv->variant)
		    || memcmp(tv->ciphertext, out, tv->len)
		    || memcmp(tv->iv_out, iv, AES_BLKSIZE))
			goto _err_;

		memcpy(iv, AES_CBC_CS_TV[i].iv, AES_BLKSIZE);
		if (ica_aes_cbc_cs(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_DECRYPT, tv->variant)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica AES-CBC-CS test failed.");
	return 1;
}

static int
aes_cfb_kat(void) {
	const struct aes_cfb_tv *tv;
	size_t i;
	unsigned char iv[AES_BLKSIZE], *out;

	for (i = 0; i < AES_CFB_TV_LEN; i++) {
		tv = &AES_CFB_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_cfb(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, iv, tv->lcfb, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, out, tv->len))
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_cfb(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, iv, tv->lcfb, ICA_DECRYPT)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica AES-CFB test failed.");
	return 1;
}

static int
aes_ofb_kat(void) {
	const struct aes_ofb_tv *tv;
	size_t i;
	unsigned char iv[AES_BLKSIZE], *out;

	for (i = 0; i < AES_OFB_TV_LEN; i++) {
		tv = &AES_OFB_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_ofb(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_ENCRYPT) || memcmp(tv->ciphertext, out,
		    tv->len))
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_ofb(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_DECRYPT) || memcmp(tv->plaintext, out,
		    tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica AES-OFB test failed.");
	return 1;
}

static int
aes_ctr_kat(void) {
	const struct aes_ctr_tv *tv;
	size_t i;
	unsigned char *out, ctr[AES_BLKSIZE];

	for (i = 0; i < AES_CTR_TV_LEN; i++) {
		tv = &AES_CTR_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(ctr, tv->ctr, AES_BLKSIZE);
		if (ica_aes_ctr(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, ctr, 32, ICA_ENCRYPT) || memcmp(tv->ciphertext,
		    out, tv->len))
			goto _err_;

		memcpy(ctr, tv->ctr, AES_BLKSIZE);
		if (ica_aes_ctr(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, ctr, 32, ICA_DECRYPT) || memcmp(tv->plaintext,
		    out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica AES-CTR test failed.");
	return 1;
}

static int
aes_ccm_kat(void) {
	const struct aes_ccm_tv *tv;
	size_t i;
	unsigned char *ciphertext, *payload;

	for (i = 0; i < AES_CCM_TV_LEN; i++) {
		tv = &AES_CCM_TV[i];

		ciphertext = malloc(tv->payloadlen + tv->taglen);
		payload = malloc(tv->payloadlen);

		if (payload == NULL || ciphertext == NULL)
			goto _err_;

		if (ica_aes_ccm(payload, tv->payloadlen, tv->ciphertext,
		    tv->taglen, tv->adata, tv->adatalen, tv->nonce,
		    tv->noncelen, tv->key, tv->keylen, ICA_DECRYPT)
		    != tv->rv)
			goto _err_;

		if ((tv->rv == 0) && (memcmp(tv->payload, payload,
		    tv->payloadlen) || ica_aes_ccm(tv->payload, tv->payloadlen,
		    ciphertext, tv->taglen, tv->adata, tv->adatalen, tv->nonce,
		    tv->noncelen, tv->key, tv->keylen, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, ciphertext, tv->payloadlen
		    + tv->taglen)))
			goto _err_;

		free(payload);
		free(ciphertext);
	}
	return 0;

_err_:
	free(ciphertext);
	free(payload);
	syslog(LOG_ERR, "Libica AES-CCM test failed.");
	return 1;
}

static int
aes_gcm_kat(void) {
	const struct aes_gcm_tv *tv;
	size_t i, lastlen;
	unsigned char *out, *tag, icb[AES_BLKSIZE], ucb[AES_BLKSIZE],
	    subkey[AES_BLKSIZE];

	for (i = 0; i < AES_GCM_TV_LEN; i++) {
		tv = &AES_GCM_TV[i];

		out = malloc(tv->len);
		tag = malloc(tv->taglen);

		if (tag == NULL || out == NULL)
			goto _err_;

		if ((ica_aes_gcm(out, tv->len, tv->ciphertext, tv->iv,
		    tv->ivlen, tv->aad, tv->aadlen, tv->tag, tv->taglen,
		    tv->key, tv->keylen, ICA_DECRYPT) != tv->rv)
		    || ((tv->rv == 0)
		    && memcmp(tv->plaintext, out, tv->len)))
			goto _err_;

		if ((tv->rv == 0) && (ica_aes_gcm(tv->plaintext, tv->len,
		    out, tv->iv, tv->ivlen, tv->aad, tv->aadlen, tag,
		    tv->taglen, tv->key, tv->keylen, ICA_ENCRYPT)
		    || memcmp(tv->tag, tag, tv->taglen)
		    || memcmp(tv->ciphertext, out, tv->len)))
			goto _err_;

		free(tag);
		free(out);
	}

	for (i = 0; i < AES_GCM_TV_LEN; i++) {
		tv = &AES_GCM_TV[i];

		/* Divide the test vector into two chunks. */
		if (tv->len  <= AES_BLKSIZE)
			lastlen = 0;
		else {
			lastlen = tv->len % AES_BLKSIZE;
			/* Last chunk can only be 16 bytes long, if test
			 * vector is at least 32 bytes long. */
			if (lastlen == 0 && tv->len >= 2 * AES_BLKSIZE)
				lastlen = AES_BLKSIZE;
		}

		out = malloc(tv->len);
		tag = malloc(AES_BLKSIZE);

		if (tag == NULL || out == NULL)
			goto _err_;

		memset(tag, 0, AES_BLKSIZE);
		if (ica_aes_gcm_initialize(tv->iv, tv->ivlen, tv->key,
		    tv->keylen, icb, ucb, subkey, ICA_DECRYPT)
		    || ica_aes_gcm_intermediate(out, tv->len - lastlen,
		    tv->ciphertext, ucb, tv->aad, tv->aadlen, tag,
		    tv->taglen, tv->key, tv->keylen, subkey, ICA_DECRYPT)
		    || ica_aes_gcm_intermediate(out + (tv->len - lastlen),
		    lastlen, tv->ciphertext + (tv->len - lastlen), ucb,
		    NULL, 0, tag, tv->taglen, tv->key, tv->keylen,
		    subkey, ICA_DECRYPT) || (ica_aes_gcm_last(icb, tv->aadlen,
		    tv->len, tag, tv->tag, tv->taglen, tv->key, tv->keylen,
		    subkey, ICA_DECRYPT) != tv->rv) || ((tv->rv == 0)
		    && memcmp(tv->plaintext, out, tv->len)))
			goto _err_;

		memset(tag, 0, AES_BLKSIZE);
		memset(out, 0, tv->len);
		memset(icb, 0, sizeof(icb));
		memset(icb, 0, sizeof(ucb));
		memset(subkey, 0, sizeof(subkey));
		if ((tv->rv == 0) && (ica_aes_gcm_initialize(tv->iv, tv->ivlen,
		    tv->key, tv->keylen, icb, ucb, subkey, ICA_ENCRYPT)
		    || ica_aes_gcm_intermediate(tv->plaintext,
		    tv->len - lastlen, out, ucb, tv->aad, tv->aadlen, tag,
		    tv->taglen, tv->key, tv->keylen, subkey, ICA_ENCRYPT)
		    || ica_aes_gcm_intermediate(tv->plaintext
		    + (tv->len - lastlen), lastlen, out + (tv->len - lastlen),
		    ucb, NULL, 0, tag, tv->taglen, tv->key, tv->keylen, subkey,
		    ICA_ENCRYPT) || ica_aes_gcm_last(icb, tv->aadlen, tv->len,
		    tag, NULL, tv->taglen, tv->key, tv->keylen, subkey,
		    ICA_ENCRYPT) || memcmp(tv->ciphertext, out, tv->len)
		    || memcmp(tv->tag, tag, tv->taglen)))
			goto _err_;

		free(tag);
		free(out);
	}
	return 0;

_err_:
	free(tag);
	free(out);
	syslog(LOG_ERR, "Libica AES-GCM test failed.");
	return 1;
}

static int
aes_xts_kat(void) {
	const struct aes_xts_tv *tv;
	size_t i;
	unsigned char *out, tweak[16];

	for (i = 0; i < AES_XTS_TV_LEN; i++) {
		tv = &AES_XTS_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(tweak, tv->tweak, sizeof(tweak));
		if (ica_aes_xts(tv->plaintext, out, tv->len, tv->key1,
		    tv->key2, tv->keylen, tweak, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, out, tv->len))
			goto _err_;

		memcpy(tweak, tv->tweak, sizeof(tweak));
		if (ica_aes_xts(tv->ciphertext, out, tv->len, tv->key1,
		    tv->key2, tv->keylen, tweak, ICA_DECRYPT)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica AES-XTS test failed.");
	return 1;
}

static int
aes_cmac_kat(void)
{
	const struct aes_cmac_tv *tv;
	size_t i, lastlen;
	unsigned char *mac, iv[AES_BLKSIZE];

	for (i = 0; i < AES_CMAC_TV_LEN; i++) {
		tv = &AES_CMAC_TV[i];

		mac = malloc(tv->maclen);

		if (mac == NULL)
			goto _err_;

		if ((ica_aes_cmac(tv->msg, tv->msglen, tv->mac, tv->maclen,
		    tv->key, tv->keylen, ICA_DECRYPT) != tv->rv)
		    || ((tv->rv == 0) && (ica_aes_cmac(tv->msg, tv->msglen,
		    mac, tv->maclen, tv->key, tv->keylen, ICA_ENCRYPT)
		    || memcmp(tv->mac, mac, tv->maclen))))
			goto _err_;

		free(mac);
	}

	for (i = 0; i < AES_CMAC_TV_LEN; i++) {
		tv = &AES_CMAC_TV[i];

		if (tv->msglen <= AES_BLKSIZE)
			continue;

		lastlen = tv->msglen % AES_BLKSIZE ? tv->msglen % AES_BLKSIZE
		    : AES_BLKSIZE;
		memset(iv, 0, AES_BLKSIZE);

		if (ica_aes_cmac_intermediate(tv->msg, tv->msglen - lastlen,
		    tv->key, tv->keylen, iv) || (ica_aes_cmac_last(tv->msg
		    + (tv->msglen - lastlen), lastlen, tv->mac, tv->maclen,
		    tv->key, tv->keylen, iv, ICA_DECRYPT) != tv->rv))
			return 1;

		if (tv->rv != 0)
			continue;

		mac = malloc(tv->maclen);

		if (mac == NULL)
			goto _err_;

		memset(iv, 0, AES_BLKSIZE);
		if (ica_aes_cmac_intermediate(tv->msg, tv->msglen - lastlen,
		    tv->key, tv->keylen, iv) || ica_aes_cmac_last(tv->msg
		    + (tv->msglen - lastlen), lastlen, mac, tv->maclen,
		    tv->key, tv->keylen, iv, ICA_ENCRYPT) || memcmp(tv->mac,
		    mac, tv->maclen))
			goto _err_;

		free(mac);
	}
	return 0;

_err_:
	free(mac);
	syslog(LOG_ERR, "Libica AES-CMAC test failed.");
	return 1;
}

static int
des3_ecb_kat(void) {
	const struct des3_ecb_tv *tv;
	size_t i;
	unsigned char *out;

	for (i = 0; i < DES3_ECB_TV_LEN; i++) {
		tv = &DES3_ECB_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		if (ica_3des_ecb(tv->plaintext, out, tv->len,
		    (unsigned char *)tv->key, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, out, tv->len)
		    || ica_3des_ecb(tv->ciphertext, out, tv->len,
		    (unsigned char *)tv->key, ICA_DECRYPT)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica 3DES-ECB test failed.");
	return 1;
}

static int
des3_cbc_kat(void) {
	const struct des3_cbc_tv *tv;
	size_t i;
	unsigned char iv[DES3_BLKSIZE], *out;

	for (i = 0; i < DES3_CBC_TV_LEN; i++) {
		tv = &DES3_CBC_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, DES3_BLKSIZE);
		if (ica_3des_cbc(tv->plaintext, out, tv->len,
		    (unsigned char *)tv->key, iv, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, out, tv->len))
			goto _err_;

		memcpy(iv, tv->iv, DES3_BLKSIZE);
		if (ica_3des_cbc(tv->ciphertext, out, tv->len,
		    (unsigned char *)tv->key, iv, ICA_DECRYPT)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica 3DES-CBC test failed.");
	return 1;
}

static int
des3_cbc_cs_kat(void){
	const struct des3_cbc_cs_tv *tv;
	size_t i;
	unsigned char iv[DES3_BLKSIZE], *out;

	for (i = 0; i < DES3_CBC_CS_TV_LEN; i++) {
		tv = &DES3_CBC_CS_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, DES3_BLKSIZE);
		if (ica_3des_cbc_cs(tv->plaintext, out, tv->len,
		    (unsigned char *)tv->key, iv, ICA_ENCRYPT, tv->variant)
		    || memcmp(tv->ciphertext, out, tv->len))
			goto _err_;

		memcpy(iv, tv->iv, DES3_BLKSIZE);
		if (ica_3des_cbc_cs(tv->ciphertext, out, tv->len,
		    (unsigned char *)tv->key, iv,
		    ICA_DECRYPT, tv->variant)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica 3DES-CBC-CS test failed.");
	return 1;
}

static int
des3_cfb_kat(void) {
	const struct des3_cfb_tv *tv;
	size_t i;
	unsigned char iv[DES3_BLKSIZE], *out;

	for (i = 0; i < DES3_CFB_TV_LEN; i++) {
		tv = &DES3_CFB_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, DES3_BLKSIZE);
		if (ica_3des_cfb(tv->plaintext, out, tv->len,
		    (unsigned char *)tv->key, iv, tv->lcfb, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, out, tv->len))
			goto _err_;

		memcpy(iv, tv->iv, DES3_BLKSIZE);
		if (ica_3des_cfb(tv->ciphertext, out, tv->len,
		    (unsigned char *)tv->key, iv, tv->lcfb, ICA_DECRYPT)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica 3DES-CFB test failed.");
	return 1;
}

static int
des3_ofb_kat(void) {
	const struct des3_ofb_tv *tv;
	size_t i;
	unsigned char iv[DES3_BLKSIZE], *out;

	for (i = 0; i < DES3_OFB_TV_LEN; i++) {
		tv = &DES3_OFB_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, DES3_BLKSIZE);
		if (ica_3des_ofb(tv->plaintext, out, tv->len,
		    (unsigned char *)tv->key, iv, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, out, tv->len))
			goto _err_;

		memcpy(iv, tv->iv, DES3_BLKSIZE);
		if (ica_3des_ofb(tv->ciphertext, out, tv->len,
		    (unsigned char *)tv->key, iv, ICA_DECRYPT)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica 3DES-OFB test failed.");
	return 1;
}

static int
des3_ctr_kat(void) {
	const struct des3_ctr_tv *tv;
	size_t i;
	unsigned char *out, ctr[DES3_BLKSIZE];

	for (i = 0; i < DES3_CTR_TV_LEN; i++) {
		tv = &DES3_CTR_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(ctr, tv->ctr, DES3_BLKSIZE);
		if (ica_3des_ctr(tv->plaintext, out, tv->len,
		    (unsigned char *)tv->key, ctr, 32, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, out, tv->len))
			goto _err_;

		memcpy(ctr, tv->ctr, DES3_BLKSIZE);
		if (ica_3des_ctr(tv->ciphertext, out, tv->len,
		    (unsigned char *)tv->key, ctr, 32, ICA_DECRYPT)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
	syslog(LOG_ERR, "Libica 3DES-CTR test failed.");
	return 1;
}

static int
des3_cmac_kat(void)
{
	const struct des3_cmac_tv *tv;
	size_t i, lastlen;
	unsigned char *mac, iv[DES3_BLKSIZE];

	for (i = 0; i < DES3_CMAC_TV_LEN; i++) {
		tv = &DES3_CMAC_TV[i];

		mac = malloc(tv->maclen);

		if (mac == NULL)
			goto _err_;

		if ((ica_3des_cmac(tv->msg, tv->msglen, tv->mac, tv->maclen,
		    (unsigned char *)tv->key, ICA_DECRYPT) != tv->rv)
		    || ((tv->rv == 0) && (ica_3des_cmac(tv->msg, tv->msglen,
		    mac, tv->maclen, (unsigned char *)tv->key, ICA_ENCRYPT)
		    || memcmp(tv->mac, mac, tv->maclen))))
			goto _err_;

		free(mac);
	}
	for (i = 0; i < DES3_CMAC_TV_LEN; i++) {
		tv = &DES3_CMAC_TV[i];

		if (tv->msglen <= DES3_BLKSIZE)
			continue;

		lastlen = tv->msglen % DES3_BLKSIZE ? tv->msglen % DES3_BLKSIZE
		    : DES3_BLKSIZE;
		memset(iv, 0, DES3_BLKSIZE);

		if (ica_3des_cmac_intermediate(tv->msg, tv->msglen - lastlen,
		    (unsigned char *)tv->key, iv)
		    || (ica_3des_cmac_last(tv->msg + (tv->msglen - lastlen),
		    lastlen, tv->mac, tv->maclen, (unsigned char *)tv->key, iv,
		    ICA_DECRYPT) != tv->rv))
			return 1;

		if (tv->rv != 0)
			continue;

		mac = malloc(tv->maclen);

		if (mac == NULL)
			goto _err_;

		memset(iv, 0, DES3_BLKSIZE);
		if (ica_3des_cmac_intermediate(tv->msg, tv->msglen - lastlen,
		    (unsigned char *)tv->key, iv)
		    || ica_3des_cmac_last(tv->msg + (tv->msglen - lastlen),
		    lastlen, mac, tv->maclen, (unsigned char *)tv->key, iv,
		    ICA_ENCRYPT) || memcmp(tv->mac, mac, tv->maclen))
			goto _err_;

		free(mac);
	}
	return 0;

_err_:
	free(mac);
	syslog(LOG_ERR, "Libica 3DES-CMAC test failed.");
	return 1;
}

static int
rsa_kat(void)
{
	ica_rsa_key_mod_expo_t pubkey;
	ica_rsa_key_crt_t privkey;
	ica_adapter_handle_t ah;
	const struct rsa_tv *tv;
	size_t i, keylen, crtparamlen;
	unsigned char *out;

	if (ica_open_adapter(&ah))
		return 1;

	for (i = 0; i < RSA_TV_LEN; i++) {
		tv = &RSA_TV[i];

		keylen = (tv->mod + 7) / 8;
		crtparamlen = (keylen + 1) / 2;

		pubkey.key_length = keylen;
		privkey.key_length = keylen;

		out = malloc(keylen);
		pubkey.exponent = malloc(keylen);
		pubkey.modulus = malloc(keylen);
		privkey.q = malloc(crtparamlen);
		privkey.dq = malloc(crtparamlen);
		/* Some values have 8 bytes of zero padding. */
		privkey.p = malloc(crtparamlen + 8);
		privkey.dp = malloc(crtparamlen + 8);
		privkey.qInverse = malloc(crtparamlen + 8);

		if (privkey.qInverse == NULL || privkey.dq == NULL
		    || privkey.dp == NULL || privkey.q == NULL
		    || privkey.p == NULL || pubkey.modulus == NULL
		    || pubkey.exponent == NULL || out == NULL)
			goto _err_;

		memcpy(pubkey.exponent, tv->e, keylen);
		memcpy(pubkey.modulus, tv->n, keylen);
		memcpy(privkey.q, tv->q, crtparamlen);
		memcpy(privkey.dq, tv->dq, crtparamlen);
		memcpy(privkey.p, tv->p, crtparamlen + 8);
		memcpy(privkey.dp, tv->dp, crtparamlen + 8);
		memcpy(privkey.qInverse, tv->qinv, crtparamlen + 8);

		if (ica_rsa_mod_expo(ah, tv->plaintext, &pubkey, out)
		    || memcmp(tv->ciphertext, out, keylen)
		    || ica_rsa_crt(ah, tv->ciphertext, &privkey, out)
		    || memcmp(tv->plaintext, out, keylen))
			goto _err_;

		free(out);
		free(pubkey.exponent);
		free(pubkey.modulus);
		free(privkey.p);
		free(privkey.q);
		free(privkey.dp);
		free(privkey.dq);
		free(privkey.qInverse);
	}
	ica_close_adapter(ah);
	return 0;

_err_:
	ica_close_adapter(ah);
	free(out);
	free(pubkey.exponent);
	free(pubkey.modulus);
	free(privkey.p);
	free(privkey.q);
	free(privkey.dp);
	free(privkey.dq);
	free(privkey.qInverse);
	syslog(LOG_ERR, "Libica RSA test failed.");
	return 1;
}

#endif /* FIPS_H */
