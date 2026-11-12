/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * Some parts of the content of this file have been moved from former
 * icalinux.c to this file.
 *
 * Copyright IBM Corp. 2009, 2011
 */

#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "fips.h"
#include "s390_rsa.h"
#include "s390_prng.h"
#include "s390_crypto.h"

#if OPENSSL_VERSION_PREREQ(3, 0)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
extern OSSL_LIB_CTX *openssl_libctx;
#endif

#if defined(NO_SW_FALLBACKS)
#define UNUSED(var)			((void)(var))
#endif

#ifndef NO_SW_FALLBACKS
static unsigned int mod_expo_sw(int arg_length, unsigned char *arg, int exp_length,
				unsigned char *exp, int mod_length, unsigned char *mod,
				int *res_length, unsigned char *res, BN_CTX *ctx);
static unsigned int mod_mul_sw(int fc_1_length, unsigned char *fc1, int fc_2_length,
			      unsigned char *fc2, int mod_length, unsigned char *mod,
			      int *res_length, unsigned char *res, BN_CTX *ctx);
static unsigned int mod_sw(int arg_length, unsigned char *arg, int mod_length,
			   unsigned char *mod, int *res_length, unsigned char *res, BN_CTX *ctx);
static unsigned int add_sw(int aug_length, unsigned char *aug, int add_length,
			   unsigned char *add, int *res_length, unsigned char *res, BN_CTX *ctx);
static unsigned int mod_sub_sw(int length, unsigned char *minu,
			       unsigned char *sub, unsigned char *mod,
			       unsigned char *res);
static unsigned int mul_sw(int fc_1_length, unsigned char *fc1, int fc_2_length,
			   unsigned char *fc2, int *res_length, unsigned char *res, BN_CTX *ctx);
#endif /* NO_SW_FALLBACKS */

#if !OPENSSL_VERSION_PREREQ(3, 0)
RSA* rsa_key_generate(unsigned int modulus_bit_length,
		      unsigned long *public_exponent)
{
	unsigned int min_pubexp = 3;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return NULL;
	if (fips & ICA_FIPS_MODE)
		min_pubexp = 65537;
#endif /* ICA_FIPS */

	if (*public_exponent == 0)
	{
		do {
			if (s390_prng((unsigned char*)public_exponent,
			    sizeof(unsigned long)) != 0)
				return NULL;
		} while (*public_exponent < min_pubexp || !(*public_exponent % 2));
	}

	RSA *rsa = RSA_new();
	BIGNUM *exp = BN_new();
	if (!exp || !rsa) {
		RSA_free(rsa);
		BN_free(exp);
		return NULL;
	}
	BN_GENCB *cb = BN_GENCB_new();
	if(!cb) {
		RSA_free(rsa);
		BN_free(exp);
		return NULL;
	}

	BN_set_word(exp, *public_exponent);
	BN_GENCB_set_old(cb, NULL, NULL);

	if (RSA_generate_key_ex(rsa, modulus_bit_length, exp, cb) == 0) {
		RSA_free(rsa);
		rsa = NULL;
	}

	BN_free(exp);
	BN_GENCB_free(cb);
	return rsa;
}
#else /* openssl 3.0 */
EVP_PKEY* rsa_key_generate(unsigned int modulus_bit_length,
		      unsigned long *public_exponent)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	BIGNUM *e = NULL;
	int try;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return NULL;
#endif /* ICA_FIPS */

	if (*public_exponent == 0)
	{
		do {
			if (s390_prng((unsigned char*)public_exponent,
			    sizeof(unsigned long)) != 0)
				return NULL;
		} while (*public_exponent <= 2 || !(*public_exponent % 2));
	}

	e = BN_bin2bn((const unsigned char *)public_exponent,
		      sizeof(unsigned long), NULL);
	if (e == NULL) {
		goto done;
	}

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (pctx == NULL) {
		goto done;
	}

	if (EVP_PKEY_keygen_init(pctx) != 1 ||
		EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, modulus_bit_length) != 1 ||
		EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pctx, e) != 1) {
		goto done;
	}

	/*
	 * In OpenSSL 3.0 the RSA key gen algorithm has been changed and can now
	 * fail to generate a key. Retry up to 10 times in such a case.
	 */
	for (try = 1; try <= 10; try++) {
		if (EVP_PKEY_keygen(pctx, &pkey) == 1)
			break;

		if (pkey)
			EVP_PKEY_free(pkey);
		pkey = NULL;
	}

done:
	if (pctx != NULL)
		EVP_PKEY_CTX_free(pctx);
	if (e != NULL)
		BN_free(e);

	return pkey;
}
#endif

/**
 * @brief Create a RSA modulus/expo key pair
 *
 * This function generates and returns a public/private key pair in
 * modulus/exponent format. A completion code is returned to indicate
 * success/failure.
 * @param device_handle
 * Previously opened device handle.
 * @param modulus_bit_length
 * Bit length of modulus to be generated.
 * @param public_key
 * Buffer for the public key. On output contains the public key.
 * @param private_key
 * Buffer of the private key. On output contains the private key.
 *
 * Returns 0 if successful.
 */
unsigned int rsa_key_generate_mod_expo(ica_adapter_handle_t deviceHandle,
				       unsigned int modulus_bit_length,
				       ica_rsa_key_mod_expo_t *public_key,
				       ica_rsa_key_mod_expo_t *private_key)
{
	(void)deviceHandle;	/* suppress unused param warning */
	int rc = 0;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
	if ((fips & ICA_FIPS_MODE) && (modulus_bit_length < 3072))
		return EPERM;
#endif /* ICA_FIPS */

	BEGIN_OPENSSL_LIBCTX(openssl_libctx, rc);

#if !OPENSSL_VERSION_PREREQ(3, 0)
	const BIGNUM *n, *d;

	RSA *rsa = rsa_key_generate(modulus_bit_length,
				    (unsigned long*)(public_key->exponent +
				    public_key->key_length -
				    sizeof(unsigned long)));
	if (!rsa) {
		rc = EFAULT;
		goto err;
	}

	RSA_get0_key(rsa, &n, NULL,  &d);
#else
	BIGNUM *n = NULL, *d = NULL;

	EVP_PKEY *pkey = rsa_key_generate(modulus_bit_length,
				    (unsigned long*)(public_key->exponent +
				    public_key->key_length -
				    sizeof(unsigned long)));
	if (!pkey) {
		rc = EFAULT;
		goto err;
	}

	n = BN_secure_new();
	d = BN_secure_new();
	if (!n || !d) {
		rc = ENOMEM;
		goto err;
	}

	if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
		!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d)) {
		rc = EFAULT;
		goto err;
	}
#endif

	/* Set key buffers zero to make sure there is no
	 * unneeded junk in between.
	 */
	memset(public_key->modulus, 0, public_key->key_length);
	memset(private_key->modulus, 0, private_key->key_length);
	memset(private_key->exponent, 0, private_key->key_length);

	unsigned int bn_length = BN_num_bytes(n);
	unsigned int offset = 0;

	if (bn_length < public_key->key_length)
		offset = public_key->key_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(n, public_key->modulus + offset);

	memcpy(private_key->modulus, public_key->modulus,
	       public_key->key_length);

	bn_length = BN_num_bytes(d);
	if (bn_length < private_key->key_length)
		offset = private_key->key_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(d, private_key->exponent + offset);

err:

#if !OPENSSL_VERSION_PREREQ(3, 0)
	RSA_free(rsa);
#else
	BN_clear_free(n);
	BN_clear_free(d);
	EVP_PKEY_free(pkey);
#endif

	END_OPENSSL_LIBCTX(rc);
	return rc;
}

/**
 * This function generates and returns a public/private key pair in CRT format.
 *
 * @param device_handle
 * Previously opened device handle.
 * @param modulus_bit_length
 * Bit length of modulus to be generated.
 * @param public_key
 * Buffer for the public key. On output contains the public key.
 * @param private_key
 * Buffer of the private key. On output contains the private key.
 *
 * Returns 0 if successful.
 */
unsigned int rsa_key_generate_crt(ica_adapter_handle_t deviceHandle,
				  unsigned int modulus_bit_length,
				  ica_rsa_key_mod_expo_t *public_key,
				  ica_rsa_key_crt_t *private_key)
{
	(void)deviceHandle;	/* suppress unused param warning */
	int rc = 0;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
	if ((fips & ICA_FIPS_MODE) && (modulus_bit_length < 3072))
		return EPERM;
#endif /* ICA_FIPS */

	BEGIN_OPENSSL_LIBCTX(openssl_libctx, rc);

#if !OPENSSL_VERSION_PREREQ(3, 0)
	const BIGNUM *n, *p, *q, *dmp1, *dmq1, *iqmp;

	RSA *rsa = rsa_key_generate(modulus_bit_length,
				    (unsigned long*)(public_key->exponent +
				    public_key->key_length -
				    sizeof(unsigned long)));
	if (!rsa) {
		rc = EFAULT;
		goto err;
	}

	RSA_get0_key(rsa, &n, NULL,  NULL);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
#else
	BIGNUM *n = NULL, *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

	EVP_PKEY *pkey = rsa_key_generate(modulus_bit_length,
				    (unsigned long*)(public_key->exponent +
				    public_key->key_length -
				    sizeof(unsigned long)));
	if (!pkey) {
		rc = EFAULT;
		goto err;
	}

	n = BN_secure_new();
	p = BN_secure_new();
	q = BN_secure_new();
	dmp1 = BN_secure_new();
	dmq1 = BN_secure_new();
	iqmp = BN_secure_new();
	if (!n || !p || !q || !dmp1 || !dmq1 || !iqmp) {
		rc = ENOMEM;
		goto err;
	}

	if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
		!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) ||
		!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) ||
		!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1) ||
		!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1) ||
		!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp)) {
		rc = EFAULT;
		goto err;
	}
#endif

	/* Public exponent has already been set, no need to do this here.
	 * For public key, only modulus needs to be set.
	 */
	memset(public_key->modulus, 0, public_key->key_length);

	/* Make sure that key parts are copied to the end of the buffer */
	unsigned int offset = 0;

	unsigned int bn_length = BN_num_bytes(n);
	if (bn_length < public_key->key_length)
		offset = public_key->key_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(n, public_key->modulus + offset);

	memset(private_key->p, 0, (private_key->key_length+1) / 2 + 8);
	memset(private_key->q, 0, (private_key->key_length+1) / 2);
	memset(private_key->dp, 0, (private_key->key_length+1) / 2 + 8);
	memset(private_key->dq, 0, (private_key->key_length+1) / 2);
	memset(private_key->qInverse, 0, (private_key->key_length+1) / 2 + 8);

	unsigned int key_part_length = (private_key->key_length+1) / 2;

	/* We add the "+8" because it is a requirement by the crypto adapters
	 * to have an 8 byte zero pad in the beginning of the fields for:
	 * p, dp, and qInverse.
	 */

	/* Copy p into buffer */
	bn_length = BN_num_bytes(p);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(p, private_key->p + 8 + offset);

	/* Copy q into buffer */
	bn_length = BN_num_bytes(q);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(q, private_key->q + offset);

	/* Copy dp into buffer */
	bn_length = BN_num_bytes(dmp1);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(dmp1, private_key->dp + 8 + offset);

	/* Copy dq into buffer */
	bn_length = BN_num_bytes(dmq1);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(dmq1, private_key->dq + offset);

	/* Copy qInverse into buffer */
	bn_length = BN_num_bytes(iqmp);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;

	BN_bn2bin(iqmp, private_key->qInverse + 8 + offset);

	rc = ica_rsa_crt_key_check(private_key);
	if (rc == 1)
		rc = 0;

err:
#if !OPENSSL_VERSION_PREREQ(3, 0)
	RSA_free(rsa);
#else
	BN_clear_free(n);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(dmp1);
	BN_clear_free(dmq1);
	BN_clear_free(iqmp);
	EVP_PKEY_free(pkey);
#endif

	END_OPENSSL_LIBCTX(rc);
	return rc;
}

#ifndef NO_SW_FALLBACKS
/*
 * Number of extra bytes needed to hold a CRT exponent that is blinded with
 * a BLIND_EXP_RAND_BYTES-byte multiple of (prime - 1).
 */
#define BLIND_EXP_RAND_BYTES	8
#define BLIND_EXP_EXTRA		(BLIND_EXP_RAND_BYTES + 1)

/**
 * Exponent blinding for the CRT exponentiations. Computes
 * res = d + k * (prime - 1) with a fresh random k. Since prime is a prime
 * number, x^res = x^d (mod prime) for every x, but the exponent that is
 * processed differs on each call, so timing and power measurements cannot
 * be accumulated over several operations.
 *
 * @param d Exponent (dp or dq), d_length bytes
 * @param prime The prime p or q, prime_length bytes
 * @param res Output buffer of res_length bytes, big endian, zero padded.
 *	      res_length must be at least max(d_length, prime_length) +
 *	      BLIND_EXP_EXTRA.
 *
 * Returns 0 if successful, EIO otherwise.
 */
static unsigned int blind_exponent(const unsigned char *d, int d_length,
				   const unsigned char *prime, int prime_length,
				   unsigned char *res, int res_length, BN_CTX *ctx)
{
	unsigned char k[BLIND_EXP_RAND_BYTES];
	BIGNUM *b_d, *b_p, *b_k;
	unsigned int rc = EIO;

	BN_CTX_start(ctx);

	b_d = BN_CTX_get(ctx);
	b_p = BN_CTX_get(ctx);
	if ((b_k = BN_CTX_get(ctx)) == NULL)
		goto cleanup;

	if (RAND_bytes(k, sizeof(k)) != 1)
		goto cleanup;

	if (BN_bin2bn(d, d_length, b_d) == NULL ||
	    BN_bin2bn(prime, prime_length, b_p) == NULL ||
	    BN_bin2bn(k, sizeof(k), b_k) == NULL)
		goto cleanup;

	if (!BN_sub_word(b_p, 1) || !BN_mul(b_p, b_p, b_k, ctx) ||
	    !BN_add(b_d, b_d, b_p))
		goto cleanup;

	if (BN_bn2binpad(b_d, res, res_length) < 0)
		goto cleanup;

	rc = 0;

cleanup:
	OPENSSL_cleanse(k, sizeof(k));
	BN_CTX_end(ctx);

	return rc;
}

/**
 * @deprecated Perform a modular muliplication operation in software.
 */
unsigned int rsa_mod_mult_sw(ica_rsa_modmult_t *pMul)
{
	int rc = 0;
	BN_CTX *ctx = NULL;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	if ((ctx = BN_CTX_new()) == NULL) {
		return EFAULT;
	}

	rc = mod_mul_sw(pMul->inputdatalength, pMul->inputdata,
			pMul->inputdatalength, pMul->b_key,
			pMul->inputdatalength, pMul->n_modulus,
			(int *)&(pMul->outputdatalength),
			pMul->outputdata, ctx);
	BN_CTX_free(ctx);
	if (rc)
		rc = EIO;
	return rc;
}

/**
 * Perform a multiprecision modular multiplication using a multiplicand,
 * multiplier and modulus.
 */
static unsigned int mod_mul_sw(int fc_1_length, unsigned char *fc1, int fc_2_length,
			      unsigned char *fc2, int mod_length, unsigned char *mod,
			      int *res_length, unsigned char *res, BN_CTX *ctx)
{
	int rc = 0;
	BIGNUM *b_fc1 = NULL;
	BIGNUM *b_fc2 = NULL;
	BIGNUM *b_mod = NULL;
	BIGNUM *b_res = NULL;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	BN_CTX_start(ctx);

	b_fc1 = BN_CTX_get(ctx);
	b_fc2 = BN_CTX_get(ctx);
	b_mod = BN_CTX_get(ctx);
	if ((b_res = BN_CTX_get(ctx)) == NULL) {
		rc = ENOMEM;
		goto cleanup;
	}

	b_fc1 = BN_bin2bn((const unsigned char *)fc1, fc_1_length, b_fc1);
	b_fc2 = BN_bin2bn((const unsigned char *)fc2, fc_2_length, b_fc2);
	b_mod = BN_bin2bn((const unsigned char *)mod, mod_length, b_mod);

	if (b_fc1 == NULL || b_fc2 == NULL || b_mod == NULL)
		goto err;

	/* The operands may be secret (CRT: qInv and the modulus p). */
	BN_set_flags(b_fc1, BN_FLG_CONSTTIME);
	BN_set_flags(b_fc2, BN_FLG_CONSTTIME);
	BN_set_flags(b_mod, BN_FLG_CONSTTIME);

	if (!(BN_mod_mul(b_res, b_fc1, b_fc2, b_mod, ctx))) {
		goto err;
	}

	if (BN_bn2binpad(b_res, res, *res_length) < 0) {
		rc = EIO;
		goto cleanup;
	}

	goto cleanup;

      err:
	rc = EIO;

      cleanup:
	BN_CTX_end(ctx);

	 return rc;
}
#endif /* NO_SW_FALLBACKS */

/**
 * Perform a mod expo operation using a key in modulus/exponent form, in
 * software.
 * @param pMex
 * Address of an ica_rsa_modexpo_t, containing:
 *	input_length - The byte length of the input data
 *	input_data - Pointer to input data
 *	b_key - Pointer to the exponent
 *	n_modulus - Pointer to the modulus
 *	output_length - On input it contains the byte length of the output
 *	      	     	buffer. On output it contains the actual byte
 *	      	     	length of the output_data
 *	output_data - Pointer to the output buffer
 *
 * Returns 0 if successful.
 */
unsigned int rsa_mod_expo_sw(ica_rsa_modexpo_t *pMex)
{
#ifdef NO_SW_FALLBACKS
	UNUSED(pMex);
	return EPERM;
#else
	int rc = 0;
	BN_CTX *ctx = NULL;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	/* check if modulus value > data value */
	if ((memcmp(pMex->n_modulus, pMex->inputdata,
		    pMex->inputdatalength)) <= 0)
		return EINVAL;

	if ((ctx = BN_CTX_new()) == NULL) {
		return EFAULT;
	}

	rc = mod_expo_sw(pMex->inputdatalength, pMex->inputdata,
		       pMex->inputdatalength, pMex->b_key,
		       pMex->inputdatalength, pMex->n_modulus,
		       (int *)&(pMex->outputdatalength), pMex->outputdata, ctx);

	BN_CTX_free(ctx);
	if (rc == 1)
		rc = EIO;
	return rc;
#endif /* NO_SW_FALLBACKS */
}

#ifndef NO_SW_FALLBACKS
/**
 * Perform a mod expo operation using a key in modulus/exponent form, in
 * software.
 * @param arg_length
 * The byte length of the input data
 * @param arg
 * Pointer to input data
 * @param exp_length
 * The byte length of the exponent
 * @param exp
 * Pointer to the exponent
 * @param mod_length
 * The byte length of the modulus
 * @param mod
 * Pointer to the modulus
 * @param res_length
 * On input it points to the byte length of the output buffer. On output it
 * points to the actual byte length of the output_data
 * @param res
 * Pointer to the output buffer
 * @param ctx
 * Pointer to a BN_CTX
 *
 * Returns 0 if successful BN error code if unsuccessful.
 */
static unsigned int mod_expo_sw(int arg_length, unsigned char *arg, int exp_length,
				unsigned char *exp, int mod_length, unsigned char *mod,
				int *res_length, unsigned char *res, BN_CTX *ctx)
{
	int rc = 0;
	BIGNUM *b_arg = NULL;
	BIGNUM *b_exp = NULL;
	BIGNUM *b_mod = NULL;
	BIGNUM *b_res = NULL;
	BN_CTX *mod_expo_ctx = NULL;
	int mod_expo_rc = 1;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	BN_CTX_start(ctx);

	b_arg = BN_CTX_get(ctx);
	b_exp = BN_CTX_get(ctx);
	b_mod = BN_CTX_get(ctx);
	if ((b_res = BN_CTX_get(ctx)) == NULL) {
		rc = ENOMEM;
		goto cleanup;
	}

	b_arg = BN_bin2bn((const unsigned char *)arg, arg_length, b_arg);
	b_exp = BN_bin2bn((const unsigned char *)exp, exp_length, b_exp);
	b_mod = BN_bin2bn((const unsigned char *)mod, mod_length, b_mod);

	if (b_arg == NULL || b_exp == NULL || b_mod == NULL)
		goto err;

	/* The exponent (d, dp, dq) and, for CRT, the modulus are secret. */
	BN_set_flags(b_exp, BN_FLG_CONSTTIME);
	BN_set_flags(b_mod, BN_FLG_CONSTTIME);

	// Evidently BN_mod_exp gets a *lot* of temp BN's, so it
	// needs a context all its own.
	if ((mod_expo_ctx = BN_CTX_new()) == NULL) {
		goto err;
	}

	mod_expo_rc = BN_mod_exp(b_res, b_arg, b_exp, b_mod, mod_expo_ctx);
	BN_CTX_free(mod_expo_ctx);

	if (!(mod_expo_rc)) {
		goto err;
	}

	/* The result may be secret: do not branch on or copy by its length. */
	if (BN_bn2binpad(b_res, res, *res_length) < 0) {
		rc = 1;
		goto cleanup;
	}

	goto cleanup;

      err:
	rc = EIO;

      cleanup:
	BN_CTX_end(ctx);

	return rc;
}
#endif /* NO_SW_FALLBACKS */

/**
 * Perform a RSA mod expo on input data using a key in CRT format, in software.
 *
 * @param pCrt
 * Address of an ica_rsa_modexpo_crt_t, containing:
 *	input_length: The byte length of the input data.
 *	input_data: Pointer to input data  b
 *	output_length: On input it contains the byte length of the output
 *		      buffer.  On output it contains the actual byte length
 *		      of the output_data
 *	output_data: Pointer to the output buffer
 *	bp_key: Pointer to dp
 *	bq_key: Pointer to dq
 *	np_prime: Pointer to p
 *	nq_prime: Pointer to q
 *	u_mult_inv: Pointer to u
 *
 * Returns 0 if successful
 */
unsigned int rsa_crt_sw(ica_rsa_modexpo_crt_t * pCrt)
{
#ifdef NO_SW_FALLBACKS
	UNUSED(pCrt);
	return EPERM;
#else
	int rc = 0;
	unsigned int long_length = 0;
	unsigned int short_length = 0;
	BN_CTX *ctx = NULL;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	short_length = (pCrt->inputdatalength+1) / 2;
	long_length = short_length + 8;
/*
	Use variable buffer length. Earlier version contained fixed 136byte
	size for ir buffers. Thus the software fallback should be able to
	handle keys of bigger size, too.
*/
	unsigned char ir1[long_length];
	int ir_1_length = sizeof(ir1);
	unsigned char ir2[long_length];
	int ir_2_length = sizeof(ir2);
	unsigned char temp[long_length];
	int temp_length = sizeof(temp);
	/* Blinded exponents: dp or dq plus a 64-bit multiple of p-1 or q-1. */
	unsigned char bexp1[long_length + BLIND_EXP_EXTRA];
	unsigned char bexp2[long_length + BLIND_EXP_EXTRA];

	if ((ctx = BN_CTX_new()) == NULL) {
		return EFAULT;
	}

	memset(ir1, 0, sizeof(ir1));
	if ((rc = mod_sw(pCrt->inputdatalength, pCrt->inputdata,
			 long_length, pCrt->np_prime, &ir_1_length, ir1, ctx)) != 0)
		goto err;

	if ((rc = blind_exponent(pCrt->bp_key, long_length,
				 pCrt->np_prime, long_length,
				 bexp1, sizeof(bexp1), ctx)) != 0)
		goto err;

	memset(temp, 0, sizeof(temp));
	if ((rc = mod_expo_sw(ir_1_length, ir1,
			      sizeof(bexp1), bexp1,
			      long_length, pCrt->np_prime,
			      &temp_length, temp, ctx)) != 0)
		goto err;

	memset(ir1, 0, sizeof(ir1));
	memcpy(ir1, temp, temp_length);
	ir_1_length = temp_length;

	memset(ir2, 0, sizeof(ir2));
	if ((rc = mod_sw(pCrt->inputdatalength, pCrt->inputdata,
			 short_length, pCrt->nq_prime, &ir_2_length,
			 ir2, ctx)) != 0)
		goto err;

	if ((rc = blind_exponent(pCrt->bq_key, short_length,
				 pCrt->nq_prime, short_length,
				 bexp2, sizeof(bexp2), ctx)) != 0)
		goto err;

	temp_length = sizeof(temp);
	memset(temp, 0, sizeof(temp));
	if ((rc = mod_expo_sw(ir_2_length, ir2,
			      sizeof(bexp2), bexp2,
			      short_length, pCrt->nq_prime,
			      &temp_length, temp, ctx)) != 0)
		goto err;

	memset(ir2, 0, sizeof(ir2));
	memcpy(ir2, temp, temp_length);
	ir_2_length = temp_length;

	/* ir1, ir2 and np_prime all have long_length bytes here. */
	if ((rc = mod_sub_sw(long_length, ir1, ir2, pCrt->np_prime, ir1)) != 0)
		goto err;

	ir_1_length = long_length;

	temp_length = sizeof(temp);
	memset(temp, 0, sizeof(temp));
	if ((rc = mod_mul_sw(ir_1_length, ir1,
			     long_length, pCrt->u_mult_inv,
			     long_length, pCrt->np_prime,
			     &temp_length, temp, ctx)) != 0)
		goto err;

	if ((rc = mul_sw(temp_length, temp,
			short_length, pCrt->nq_prime,
			(int *)&(pCrt->outputdatalength), pCrt->outputdata, ctx)) != 0)
		goto err;

	if ((rc = add_sw(pCrt->outputdatalength, pCrt->outputdata,
			ir_2_length, ir2,
			(int *)&(pCrt->outputdatalength), pCrt->outputdata, ctx)) != 0)
		goto err;

	goto cleanup;

      err:
	rc = EIO;

      cleanup:
	OPENSSL_cleanse(ir1, sizeof(ir1));
	OPENSSL_cleanse(ir2, sizeof(ir2));
	OPENSSL_cleanse(temp, sizeof(temp));
	OPENSSL_cleanse(bexp1, sizeof(bexp1));
	OPENSSL_cleanse(bexp2, sizeof(bexp2));
	BN_CTX_free(ctx);

	return rc;
#endif /* NO_SW_FALLBACKS */
}

#ifndef NO_SW_FALLBACKS
/**
 * Perform a 'residue modulo' operation using an argument and a modulus.
 * @param arg_length The byte length of the input data
 * @param arg Pointer to input data
 * @param mod_length The byte length of the modulus
 * @param mod Pointer to the modulus
 * @param res_length
 * On input it points to the byte length of the output buffer. On output it
 * points to the actual byte length of the output_data.
 * @param res Pointer to the output buffer
 * @param ctx Pointer to a BN_CTX
 *
 * Returns 0 if successful, BN error code if unsuccessful
 */
static unsigned int mod_sw(int arg_length, unsigned char *arg, int mod_length,
			   unsigned char *mod, int *res_length, unsigned char *res, BN_CTX *ctx)
{
	int rc = 0;
	BIGNUM *b_arg = NULL;
	BIGNUM *b_mod = NULL;
	BIGNUM *b_res = NULL;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	BN_CTX_start(ctx);

	b_arg = BN_CTX_get(ctx);
	b_mod = BN_CTX_get(ctx);
	if ((b_res = BN_CTX_get(ctx)) == NULL) {
		rc = -ENOMEM;
		goto cleanup;
	}

	b_arg = BN_bin2bn((const unsigned char *)arg, arg_length, b_arg);
	b_mod = BN_bin2bn((const unsigned char *)mod, mod_length, b_mod);

	if (b_arg == NULL || b_mod == NULL)
		goto err;

	/*
	 * The modulus is a secret prime. Ask OpenSSL to use its constant-time
	 * division code, as OpenSSL does in its own CRT implementation.
	 */
	BN_set_flags(b_arg, BN_FLG_CONSTTIME);
	BN_set_flags(b_mod, BN_FLG_CONSTTIME);

	if (!(BN_mod(b_res, b_arg, b_mod, ctx))) {
		goto err;
	}

	if (BN_bn2binpad(b_res, res, *res_length) < 0) {
		rc = 1;
		goto cleanup;
	}

	goto cleanup;

      err:
	rc = EIO;

      cleanup:
	BN_CTX_end(ctx);

	return rc;
}

/*
 * Constant-time helpers for big-endian numbers of equal, public length. The
 * operands are secret in the CRT code, so neither the control flow nor the
 * memory accesses may depend on their values.
 */

/*
 * res = a - b (mod 2^(8*len)). Returns the borrow: 1 if a < b, otherwise 0.
 * res may be the same buffer as a or b.
 */
static unsigned int ct_sub(unsigned char *res, const unsigned char *a,
			   const unsigned char *b, size_t len)
{
	unsigned int borrow = 0, d;
	size_t i;

	for (i = len; i-- > 0;) {
		d = (unsigned int)a[i] - b[i] - borrow;
		res[i] = (unsigned char)d;
		borrow = (d >> 8) & 1;
	}

	return borrow;
}

/*
 * res += b (mod 2^(8*len)) if mask is 0xff, leaves res unchanged if mask is
 * 0x00. res may be the same buffer as b.
 */
static void ct_cond_add(unsigned char *res, const unsigned char *b, size_t len,
			unsigned char mask)
{
	unsigned int carry = 0, s;
	size_t i;

	for (i = len; i-- > 0;) {
		s = (unsigned int)res[i] + (b[i] & mask) + carry;
		res[i] = (unsigned char)s;
		carry = s >> 8;
	}
}

/**
 * Perform (minu - sub) mod mod on big-endian numbers of the same byte length.
 * minu and sub must be smaller than mod. The operands are secret in the CRT
 * (m mod p and m mod q), so this is done without BIGNUM arithmetic: the
 * modulus is added back, masked by the borrow of the subtraction.
 *
 * @param length The byte length of minu, sub, mod and res
 * @param minu Pointer to the minuend
 * @param sub Pointer to the subtrahend
 * @param mod Pointer to the modulus
 * @param res Pointer to the output buffer (may be the same as minu or sub)
 *
 * Returns 0 if successful.
 */
static unsigned int mod_sub_sw(int length, unsigned char *minu,
			       unsigned char *sub, unsigned char *mod,
			       unsigned char *res)
{
	unsigned int borrow;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	borrow = ct_sub(res, minu, sub, length);
	ct_cond_add(res, mod, length, (unsigned char)(0u - borrow));

	return 0;
}

/**
 * Perform a multiprecision addition using an augend and addend
 * @param aug_length The byte length of the augend
 * @param aug Pointer to augend
 * @param add_length The byte length of the addend
 * @param add Pointer to the addend
 * @param res_length On input it points to the byte length of the output buffer.
 *		On output it points to the actual byte length of the
 *		output_data
 * @param res Pointer to the output buffer
 * @param ctx Pointer to a BN_CTX
 *
 * Returns 0 if successful, BN error code if unsuccessful
 * Process:
 * 1) Call BN_CTX_get for the augend, addend and result BN's
 * 2) Convert the augend and addend BN's using BN_bin2bn
 * 3) Call BN_add
 * 4) Convert the result from a BN to a string using BN_bn2bin
 * 5) Call BN_free for the augend, addend and result BN's
*/
static unsigned int add_sw(int aug_length, unsigned char *aug, int add_length,
			   unsigned char *add, int *res_length, unsigned char *res, BN_CTX *ctx)
{
	int rc = 0;
	BIGNUM *b_aug = NULL;
	BIGNUM *b_add = NULL;
	BIGNUM *b_res = NULL;

	BN_CTX_start(ctx);

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	b_aug = BN_CTX_get(ctx);
	b_add = BN_CTX_get(ctx);
	if ((b_res = BN_CTX_get(ctx)) == NULL) {
		rc = -ENOMEM;
		goto cleanup;
	}

	b_aug = BN_bin2bn((const unsigned char *)aug, aug_length, b_aug);
	b_add = BN_bin2bn((const unsigned char *)add, add_length, b_add);

	if (!(BN_add(b_res, b_aug, b_add))) {
		goto err;
	}

	if (BN_bn2binpad(b_res, res, *res_length) < 0) {
		rc = 1;
		goto cleanup;
	}

	goto cleanup;

      err:
	rc = EIO;

      cleanup:
	BN_CTX_end(ctx);

	return rc;
}

/**
 * Perform a multiprecision multiply using a multiplicand and multiplier.
 * @param fc_1_length The byte length of the multiplicand
 * @param fc1 Pointer to multiplicand
 * @param fc_2_length The byte length of the multiplier
 * @param fc2 Pointer to the multiplier
 * @param res_length
 * On input it points to the byte length of the output buffer. On output it
 * points to the actual byte length of the output_data.
 * @param res Pointer to the output buffer
 * @param ctx Pointer to a BN_CTX
 *
 * Returns 0 if successful, BN error code if unsuccessful
 */
static unsigned int mul_sw(int fc_1_length, unsigned char *fc1, int fc_2_length,
			   unsigned char *fc2, int *res_length, unsigned char *res, BN_CTX *ctx)
{
	int rc = 0;
	BIGNUM *b_fc1 = NULL;
	BIGNUM *b_fc2 = NULL;
	BIGNUM *b_res = NULL;

	BN_CTX_start(ctx);

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!openssl_in_fips_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	b_fc1 = BN_CTX_get(ctx);
	b_fc2 = BN_CTX_get(ctx);
	if ((b_res = BN_CTX_get(ctx)) == NULL) {
		rc = -ENOMEM;
		goto cleanup;
	}

	b_fc1 = BN_bin2bn((const unsigned char *)fc1, fc_1_length, b_fc1);
	b_fc2 = BN_bin2bn((const unsigned char *)fc2, fc_2_length, b_fc2);

	if (!(BN_mul(b_res, b_fc1, b_fc2, ctx))) {
		goto err;
	}

	/* The padded conversion does not depend on the value's length. */
	if (BN_bn2binpad(b_res, res, *res_length) < 0) {
		rc = 1;
		goto cleanup;
	}

	goto cleanup;

      err:
	rc = EIO;

      cleanup:
	BN_CTX_end(ctx);

	return rc;
}
#endif /* NO_SW_FALLBACKS */
