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
#include <openssl/rsa.h>

#include "s390_rsa.h"
#include "s390_prng.h"

static unsigned int mod_expo_sw(int arg_length, char *arg, int exp_length,
				char *exp, int mod_length, char *mod,
				int *res_length, char *res, BN_CTX *ctx);
static unsigned int mod_mul_sw(int fc_1_length, char *fc1, int fc_2_length,
			      char *fc2, int mod_length, char *mod,
			      int *res_length, char *res, BN_CTX *ctx);
static unsigned int mod_sw(int arg_length, char *arg, int mod_length,
			   char *mod, int *res_length, char *res, BN_CTX *ctx);
static unsigned int add_sw(int aug_length, char *aug, int add_length,
			   char *add, int *res_length, char *res, BN_CTX *ctx);
static unsigned int mod_sub_sw(int min_length, char *minu, int sub_length,
			       char *sub, int mod_length, char *mod,
			       int *res_length, char *res, BN_CTX * ctx);
static unsigned int mul_sw(int fc_1_length, char *fc1, int fc_2_length,
			   char *fc2, int *res_length, char *res, BN_CTX *ctx);
static unsigned int mod_expo_sw(int arg_length, char *arg, int exp_length,
				char *exp, int mod_length, char *mod,
				int *res_length, char *res, BN_CTX *ctx);

RSA* rsa_key_generate(unsigned int modulus_bit_length,
		      unsigned long *public_exponent)
{
	if (*public_exponent == 0)
	{
		do {
			s390_prng((unsigned char*)public_exponent,
				  sizeof(unsigned long));
		} while (*public_exponent <= 2 || !(*public_exponent % 2));
	}
	return RSA_generate_key(modulus_bit_length, *public_exponent, NULL, NULL);
}

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
	RSA *rsa = rsa_key_generate(modulus_bit_length,
				    (unsigned long*)(public_key->exponent +
				    public_key->key_length -
				    sizeof(unsigned long)));
	if (!rsa)
		return errno;
	/* Set key buffers zero to make sure there is no
	 * unneeded junk in between.
	 */
	memset(public_key->modulus, 0, public_key->key_length);
	memset(private_key->modulus, 0, private_key->key_length);
	memset(private_key->exponent, 0, private_key->key_length);

	unsigned int bn_length = BN_num_bytes(rsa->n);
	unsigned int offset = 0;

	if (bn_length < public_key->key_length)
		offset = public_key->key_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(rsa->n, public_key->modulus + offset);

	memcpy(private_key->modulus, public_key->modulus,
	       public_key->key_length);

	bn_length = BN_num_bytes(rsa->d);
	if (bn_length < private_key->key_length)
		offset = private_key->key_length - bn_length;
	else
		offset = 0;	
	BN_bn2bin(rsa->d, private_key->exponent + offset);

	RSA_free(rsa);

	return 0;
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
	RSA *rsa = rsa_key_generate(modulus_bit_length,
				    (unsigned long*)(public_key->exponent +
				    public_key->key_length -
				    sizeof(unsigned long)));
	if (!rsa)
		return errno;
	
	/* Public exponent has already been set, no need to do this here.
	 * For public key, only modulus needs to be set.
	 */
	memset(public_key->modulus, 0, public_key->key_length);

	/* Make sure that key parts are copied to the end of the buffer */
	unsigned int offset = 0;

	unsigned int bn_length = BN_num_bytes(rsa->n);
	if (bn_length < public_key->key_length)
		offset = public_key->key_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(rsa->n, public_key->modulus + offset);

	memset(private_key->p, 0, private_key->key_length / 2 + 8);
	memset(private_key->q, 0, private_key->key_length / 2);
	memset(private_key->dp, 0, private_key->key_length / 2 + 8);
	memset(private_key->dq, 0, private_key->key_length / 2);
	memset(private_key->qInverse, 0, private_key->key_length / 2 + 8);

	unsigned int key_part_length = private_key->key_length / 2;

	/* We add the "+8" because it is a requirement by the crypto adapters
	 * to have an 8 byte zero pad in the beginning of the fields for:
	 * p, dp, and qInverse.
	 */

	/* Copy p into buffer */
	bn_length = BN_num_bytes(rsa->p);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(rsa->p, private_key->p + 8 + offset);

	/* Copy q into buffer */
	bn_length = BN_num_bytes(rsa->q);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(rsa->q, private_key->q + offset);

	/* Copy dp into buffer */
	bn_length = BN_num_bytes(rsa->dmp1);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(rsa->dmp1, private_key->dp + 8 + offset);

	/* Copy dq into buffer */
	bn_length = BN_num_bytes(rsa->dmq1);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;
	BN_bn2bin(rsa->dmq1, private_key->dq + offset);
	
	/* Copy qInverse into buffer */
	bn_length = BN_num_bytes(rsa->iqmp);
	if(bn_length < key_part_length)
		offset = key_part_length - bn_length;
	else
		offset = 0;

	BN_bn2bin(rsa->iqmp, private_key->qInverse + 8 + offset);

	RSA_free(rsa);

	return 0;
}
/**
 * @deprecated Perform a modular muliplication operation in software.
 */
unsigned int rsa_mod_mult_sw(ica_rsa_modmult_t *pMul)
{
        int rc = 0;
        BN_CTX *ctx = NULL;

        if ((ctx = BN_CTX_new()) == NULL) {
		return errno;		
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
static unsigned int mod_mul_sw(int fc_1_length, char *fc1, int fc_2_length,
			      char *fc2, int mod_length, char *mod,
			      int *res_length, char *res, BN_CTX *ctx)
{
        int rc = 0;
        int ln = 0;
        int pad = 0;
        BIGNUM *b_fc1 = NULL;
        BIGNUM *b_fc2 = NULL;
        BIGNUM *b_mod = NULL;
        BIGNUM *b_res = NULL;

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

        if (!(BN_mod_mul(b_res, b_fc1, b_fc2, b_mod, ctx))) {
                goto err;
        }

        if ((ln = BN_num_bytes(b_res)) > *res_length) {
                rc = EIO;
                goto cleanup;
        }

        if (ln)
                pad = *res_length - ln;

        ln = BN_bn2bin(b_res,(unsigned char *)(res + pad));

        if (pad)
                memset(res, 0, pad);

        goto cleanup;

      err:
        rc = EIO;

      cleanup:
        BN_CTX_end(ctx);
	
	 return rc;
}

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
        int rc = 0;
        BN_CTX *ctx = NULL;

        if ((ctx = BN_CTX_new()) == NULL) {
		return errno;
        }

        rc = mod_expo_sw(pMex->inputdatalength, pMex->inputdata,
                       pMex->inputdatalength, pMex->b_key,
                       pMex->inputdatalength, pMex->n_modulus,
                       (int *)&(pMex->outputdatalength), pMex->outputdata, ctx);

        BN_CTX_free(ctx);
	if (rc == 1)
		rc = EIO;
        return rc;
}

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
static unsigned int mod_expo_sw(int arg_length, char *arg, int exp_length,
				char *exp, int mod_length, char *mod,
				int *res_length, char *res, BN_CTX *ctx)
{
        int rc = 0;
        int ln = 0;
        int pad = 0;
        BIGNUM *b_arg = NULL;
        BIGNUM *b_exp = NULL;
        BIGNUM *b_mod = NULL;
        BIGNUM *b_res = NULL;
        BN_CTX *mod_expo_ctx = NULL;
        int mod_expo_rc = 1;

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

        if ((ln = BN_num_bytes(b_res)) > *res_length) {
                rc = 1;
                goto cleanup;
        }

    if (ln)
                pad = *res_length - ln;

        ln = BN_bn2bin(b_res, (unsigned char *)(res + pad));

        if (pad)
                memset(res, 0, pad);

        goto cleanup;

      err:
        rc = EIO;

      cleanup:
        BN_CTX_end(ctx);

        return rc;
}

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
	int rc = 0;
	int long_length = 0;
	int short_length = 0;
	int orig_outl;
	BN_CTX *ctx = NULL;

	short_length = pCrt->inputdatalength / 2;
	long_length = short_length + 8;
/*	
	Use variable buffer length. Earlier version contained fixed 136byte
	size for ir buffers. Thus the software fallback should be able to
	handle keys of bigger size, too.
*/
	char ir1[long_length];
	int ir_1_length = sizeof(ir1);
	char ir2[long_length];
	int ir_2_length = sizeof(ir2);
	char temp[long_length];
	int temp_length = sizeof(temp);

	if ((ctx = BN_CTX_new()) == NULL) {
		return errno;
	}

	memset(ir1, 0, sizeof(ir1));
	if ((rc = mod_sw(pCrt->inputdatalength, pCrt->inputdata,
			 long_length, pCrt->np_prime, &ir_1_length, ir1, ctx)) != 0)
		goto err;

	memset(temp, 0, sizeof(temp));
	if ((rc = mod_expo_sw(ir_1_length, ir1,
			      long_length, pCrt->bp_key,
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

	temp_length = sizeof(temp);
	memset(temp, 0, sizeof(temp));
	if ((rc = mod_expo_sw(ir_2_length, ir2,
			      short_length, pCrt->bq_key,
			      short_length, pCrt->nq_prime,
			      &temp_length, temp, ctx)) != 0)
		goto err;

	memset(ir2, 0, sizeof(ir2));
	memcpy(ir2, temp, temp_length);
	ir_2_length = temp_length;

	temp_length = sizeof(ir1);
	if ((rc = mod_sub_sw(ir_1_length, ir1,
			   ir_2_length, ir2,
			   long_length, pCrt->np_prime,
			   &temp_length, ir1, ctx)) != 0) {
		if (rc != -1) {
			goto err;
		} else {
			if (ir_2_length > pCrt->outputdatalength) {
				memcpy(pCrt->outputdata,
				       ir2 + (ir_2_length -
					      pCrt->outputdatalength),
				       pCrt->outputdatalength);
			} else {
				if (ir_2_length < pCrt->outputdatalength) {
					memset(pCrt->outputdata, 0,
					       (pCrt->outputdatalength -
						ir_2_length));
					memcpy(pCrt->outputdata +
					       (pCrt->outputdatalength -
						ir_2_length), ir2, ir_2_length);
				} else {
					memcpy(pCrt->outputdata, ir2,
					       ir_2_length);
				}
			}
			rc = 0;
			goto cleanup;
		}
	}

	ir_1_length = temp_length;

	temp_length = sizeof(temp);
	memset(temp, 0, sizeof(temp));
	if ((rc = mod_mul_sw(ir_1_length, ir1,
			     long_length, pCrt->u_mult_inv,
			     long_length, pCrt->np_prime,
			     &temp_length, temp, ctx)) != 0)
		goto err;

	orig_outl = pCrt->outputdatalength;

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
	BN_CTX_free(ctx);

	return rc;
}

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
static unsigned int mod_sw(int arg_length, char *arg, int mod_length,
			   char *mod, int *res_length, char *res, BN_CTX *ctx)
{
        int rc = 0;
        int ln = 0;
        int pad = 0;
        BIGNUM *b_arg = NULL;
        BIGNUM *b_mod = NULL;
        BIGNUM *b_res = NULL;

        BN_CTX_start(ctx);

        b_arg = BN_CTX_get(ctx);
        b_mod = BN_CTX_get(ctx);
        if ((b_res = BN_CTX_get(ctx)) == NULL) {
                rc = -ENOMEM;
                goto cleanup;
        }

        b_arg = BN_bin2bn((const unsigned char *)arg, arg_length, b_arg);
        b_mod = BN_bin2bn((const unsigned char *)mod, mod_length, b_mod);

        if (!(BN_mod(b_res, b_arg, b_mod, ctx))) {
                goto err;
        }

        if ((ln = BN_num_bytes(b_res)) > *res_length) {
                rc = 1;
                goto cleanup;
        }

        if (ln)
                pad = *res_length - ln;

        ln = BN_bn2bin(b_res, (unsigned char *)(res + pad));

        if (pad)
                memset(res, 0, pad);

        goto cleanup;

      err:
        rc = EIO;

      cleanup:
        BN_CTX_end(ctx);

        return rc;
}

/**
 * Perform a multiprecision subtraction modulo a modulus using a minuend,
 * subtrahend and modulus
 *
 * @param min_length The byte length of the minuend
 * @param min Pointer to minuend
 * @param sub_length The byte length of the subtrahend
 * @param sub Pointer to the subtrahend
 * @param mod_length The byte length of the modulus
 * @param mod The modulus
 * @param res_length
 * On input it points to the byte length of the output buffer. On output it
 * points to the actual byte length of the output_data
 * @param res Pointer to the output buffer
 * @param ctx Pointer to a BN_CTX
 *
 * Returns 0 if successful, BN error code if unsuccessful
 * Process:
 * 1) If the subtrahend exceeds the minuend, use add_sw to
 * add the modulus to the minuend
 * 2) Call BN_CTX_get for the minuend, subtrahend & result BN's
 * 3) Convert the minuend and subtrahend BN's using BN_bin2bn
 * 4) Call BN_sub
 * 5) Convert the result from a BN to a string using BN_bn2bin
 * 6) Call BN_free for the minuend, subtrahend and result BN's
 */
static unsigned int mod_sub_sw(int min_length, char *minu, int sub_length,
			       char *sub, int mod_length, char *mod,
			       int *res_length, char *res, BN_CTX * ctx)
{
        int rc = 0;
        int ln = 0;
        int pad = 0;

        int min_size, sub_size, dif_size;

        BIGNUM *b_min = NULL;
        BIGNUM *b_sub = NULL;
        BIGNUM *b_mod = NULL;
        BIGNUM *b_res = NULL;

        BN_CTX_start(ctx);

        b_min = BN_CTX_get(ctx);
        b_sub = BN_CTX_get(ctx);
        b_mod = BN_CTX_get(ctx);
        if ((b_res = BN_CTX_get(ctx)) == NULL) {
                rc = -ENOMEM;
                goto cleanup;
        }

        b_min = BN_bin2bn((const unsigned char *)minu, min_length, b_min);
        b_sub = BN_bin2bn((const unsigned char *)sub, sub_length, b_sub);
        b_mod = BN_bin2bn((const unsigned char *)mod, mod_length, b_mod);

        min_size = BN_num_bytes(b_min);
        sub_size = BN_num_bytes(b_sub);

        /* if sub == min, the result is zero, but it's an error */
        if (sub_size == min_size) {
                dif_size = memcmp(sub, minu, sub_length);
                if (dif_size == 0) {
                        memset(res, 0, *res_length);
                        rc = -1;
                        goto cleanup;
                }
        }
        /* if sub < min, the result is just min - sub */
        if ((sub_size < min_size) || ((sub_size == min_size) && (dif_size < 0))) {
                if (!(BN_sub(b_res, b_min, b_sub))) {
                        goto err;
                }
        } else {                /* sub > min, so the result is (min + mod) - sub */
                if (!(BN_add(b_res, b_min, b_mod))) {
                        goto err;
                }
                if (!(BN_sub(b_res, b_res, b_sub))) {
                        goto err;
                }
        }

        if ((ln = BN_num_bytes(b_res)) > *res_length) {
                rc = 1;
                goto cleanup;
        }

        if (ln)
                pad = *res_length - ln;

        ln = BN_bn2bin(b_res, (unsigned char *)(res + pad));

        if (pad)
                memset(res, 0, pad);

        goto cleanup;

      err:
        rc = EIO;

      cleanup:
        BN_CTX_end(ctx);

        return rc;
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
static unsigned int add_sw(int aug_length, char *aug, int add_length,
			   char *add, int *res_length, char *res, BN_CTX *ctx)
{
        int rc = 0;
        int ln = 0;
        int pad = 0;
        BIGNUM *b_aug = NULL;
        BIGNUM *b_add = NULL;
        BIGNUM *b_res = NULL;

        BN_CTX_start(ctx);

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

        if ((ln = BN_num_bytes(b_res)) > *res_length) {
                rc = 1;
                goto cleanup;
        }

        if (ln)
                pad = *res_length - ln;

        ln = BN_bn2bin(b_res, (unsigned char *)(res + pad));

        if (pad)
                memset(res, 0, pad);

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
static unsigned int mul_sw(int fc_1_length, char *fc1, int fc_2_length,
			   char *fc2, int *res_length, char *res, BN_CTX *ctx)
{
        int rc = 0;
        int ln = 0;
        int pad = 0;
        BIGNUM *b_fc1 = NULL;
        BIGNUM *b_fc2 = NULL;
        BIGNUM *b_res = NULL;

        BN_CTX_start(ctx);

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

        if ((ln = BN_num_bytes(b_res)) > *res_length) {
                rc = 1;
                goto cleanup;
        }

        if (ln)
                pad = *res_length - ln;

        ln = BN_bn2bin(b_res, (unsigned char *)(res + pad));

        if (pad)
                memset(res, 0, pad);

        goto cleanup;

      err:
        rc = EIO;

      cleanup:
        BN_CTX_end(ctx);

        return rc;
}

