/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Jon Grimm <jgrimm@us.ibm.com>
 *	    Amuche Chukudebelu
 *	    Robert Burroughs
 *	    Eric Rossman <edrossma@us.ibm.com>
 *	    Ralph Wuerthner <ralph.wuerthner@de.ibm.com>
 *	    Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2001, 2005, 2008, 2009, 2011
 */

#include <string.h>
#include <errno.h>
#include "ica_api.h"
#include "s390_rsa.h"

unsigned int icaOpenAdapter(unsigned int adapter_id,
			    ica_adapter_handle_t *adapter_handle)
{
	return ica_open_adapter(adapter_handle);
}

unsigned int icaCloseAdapter(ica_adapter_handle_t adapter_handle)
{
	return ica_close_adapter(adapter_handle);
}

unsigned int icaSha1(ica_adapter_handle_t adapter_handle,
		     unsigned int message_part,
		     unsigned int input_length,
		     unsigned char *input_data,
		     unsigned int context_length,
		     sha_context_t *sha_context,
		     unsigned int *output_length,
		     unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < SHA_HASH_LENGTH)
		return EINVAL;
	*output_length = SHA_HASH_LENGTH;
	return ica_sha1(message_part, input_length, input_data,
			sha_context, output_data);
}

unsigned int icaSha224(ica_adapter_handle_t adapter_handle,
		       unsigned int message_part,
		       unsigned int input_length,
		       unsigned char *input_data,
		       unsigned int context_length,
		       sha256_context_t *sha256_context,
		       unsigned int *output_length,
		       unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < SHA224_HASH_LENGTH)
		return EINVAL;
	*output_length = SHA224_HASH_LENGTH;
	return ica_sha224(message_part, input_length, input_data,
			  sha256_context, output_data);
}

unsigned int icaSha256(ica_adapter_handle_t adapter_handle,
	  	       unsigned int message_part,
	  	       unsigned int input_length,
	  	       unsigned char *input_data,
	  	       unsigned int context_length,
	  	       sha256_context_t *sha256_context,
	  	       unsigned int *output_length,
		       unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < SHA256_HASH_LENGTH)
		return EINVAL;
	*output_length = SHA256_HASH_LENGTH;
	return ica_sha256(message_part, input_length, input_data,
			  sha256_context, output_data);
}

unsigned int icaSha384(ica_adapter_handle_t adapter_handle,
		       unsigned int message_part,
	  	       unsigned int input_length,
		       unsigned char *input_data,
		       unsigned int context_length,
		       sha512_context_t *sha512_context,
		       unsigned int *output_length,
		       unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < SHA384_HASH_LENGTH)
		return EINVAL;
	*output_length = SHA384_HASH_LENGTH;
	return ica_sha384(message_part, input_length, input_data,
			  sha512_context, output_data);
}

unsigned int icaSha512(ica_adapter_handle_t adapter_handle,
		       unsigned int message_part,
		       unsigned int input_length,
		       unsigned char *input_data,
		       unsigned int context_length,
		       sha512_context_t *sha512_context,
		       unsigned int *output_length,
		       unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < SHA512_HASH_LENGTH)
		return EINVAL;
	*output_length = SHA512_HASH_LENGTH;
	return ica_sha512(message_part, input_length, input_data,
			  sha512_context, output_data);
}

unsigned int icaRandomNumberGenerate(ica_adapter_handle_t adapter_handle,
				     unsigned int output_length,
				     unsigned char *output_data)
{
	return ica_random_number_generate(output_length, output_data);
}

unsigned int icaRsaKeyGenerateModExpo(ica_adapter_handle_t adapter_handle,
				      unsigned int modulus_bit_length,
				      unsigned int public_exp_type,
				      unsigned int *public_key_length,
				      ICA_KEY_RSA_MODEXPO *public_key,
				      unsigned int *private_key_length,
				      ICA_KEY_RSA_MODEXPO *private_key)
{
	if (private_key == NULL || public_key == NULL ||
	    private_key_length == NULL || public_key_length == NULL)
		return EINVAL;

	public_key->modulusBitLength = modulus_bit_length;
	private_key->modulusBitLength = modulus_bit_length;

	unsigned int key_length = (modulus_bit_length + 7) / 8;

	ica_rsa_key_mod_expo_t new_public_key;
	new_public_key.key_length = key_length;
	new_public_key.exponent = &public_key->keyRecord[0];
	new_public_key.modulus =
		&public_key->keyRecord[new_public_key.key_length];

	ica_rsa_key_mod_expo_t new_private_key;
	new_private_key.key_length = key_length;
	new_private_key.exponent = &private_key->keyRecord[0];
	new_private_key.modulus =
		&private_key->keyRecord[new_private_key.key_length];

	switch (public_exp_type) {
	case RSA_PUBLIC_3:
		memset(new_public_key.exponent, 0, new_public_key.key_length);
		*(unsigned long *)((unsigned char *)new_public_key.exponent +
			new_public_key.key_length - sizeof(unsigned long)) = 3;
		break;
	case RSA_PUBLIC_65537:
		memset(new_public_key.exponent, 0, new_public_key.key_length);
		*(unsigned long *)((unsigned char *)new_public_key.exponent +
			new_public_key.key_length - sizeof(unsigned long))
			= 65537;
		break;
	case RSA_PUBLIC_RANDOM:
		/* If random, then zero it completely for the random mode will
		 * be chosen anyway if the buffer is detected to be zeroed. */
		memset(new_public_key.exponent, 0, new_public_key.key_length);
		break;
	case RSA_PUBLIC_FIXED:
		/* Do not do anything. There is a value in the buffer, which
		 * will be used later as exponent. Choose your exponent
		 * carfully. */
		break;
	}

	/* Set values in the key structs to give back to user*/
	/* For public key */
	public_key->nLength = key_length;
	public_key->expLength = key_length;
	public_key->expOffset = sizeof(ICA_KEY_RSA_MODEXPO) -
				sizeof(ICA_KEY_RSA_MODEXPO_REC);
	public_key->nOffset = public_key->expOffset + public_key->expLength;
	public_key->keyLength = sizeof(ICA_KEY_RSA_MODEXPO);
	/* For private key */
	private_key->nLength = key_length;
	private_key->expLength = key_length;
	private_key->expOffset = sizeof(ICA_KEY_RSA_MODEXPO) -
				sizeof(ICA_KEY_RSA_MODEXPO_REC);
	public_key->nOffset = public_key->expOffset + public_key->expLength;
	private_key->keyLength = sizeof(ICA_KEY_RSA_MODEXPO);

	return ica_rsa_key_generate_mod_expo(adapter_handle,
					     modulus_bit_length,
					     &new_public_key,
					     &new_private_key);
}

unsigned int icaRsaKeyGenerateCrt(ica_adapter_handle_t adapter_handle,
				  unsigned int modulus_bit_length,
				  unsigned int public_exp_type,
				  unsigned int *public_key_length,
				  ICA_KEY_RSA_MODEXPO *public_key,
				  unsigned int *private_key_length,
				  ICA_KEY_RSA_CRT *private_key)
{
	if (private_key == NULL || public_key == NULL ||
	    private_key_length == NULL || public_key_length == NULL)
		return EINVAL;

	public_key->modulusBitLength = modulus_bit_length;
	private_key->modulusBitLength = modulus_bit_length;	

	ica_rsa_key_mod_expo_t new_public_key;
	unsigned int key_length = (modulus_bit_length + 7) / 8;
	new_public_key.key_length = key_length;
	new_public_key.exponent = &public_key->keyRecord[0];
	new_public_key.modulus = &public_key->keyRecord[key_length];

	ica_rsa_key_crt_t new_private_key;
	new_private_key.key_length = key_length;

	/* Different order of key parts in old structure is described in
	 * ica_api.h */
	new_private_key.dp = &private_key->keyRecord[0];
	new_private_key.dq = &private_key->keyRecord[key_length / 2 + 8];
	new_private_key.p = &private_key->keyRecord[key_length + 8];
	new_private_key.q = &private_key->keyRecord[3 * key_length / 2 + 16];
	new_private_key.qInverse =
		&private_key->keyRecord[2 * key_length + 16];

	switch (public_exp_type) {
	case RSA_PUBLIC_3:
		memset(new_public_key.exponent, 0, new_public_key.key_length);
		*(unsigned long *)((unsigned char *)new_public_key.exponent +
			new_public_key.key_length - sizeof(unsigned long))
			= 3;
		break;
	case RSA_PUBLIC_65537:
		memset(new_public_key.exponent, 0, new_public_key.key_length);
		*(unsigned long *)((unsigned char *)new_public_key.exponent +
			new_public_key.key_length - sizeof(unsigned long))
			= 65537;
		break;
	case RSA_PUBLIC_RANDOM:
		/* If random, then zero it completely for the random mode will
		 * be chosen anyway if the buffer is detected to be zeroed. */
		memset(new_public_key.exponent, 0, new_public_key.key_length);
		break;
	case RSA_PUBLIC_FIXED:
		/* Do not do anything. There is a value in the buffer, which
		 * will be used later as exponent. Choose your exponent
		 * carfully. */
		break;
	}

	/* Set values in the key structs to give back to user*/
	/* For public key */
	public_key->nLength = key_length;
	public_key->expLength = key_length;
	public_key->expOffset = sizeof(ICA_KEY_RSA_MODEXPO) -
				sizeof(ICA_KEY_RSA_MODEXPO_REC);
	public_key->nOffset = public_key->expOffset + public_key->expLength;
	public_key->keyLength = sizeof(ICA_KEY_RSA_MODEXPO);
	/* For private key */
	private_key->pLength = key_length / 2 + 8;
	private_key->qLength = key_length / 2;
	private_key->dpLength = key_length / 2 + 8;
	private_key->dqLength = key_length / 2;
	private_key->qInvLength = key_length / 2 + 8;
	/* For public key */
	private_key->dpOffset = sizeof(ICA_KEY_RSA_CRT) -
				sizeof(ICA_KEY_RSA_CRT_REC);
	private_key->dqOffset = private_key->dpOffset + private_key->dpLength;
	private_key->pOffset = private_key->dqOffset + private_key->dqLength;
	private_key->qOffset = private_key->pOffset + private_key->pLength;
	private_key->qInvOffset = private_key->qOffset + private_key->qLength;
	private_key->keyLength = sizeof(ICA_KEY_RSA_CRT);

	return ica_rsa_key_generate_crt(adapter_handle, modulus_bit_length,
					&new_public_key, &new_private_key);
}

unsigned int icaRsaModExpo(ica_adapter_handle_t adapter_handle,
			   unsigned int input_length,
			   unsigned char *input_data,
			   ICA_KEY_RSA_MODEXPO *rsa_key,
			   unsigned int *output_length,
			   unsigned char *output_data)
{
	if (output_data == NULL || rsa_key == NULL || output_data == NULL ||
	    output_length == NULL)
		return EINVAL;

	unsigned int key_length = (rsa_key->modulusBitLength + 7) / 8;

	if (rsa_key->modulusBitLength == 0 || input_length != key_length ||
	    *output_length < input_length)
		return EINVAL;
	*output_length = key_length;

	ica_rsa_key_mod_expo_t new_rsa_key;
	new_rsa_key.key_length = key_length;

        new_rsa_key.modulus = &rsa_key->keyRecord[new_rsa_key.key_length];
        new_rsa_key.exponent = &rsa_key->keyRecord[0];

	return ica_rsa_mod_expo(adapter_handle, input_data,
				&new_rsa_key, output_data);
}

unsigned int icaRsaCrt(ica_adapter_handle_t adapter_handle,
		       unsigned int input_length,
		       unsigned char *input_data,
		       ICA_KEY_RSA_CRT *rsa_key,
		       unsigned int *output_length,
		       unsigned char *output_data)
{
	if (output_data == NULL || rsa_key == NULL || output_data == NULL ||
	    output_length == NULL)
		return EINVAL;

	unsigned int key_length = (rsa_key->modulusBitLength + 7) / 8;

	if (rsa_key->modulusBitLength == 0 || input_length != key_length ||
	    *output_length < input_length)
		return EINVAL;
	*output_length = key_length;

	ica_rsa_key_crt_t new_rsa_key;
	new_rsa_key.key_length = key_length;

	/* Old, complicated key structure is described in ica_api.h */
	new_rsa_key.dp = &rsa_key->keyRecord[0];
	new_rsa_key.dq = &rsa_key->keyRecord[key_length / 2 + 8];
	new_rsa_key.p = &rsa_key->keyRecord[key_length + 8];
	new_rsa_key.q =	&rsa_key->keyRecord[3 * key_length / 2 + 16];
	new_rsa_key.qInverse = &rsa_key->keyRecord[2 * key_length + 16];

	return ica_rsa_crt(adapter_handle, input_data, &new_rsa_key,
			   output_data);
}

unsigned int icaDesEncrypt(ica_adapter_handle_t adapter_handle,
			   unsigned int mode,
			   unsigned int data_length,
			   unsigned char *input_data,
			   ica_des_vector_t *iv,
			   ica_des_key_single_t *des_key,
			   unsigned int *output_length,
			   unsigned char *output_data)
{
	/* Length of output data will be a multiple of the cipher block.
	 * For we check that data_length is a multiple of the cipher block,
	 * we can assign data_length to output_length.
	 */
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < data_length)
		return EINVAL;
	*output_length = data_length;
	return ica_des_encrypt(mode, data_length, input_data, iv, des_key,
			       output_data);
}

unsigned int icaDesDecrypt(ica_adapter_handle_t adapter_handle,
			   unsigned int mode,
			   unsigned int data_length,
			   unsigned char *input_data,
			   ica_des_vector_t *iv,
			   ica_des_key_single_t *des_key,
			   unsigned int *output_length,
			   unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < data_length)
		return EINVAL;
	*output_length = data_length;
	return ica_des_decrypt(mode, data_length, input_data, iv, des_key,
			       output_data);
}

unsigned int icaTDesEncrypt(ica_adapter_handle_t adapter_handle,
			    unsigned int mode,
			    unsigned int data_length,
			    unsigned char *input_data,
			    ica_des_vector_t *iv,
			    ica_des_key_triple_t *des_key,
			    unsigned int *output_length,
			    unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < data_length)
		return EINVAL;
	*output_length = data_length;
	return ica_3des_encrypt(mode, data_length, input_data, iv, des_key,
				output_data);
}

unsigned int icaTDesDecrypt(ica_adapter_handle_t adapter_handle,
			    unsigned int mode,
			    unsigned int data_length,
			    unsigned char *input_data,
			    ica_des_vector_t *iv,
			    ica_des_key_triple_t *des_key,
			    unsigned int *output_length,
			    unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < data_length)
		return EINVAL;
	*output_length = data_length;
	return ica_3des_decrypt(mode, data_length, input_data, iv, des_key,
				output_data);
}

unsigned int icaAesEncrypt(ica_adapter_handle_t adapter_handle,
			   unsigned int mode,
			   unsigned int data_length,
			   unsigned char *input_data,
			   ica_aes_vector_t *iv,
			   unsigned int key_length,
			   unsigned char *aes_key,
			   unsigned int *output_length,
			   unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < data_length)
		return EINVAL;
	*output_length = data_length;
	return ica_aes_encrypt(mode, data_length, input_data, iv, key_length,
			       aes_key, output_data);
}

unsigned int icaAesDecrypt(ica_adapter_handle_t adapter_handle,
			   unsigned int mode,
			   unsigned int data_length,
			   unsigned char *input_data,
			   ica_aes_vector_t *iv,
			   unsigned int key_length,
			   unsigned char *aes_key,
			   unsigned int *output_length,
			   unsigned char *output_data)
{
	if (output_length == NULL)
		return EINVAL;
	if (*output_length < data_length)
		return EINVAL;
	*output_length = data_length;
	return ica_aes_decrypt(mode, data_length, input_data, iv, key_length,
			       aes_key, output_data);
}

unsigned int icaRsaModMult(ica_adapter_handle_t adapter_handle,
			   unsigned int input_length,
			   unsigned char *input_data,
			   ICA_KEY_RSA_MODEXPO *rsa_key,
			   unsigned int *output_length,
			   unsigned char *output_data)
{
	ica_rsa_modmult_t rb;
	int bytelength;
	unsigned char pad[256];
	unsigned char *inputdata;

	if ((input_length < 1) ||
	    (input_length > 256) ||
	    (input_data == NULL) ||
	    (rsa_key == NULL) || (output_data == NULL))
		return EINVAL;

	bytelength = (rsa_key->modulusBitLength + 7) / 8;
	if (input_length > bytelength)
		return EINVAL;
	if (input_length == bytelength)
		inputdata = input_data;
	else {
		memset(pad, 0x00, 256);
		memcpy(pad + bytelength - input_length, input_data,
		       input_length);
		inputdata = pad;
	}
	rb.inputdata = (char *)inputdata;
	rb.inputdatalength = bytelength;
	rb.outputdata = (char *)output_data;
	rb.outputdatalength = bytelength;
	rb.b_key = (char *)&rsa_key->keyRecord[0];
	rb.n_modulus = (char *)&rsa_key->keyRecord[bytelength];
	return rsa_mod_mult_sw(&rb);
}

