/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2011
 */

#ifndef S390_RSA_H
#define S390_RSA_H

#include <openssl/bn.h>
#include <asm/zcrypt.h>
#include "ica_api.h"

typedef struct ica_rsa_modexpo ica_rsa_modexpo_t;
typedef struct ica_rsa_modexpo_crt ica_rsa_modexpo_crt_t;
typedef struct ica_rsa_modexpo ica_rsa_modmult_t;
unsigned int rsa_key_generate_mod_expo(ica_adapter_handle_t deviceHandle,
				       unsigned int modulus_bit_length,
				       ica_rsa_key_mod_expo_t *public_key,
				       ica_rsa_key_mod_expo_t *private_key);
unsigned int ica_rsa_key_generate_crt(ica_adapter_handle_t device_handle,
				      unsigned int modulus_bit_length,
				      ica_rsa_key_mod_expo_t *public_key,
				      ica_rsa_key_crt_t *private_key);
unsigned int rsa_key_generate_mod_expo(ica_adapter_handle_t deviceHandle,
                                       unsigned int modulus_bit_length,
                                       ica_rsa_key_mod_expo_t *public_key,
                                       ica_rsa_key_mod_expo_t *private_key);
unsigned int rsa_key_generate_crt(ica_adapter_handle_t deviceHandle,
				  unsigned int modulus_bit_length,
				  ica_rsa_key_mod_expo_t *public_key,
				  ica_rsa_key_crt_t *private_key);
unsigned int rsa_crt_sw(ica_rsa_modexpo_crt_t * pCrt);
unsigned int rsa_mod_mult_sw(ica_rsa_modmult_t * pMul);
unsigned int rsa_mod_expo_sw(ica_rsa_modexpo_t *pMex);
#endif

