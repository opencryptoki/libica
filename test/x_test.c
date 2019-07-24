/*
 * This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * Copyright IBM Corp. 2019
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>

#include "ica_api.h"
#include "testcase.h"

#define ITERATIONS	100  /*XXX*/

static void check_functionlist(void);

static void x25519_pc(void);
static void x448_pc(void);

int main(int argc, char *argv[])
{
	int i;

	set_verbosity(argc, argv);

	check_functionlist();

	VV_(printf("\n=== X25519 PC ===\n"));
	for (i = 0; i < ITERATIONS; i++)
		x25519_pc();

	VV_(printf("\n=== X448 PC ===\n"));
	for (i = 0; i < ITERATIONS; i++)
		x448_pc();
}

static void check_functionlist(void)
{
	unsigned int i, listlen, func;
	libica_func_list_element *list;

	if (ica_get_functionlist(NULL, &listlen))
		EXIT_ERR("ica_get_functionlist failed.");

	func = 0;

	list = calloc(1, sizeof(*list) * listlen);
	if (list == NULL)
		EXIT_ERR("calloc failed.");

	if (ica_get_functionlist(list, &listlen))
		EXIT_ERR("ica_get_functionlist failed.");

	for (i = 0; i < listlen; i++) {
		if (list[i].mech_mode_id == X25519_KEYGEN
		    && (list[i].flags & 4))
			func |= 0x01;
		if (list[i].mech_mode_id == X25519_DERIVE
		    && (list[i].flags & 4))
			func |= 0x02;
		if (list[i].mech_mode_id == X448_KEYGEN
		    && (list[i].flags & 4))
			func |= 0x04;
		if (list[i].mech_mode_id == X448_DERIVE
		    && (list[i].flags & 4))
			func |= 0x08;
	}

	free(list);

	if (func != (0x01 | 0x02 | 0x04 | 0x08))
		exit(TEST_SKIP);
}

static void x25519_pc(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	ICA_X25519_CTX *ctx1 = NULL, *ctx2 = NULL;
	EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	unsigned char priv[32], pub[32], key1[32], key2[32];
	size_t keylen = 0;

	if (ica_x25519_ctx_new(&ctx1))
		EXIT_ERR("ica_x448_ctx_new failed.");
	if (ica_x25519_ctx_new(&ctx2))
		EXIT_ERR("ica_x448_ctx_new failed.");

	if (ica_x25519_key_gen(ctx1))
		EXIT_ERR("ica_x25519_key_gen failed.");
	if (ica_x25519_key_gen(ctx2))
		EXIT_ERR("ica_x25519_key_gen failed.");

	if (ica_x25519_key_get(ctx1, priv, NULL))
		EXIT_ERR("ica_x25519_key_get failed.");
	if (ica_x25519_key_get(ctx2, NULL, pub))
		EXIT_ERR("ica_x25519_key_get failed.");

	pkey1 = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
					     priv, sizeof(priv));
	if (pkey1 == NULL)
		EXIT_ERR("EVP_PKEY_new_raw_private_key failed.");

	pkey2 = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub,
					    sizeof(pub));
	if (pkey2 == NULL)
		EXIT_ERR("EVP_PKEY_new_raw_private_key failed.");

	pctx = EVP_PKEY_CTX_new(pkey1, NULL);
	if (pctx == NULL)
		EXIT_ERR("EVP_PKEY_CTX_new failed.");

	if (EVP_PKEY_derive_init(pctx) != 1)
		EXIT_ERR("EVP_PKEY_derive_init failed.");

	if (EVP_PKEY_derive_set_peer(pctx, pkey2) != 1)
		EXIT_ERR("EVP_PKEY_derive_set_peer failed.");

	if (EVP_PKEY_derive(pctx, NULL, &keylen) != 1)
		EXIT_ERR("EVP_PKEY_derive failed.");

	if (EVP_PKEY_derive(pctx, key1, &keylen) != 1)
		EXIT_ERR("EVP_PKEY_derive failed.");

	if (ica_x25519_derive(ctx1, key2, pub) != 0)
		EXIT_ERR("ica_x25519_derive failed.");

	if (keylen != 32)
		EXIT_ERR("x25519 wrong shared secret size.");

	if (memcmp(key1, key2, keylen) != 0)
		EXIT_ERR("x25519 shared secrets do not match.");
#endif
}

static void x448_pc(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	ICA_X448_CTX *ctx1 = NULL, *ctx2 = NULL;
	EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	unsigned char priv[56], pub[56], key1[56], key2[56];
	size_t keylen = 0;

	if (ica_x448_ctx_new(&ctx1))
		EXIT_ERR("ica_x448_ctx_new failed.");
	if (ica_x448_ctx_new(&ctx2))
		EXIT_ERR("ica_x448_ctx_new failed.");

	if (ica_x448_key_gen(ctx1))
		EXIT_ERR("ica_x448_key_gen failed.");
	if (ica_x448_key_gen(ctx2))
		EXIT_ERR("ica_x448_key_gen failed.");

	if (ica_x448_key_get(ctx1, priv, NULL))
		EXIT_ERR("ica_x448_key_get failed.");
	if (ica_x448_key_get(ctx2, NULL, pub))
		EXIT_ERR("ica_x448_key_get failed.");

	pkey1 = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL,
					     priv, sizeof(priv));
	if (pkey1 == NULL)
		EXIT_ERR("EVP_PKEY_new_raw_private_key failed.");

	pkey2 = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, pub,
					    sizeof(pub));
	if (pkey2 == NULL)
		EXIT_ERR("EVP_PKEY_new_raw_private_key failed.");

	pctx = EVP_PKEY_CTX_new(pkey1, NULL);
	if (pctx == NULL)
		EXIT_ERR("EVP_PKEY_CTX_new failed.");

	if (EVP_PKEY_derive_init(pctx) != 1)
		EXIT_ERR("EVP_PKEY_derive_init failed.");

	if (EVP_PKEY_derive_set_peer(pctx, pkey2) != 1)
		EXIT_ERR("EVP_PKEY_derive_set_peer failed.");

	if (EVP_PKEY_derive(pctx, NULL, &keylen) != 1)
		EXIT_ERR("EVP_PKEY_derive failed.");

	if (EVP_PKEY_derive(pctx, key1, &keylen) != 1)
		EXIT_ERR("EVP_PKEY_derive failed.");

	if (ica_x448_derive(ctx1, key2, pub) != 0)
		EXIT_ERR("ica_x448_derive failed.");

	if (keylen != 56)
		EXIT_ERR("x448 wrong shared secret size.");

	if (memcmp(key1, key2, keylen) != 0)
		EXIT_ERR("x448 shared secrets do not match.");
#endif
}
