#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "ica_api.h"
#include "testcase.h"
#include <openssl/obj_mac.h>


#define MAX_ECC_PRIV_SIZE		66 /* 521 bits */
#define MAX_ECDSA_SIG_SIZE		2*MAX_ECC_PRIV_SIZE
#define NUM_ECKEYGEN_TESTS		(sizeof(eckeygen_tests)/sizeof(eckeygen_test_t))
#define NUM_HASH_LENGTHS		(sizeof(hash_length)/sizeof(int))

typedef struct {
    unsigned int nid;
    char nid_str[32];
} eckeygen_test_t;

static eckeygen_test_t eckeygen_tests[] = {
	{NID_X9_62_prime192v1, "NID_X9_62_prime192v1"},
	{NID_secp224r1, "NID_secp224r1"},
	{NID_X9_62_prime256v1, "NID_X9_62_prime256v1"},
	{NID_secp384r1, "NID_secp384r1"},
	{NID_secp521r1, "NID_secp521r1"},
	{NID_brainpoolP160r1, "NID_brainpoolP160r1"},
	{NID_brainpoolP192r1, "NID_brainpoolP192r1"},
	{NID_brainpoolP224r1, "NID_brainpoolP224r1"},
	{NID_brainpoolP256r1, "NID_brainpoolP256r1"},
	{NID_brainpoolP320r1, "NID_brainpoolP320r1"},
	{NID_brainpoolP384r1, "NID_brainpoolP384r1"},
	{NID_brainpoolP512r1, "NID_brainpoolP512r1"},
};

static unsigned char hash[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static unsigned int hash_length[] = {
	20, 28, 32, 48, 64,
};


int main(int argc, char **argv)
{
	ica_adapter_handle_t adapter_handle;
	unsigned int i, j, rc;
	unsigned int errors=0;
	unsigned char signature[MAX_ECDSA_SIG_SIZE];
	unsigned char pub_X[MAX_ECC_PRIV_SIZE];
	unsigned char pub_Y[MAX_ECC_PRIV_SIZE];
	unsigned char priv_D[MAX_ECC_PRIV_SIZE];
	unsigned int privlen = 0;
	ICA_EC_KEY *eckey;

	set_verbosity(argc, argv);

	rc = ica_open_adapter(&adapter_handle);
	if (rc != 0) {
		V_(printf("ica_open_adapter failed and returned %d (0x%x).\n", rc, rc));
		return 8;
	}

	/* Iterate over curves */
	for (i = 0; i < NUM_ECKEYGEN_TESTS; i++) {

		memset(pub_X, 0, sizeof(pub_X));
		memset(pub_Y, 0, sizeof(pub_Y));
		memset(priv_D, 0, sizeof(priv_D));

		V_(printf("Generating EC key for curve %d (%s) \n", eckeygen_tests[i].nid, eckeygen_tests[i].nid_str));

		/* generate EC key with given curve */
		eckey = ica_ec_key_new(eckeygen_tests[i].nid, &privlen);
		rc = ica_ec_key_generate(adapter_handle, eckey);
		if (rc) {
			V_(printf("EC key for curve %i could not be generated, rc=%i.\n", eckeygen_tests[i].nid, rc));
			errors++;
		} else {

			for (j = 0; j<NUM_HASH_LENGTHS; j++) {

				/* calculate ECDSA signature with this key */
				rc = ica_ecdsa_sign(adapter_handle, eckey, hash, hash_length[j],
						    signature, MAX_ECDSA_SIG_SIZE);

				if (rc) {
					V_(printf("Signature could not be created, key not usable, rc=%i.\n",rc));
					errors++;
				} else {

					/* verify ECDSA signature with this key */
					rc = ica_ecdsa_verify(adapter_handle, eckey, hash, hash_length[j],
							      signature, MAX_ECDSA_SIG_SIZE);

					if (rc) {
						V_(printf("Signature could not be verified, key not usable, rc=%i.\n",rc));
						errors++;
					}
				}
			}
		}

		ica_ec_key_free(eckey);
	}

	ica_close_adapter(adapter_handle);

	if (errors)
		printf("%i of %li EC keygen tests failed.\n", errors, NUM_ECKEYGEN_TESTS);
	else
		printf("All EC keygen tests passed.\n");

	return 0;
}
