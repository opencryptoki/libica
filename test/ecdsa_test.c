/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2017 */

#include <stdio.h>
#include <stdlib.h>
#include "ica_api.h"
#include "testcase.h"
#include "ecdsa_test.h"


#define NUM_TOGGLE                   2
#define MAX_ECDSA_SIG_SIZE         132


static inline int curve_supported_via_cpacf(unsigned int nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
	case NID_secp384r1:
	case NID_secp521r1:
		return 1;
	default:
		return 0;
	}
}

static int is_msa9(void)
{
	unsigned int mech_len, j;
	libica_func_list_element *pmech_list = NULL;

	if (ica_get_functionlist(NULL, &mech_len) != 0) {
		perror("get_functionlist: ");
		return 0;
	}

	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (!pmech_list) {
		perror("is_msa9: error malloc");
		return 0;
	}

	if (ica_get_functionlist(pmech_list, &mech_len) != 0) {
		perror("get_functionlist: ");
		free(pmech_list);
		return 0;
	}

	for (j = 0; j < mech_len; j++) {
		if (pmech_list[j].mech_mode_id == EC_DSA_SIGN) {
			if (pmech_list[j].flags & ICA_FLAG_SHW) {
				free(pmech_list);
				return 1;
			}
		}
	}

	free(pmech_list);
	return 0;
}

/*
 * Performs "partial" known-answer tests without given k-value. So we test if
 * the key material can be used for non-deterministic sign, and if the created
 * signature can be verified. Deterministic sign with given k-value is not
 * supported on CCA cards.
 */
static int test_sign(ica_adapter_handle_t adapter_handle, const ICA_EC_KEY *eckey,
				unsigned int nid, const unsigned char *hash, unsigned int hash_len,
				const unsigned char *known_signature, unsigned int sig_len)
{
	unsigned char signature[MAX_ECDSA_SIG_SIZE];
	int rc;

	if (can_toggle(nid))
		toggle_env_icapath();

	/* calculate ECDSA signature */
	VV_(printf("  performing sign with ICAPATH=%d \n", getenv_icapath()));
	rc = ica_ecdsa_sign(adapter_handle, eckey, hash, hash_len,
					signature, MAX_ECDSA_SIG_SIZE);
	if (rc) {
		V_(printf("Signature could not be created, rc=%i.\n",rc));
		return 1;
	}

	if (can_toggle(nid))
		toggle_env_icapath();

	/* verify created ECDSA signature */
	VV_(printf("  performing verify with ICAPATH=%d \n", getenv_icapath()));
	rc = ica_ecdsa_verify(adapter_handle, eckey, hash, hash_len,
					signature, sig_len);
	if (rc) {
		V_(printf("Signature could not be verified, rc=%i.\n",rc));
		return 1;
	}

	/* verify again with known signature */
	VV_(printf("  verify again with known signature\n"));
	rc = ica_ecdsa_verify(adapter_handle, eckey, hash, hash_len,
					known_signature, sig_len);
	if (rc) {
		V_(printf("Signature could not be verified, rc=%i.\n",rc));
		return 1;
	}

	return 0;
}

/*
 * Performs known-answer tests with given k-value. This is only supported via
 * CPACF, not via CCA cards. If ica_ecdsa_sign_ex returns EPERM, the curve
 * is not supported via CPACF.
 */
static int test_sign_ex(ica_adapter_handle_t adapter_handle, const ICA_EC_KEY *eckey,
				unsigned int nid, const unsigned char *hash, unsigned int hash_len,
				const unsigned char *k, const unsigned char *known_signature,
				unsigned int sig_len)
{
	unsigned char signature[MAX_ECDSA_SIG_SIZE];
	int rc;

	if (ica_fips_status() & ICA_FIPS_MODE) {
		/* ica_ecdsa_sign_ex with k != NULL not allowed in fips mode */
		return 0;
	}

	if (can_toggle(nid))
		toggle_env_icapath();

	/* calculate ECDSA signature */
	VV_(printf("  performing sign_ex with ICAPATH=%d \n", getenv_icapath()));
	rc = ica_ecdsa_sign_ex(adapter_handle, eckey, hash, hash_len,
					signature, MAX_ECDSA_SIG_SIZE, k);
	if (rc != 0 && rc != EPERM) {
		V_(printf("Signature could not be created, rc=%i.\n",rc));
		return 1;
	}

	/* Compare created signature with known signature */
	if (memcmp(signature, known_signature, sig_len) != 0) {
		V_(printf("Signature does not match with known signature\n"));
		return 1;
	}

	if (can_toggle(nid))
		toggle_env_icapath();

	/* Verify ECDSA signature */
	VV_(printf("  performing verify with ICAPATH=%d \n", getenv_icapath()));
	rc = ica_ecdsa_verify(adapter_handle, eckey, hash, hash_len,
			signature, sig_len);
	if (rc) {
		V_(printf("Signature could not be verified, rc=%i.\n",rc));
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	ica_adapter_handle_t adapter_handle;
	const struct ecdsa_kat_tv *tv;
	unsigned int i, k, rc;
	unsigned int errors=0;
	unsigned char signature[MAX_ECDSA_SIG_SIZE];
	unsigned int privlen = 0;
	ICA_EC_KEY *eckey;
	char *icapath;
	unsigned int msa9 = is_msa9();

	set_verbosity(argc, argv);

	if (!ecc_available()) {
		printf("Skipping ECDSA test, because the required HW"
		       " is not available on this machine.\n");
		return TEST_SKIP;
	}

	rc = ica_open_adapter(&adapter_handle);
	if (rc != 0) {
		V_(printf("ica_open_adapter failed and returned %d (0x%x).\n", rc, rc));
	}

	/* set ICAPATH default value */
	icapath = getenv("ICAPATH");
	if ((icapath == NULL) || (atoi(icapath) == 0)) {
		icapath = "1";
		setenv("ICAPATH", icapath, 1);
	}

	/* Iterate over curves */
	for (i = 0; i < ECDSA_TV_LEN; i++) {

		tv = &ECDSA_TV[i];

		if (ica_fips_status() & ICA_FIPS_MODE) {
			if (!is_supported_by_hw(tv->nid)) {
				V_(printf("Skipping nid %d, because not allowed in fips mode"
					" on this system.\n", tv->nid));
				continue;
			}
		}

		setenv("ICAPATH", icapath, 1);

		V_(printf("Testing curve %d \n", tv->nid));

		memset(signature, 0, MAX_ECDSA_SIG_SIZE);

		eckey = ica_ec_key_new(tv->nid, &privlen);
		if (!eckey)
			continue;

		rc = ica_ec_key_init(tv->x, tv->y, tv->d, eckey);
		if (rc != 0) {
			ica_ec_key_free(eckey);
			eckey = NULL;
			if (rc == EPERM) {
				V_(printf("Curve %d not supported on this system, skipping ...\n", tv->nid));
				continue;
			} else {
				V_(printf("Failed to initialize key for nid %d, rc=%i.\n", tv->nid, rc));
				errors++;
				continue;
			}
		}

		/* Each test toggles between hw and sw path */
		for (k = 0; k < NUM_TOGGLE; k++) {
			rc = test_sign(adapter_handle, eckey, tv->nid, tv->hash,
					tv->hash_len, tv->sig, tv->sig_len);
			if (rc)
				errors++;

			if (msa9 && curve_supported_via_cpacf(tv->nid)) {
				rc = test_sign_ex(adapter_handle, eckey, tv->nid, tv->hash,
						tv->hash_len, tv->k, tv->sig, tv->sig_len);
				if (rc)
					errors++;
			}
		}

		ica_ec_key_free(eckey);
		eckey = NULL;
		unset_env_icapath();
	}

	ica_close_adapter(adapter_handle);

	if (errors) {
		printf("%i ECDSA tests failed.\n", errors);
		return TEST_FAIL;
	}

	printf("All ECDSA tests passed.\n");
	return TEST_SUCC;
}
