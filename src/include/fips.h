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
#ifndef FIPS_H
#define FIPS_H

#include "ica_api.h"

#define FIPS_FLAG "/proc/sys/crypto/fips_enabled"

extern int fips;			/* module status */

int openssl_in_fips_mode(void);

/*
 * Initialize global fips var to 1 resp. 0 when FIPS_FLAG is 1 resp. 0 (or not
 * present).
 */
void fips_init(void);

/*
 * Powerup tests: crypto algorithm test, SW/FW integrity test, critical
 * function test (no critical functions). The tests set the
 * corresponding status flags.
 */
void fips_powerup_tests(void);

/*
 * Create deterministic ECDSA signatures in self-tests.
 */
int ica_ecdsa_sign_ex_internal(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey, const unsigned char *hash, unsigned int hash_length,
		unsigned char *signature, unsigned int signature_length,
		const unsigned char *k);

/*
 * List of non-fips-approved algorithms
 */
static const int FIPS_BLACKLIST[] = {DES_ECB, DES_CBC, DES_CBC_CS, DES_OFB,
    DES_CFB, DES_CTR, DES_CTRLST, DES_CBC_MAC, DES_CMAC, P_RNG, DES3_ECB,
    DES3_CBC, DES3_CBC_CS, DES3_OFB, DES3_CFB, DES3_CTR, DES3_CTRLST,
    DES3_CBC_MAC, DES3_CMAC, ED25519_KEYGEN, ED25519_SIGN, ED25519_VERIFY,
    ED448_KEYGEN, ED448_SIGN, ED448_VERIFY, X25519_KEYGEN, X25519_DERIVE,
    X448_KEYGEN, X448_DERIVE, RSA_ME, RSA_CRT, SHA512_DRNG };
static const size_t FIPS_BLACKLIST_LEN
	= sizeof(FIPS_BLACKLIST) / sizeof(FIPS_BLACKLIST[0]);

/*
 * FIPS service indicator: List of tolerated but non-approved algorithms.
 */
static const int FIPS_OVERRIDE_LIST[] = { RSA_ME, RSA_CRT, SHA512_DRNG };
static const size_t FIPS_OVERRIDE_LIST_LEN
	= sizeof(FIPS_OVERRIDE_LIST) / sizeof(FIPS_OVERRIDE_LIST[0]);

/*
 * Returns 1 if the algorithm identified by @id is FIPS approved.
 * Returns 0 otherwise.
 */
static inline int
fips_approved(int id)
{
        size_t i;

        for (i = 0; i < FIPS_BLACKLIST_LEN; i++) {
                if (id == FIPS_BLACKLIST[i])
                        return 0;
        }

        return 1;
}

/*
 * Returns 1 if the algorithm identified by @id is FIPS tolerated, i.e. it is
 * available via the API in fips mode, but considered non-approved.
 * Returns 0 otherwise.
 */
static inline int fips_override(int id)
{
	size_t i;

	for (i = 0; i < FIPS_OVERRIDE_LIST_LEN; i++) {
		if (id == FIPS_OVERRIDE_LIST[i])
			return 1;
	}

	return 0;
}
#endif /* FIPS_H */
#endif /* ICA_FIPS */
