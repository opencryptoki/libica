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
void fips_get_indicator(void);
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
 * Use ica_aes_gcm_internal for fips self-test KATs. External iv are
 * allowed here.
 */
unsigned int ica_aes_gcm_internal(unsigned char *plaintext,
			unsigned long plaintext_length, unsigned char *ciphertext,
			const unsigned char *iv, unsigned int iv_length,
			const unsigned char *aad, unsigned long aad_length,
			unsigned char *tag, unsigned int tag_length,
			unsigned char *key, unsigned int key_length,
			unsigned int direction);

/*
 * Use ica_aes_gcm_initialize_internal for fips self-test KATs. External iv are
 * allowed here.
 */
unsigned int ica_aes_gcm_initialize_internal(const unsigned char *iv,
				unsigned int iv_length, unsigned char *key,
				unsigned int key_length, unsigned char *icb,
				unsigned char *ucb, unsigned char *subkey,
				unsigned int direction);

/*
 * Routines that work on the fips algo lists.
 */
int fips_approved(int id);
int fips_override(int id);
#endif /* FIPS_H */
#endif /* ICA_FIPS */
