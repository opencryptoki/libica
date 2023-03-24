/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2023 */

/* This is a special RSA test:
 * The idea is to check that leading zeros on the input message
 * or encrypted message or decrypted message are processed correctly.
 * This is more a proof for the kernel and crypto firmware and
 * hardware stack. Please have in mind, that the kernel has two
 * pathes to resolve RSA requests via ICA interface: CCA and Accelerator
 */

#include <fcntl.h>
#include <memory.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "ica_api.h"
#include <sys/time.h>
#include "rsa_test.h"
#include "testcase.h"

extern int errno;

static int handle_ica_error(int rc, char *message)
{
	V_(printf("Error in %s: ", message));
	switch (rc) {
		case 0:
		  V_(printf("OK\n"));
		  break;
		case EINVAL:
		  V_(printf("Incorrect parameter.\n"));
		  break;
		case EPERM:
		  V_(printf("Operation not permitted by Hardware.\n"));
		  break;
		case EIO:
		  V_(printf("I/O error.\n"));
		  break;
		default:
		  V_(perror(""));
	}
	return TEST_FAIL;
}

int main(int argc, char **argv)
{
	ica_adapter_handle_t adapter_handle;
	unsigned char in_data[RESULT_LENGTH];
	unsigned char enc_data[RESULT_LENGTH];
	unsigned char dec_data[RESULT_LENGTH];
	int i, j, rc;

	UNUSED(ciphertext);
	UNUSED(input_data);

	srandom(time(NULL));

	set_verbosity(argc, argv);

	rc = ica_open_adapter(&adapter_handle);
	if (rc != 0) {
		V_(printf("ica_open_adapter failed and returned %d (0x%x).\n", rc, rc));
	}

	/* Iterate over key sizes (1024, 2048 and 4096) */
	for (i = 0; i < 6; i++) {

		int ms = RSA_BYTE_LENGHT[i]; // modulus size in bytes

		V_(printf("\nmodulus size = %d bytes (%d bits)\n", ms, 8 * ms));

#ifdef ICA_FIPS
		if ((ica_fips_status() & ICA_FIPS_MODE) && RSA_BYTE_LENGHT[i] < 256) {
			V_(printf("Skipping test for this modulus size: not FIPS 140-3 approved\n"));
			continue;
		}
#endif

		/*
		 * Test 1, encrypt with ME, decrypt with CRT
		 * decrypted text with lots of leading zeros
		 */

		memset(in_data, 0, sizeof(in_data));
		for (j = ms/2; j < ms; in_data[j++] = random() % 256);

		ica_rsa_key_mod_expo_t mod_expo_key = {RSA_BYTE_LENGHT[i], n[i], e[i]};
		ica_rsa_key_crt_t crt_key = {RSA_BYTE_LENGHT[i], p[i], q[i], dp[i], dq[i], qinv[i]};

		VV_(printf("Plain text: \n"));
		dump_array(in_data, ms);

		/* encrypt with ME */
		rc = ica_rsa_mod_expo(adapter_handle, in_data, &mod_expo_key, enc_data);
		if (rc)
#ifndef NO_SW_FALLBACKS
			exit(handle_ica_error(rc, "ica_rsa_key_mod_expo I"));
#else
			rc == ENODEV ? exit(TEST_SKIP) : exit(handle_ica_error(rc, "ica_rsa_key_mod_expo I"));
#endif

		VV_(printf("Encrypted text: \n"));
		dump_array(enc_data, ms);

		/* decrypt with CRT */
		rc = ica_rsa_crt(adapter_handle, enc_data, &crt_key, dec_data);
		if (rc)
#ifndef NO_SW_FALLBACKS
			exit(handle_ica_error(rc, "ica_rsa_crt I"));
#else
			rc == ENODEV ? exit(TEST_SKIP) : exit(handle_ica_error(rc, "ica_rsa_crt I"));
#endif

		VV_(printf("Decrypted text: \n"));
		dump_array(dec_data, ms);

		// compare
		if (memcmp(in_data, dec_data, ms)){
			printf("Decrypted text mismatch\n");
			return TEST_FAIL;
		}

		/*
		 * Test 2, encrypt with CRT, decrypt with ME
		 * decrypted text with lots of leading zeros
		 */

		VV_(printf("Plain text: \n"));
		dump_array(in_data, ms);

		/* encrypt with CRT */
		rc = ica_rsa_crt(adapter_handle, in_data, &crt_key, enc_data);
		if (rc)
#ifndef NO_SW_FALLBACKS
			exit(handle_ica_error(rc, "ica_rsa_crt II"));
#else
			rc == ENODEV ? exit(TEST_SKIP) : exit(handle_ica_error(rc, "ica_rsa_crt II"));
#endif

		VV_(printf("Encrypted text: \n"));
		dump_array(enc_data, ms);

		/* decrypt with ME */
		rc = ica_rsa_mod_expo(adapter_handle, enc_data, &mod_expo_key, dec_data);
		if (rc)
#ifndef NO_SW_FALLBACKS
			exit(handle_ica_error(rc, "ica_rsa_mod_expo II"));
#else
			rc == ENODEV ? exit(TEST_SKIP) : exit(handle_ica_error(rc, "ica_rsa_mod_expo II"));
#endif

		VV_(printf("Decrypted text: \n"));
		dump_array(dec_data, ms);

		// compare
		if (memcmp(in_data, dec_data, ms)){
			printf("Decrypted text mismatch\n");
			return TEST_FAIL;
		}
	}

	rc = ica_close_adapter(adapter_handle);
	if (rc != 0) {
		printf("ica_close_adapter failed and returned %d (0x%x).\n", rc, rc);
		return TEST_FAIL;
	}

	printf("All RSA-x tests passed\n");
	return TEST_SUCC;
}
