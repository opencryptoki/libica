/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2001, 2015 */

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

static int handle_ica_error(int rc, const char *message)
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
		case ENODEV:
		  V_(printf("No such device or SW fallback disabled (ENODEV).\n"));
		  break;
		default:
		  V_(printf("%s (rc=%d)\n", strerror(rc), rc));
	}
	return TEST_FAIL;
}

static void check_rc(int rc, const char *message)
{
	if (!rc)
		return;
#ifndef NO_SW_FALLBACKS
	exit(handle_ica_error(rc, message));
#else
	rc == ENODEV ? exit(TEST_SKIP) : exit(handle_ica_error(rc, message));
#endif
}

int main(int argc, char **argv)
{
	ica_adapter_handle_t adapter_handle;
	unsigned char my_result[RESULT_LENGTH];
	unsigned char my_result2[RESULT_LENGTH];
	int i, rc, path_idx;
	struct timeval start,end;
#ifndef NO_SW_FALLBACKS
	int num_paths = 2;
#else
	int num_paths = 1;
#endif

	set_verbosity(argc, argv);
	ica_set_fallback_mode(ICA_FALLBACKS_ENABLED);

	rc = ica_open_adapter(&adapter_handle);
	if (rc != 0) {
		V_(printf("ica_open_adapter failed and returned %d (0x%x).\n", rc, rc));
	}

	for (path_idx = 0; path_idx < num_paths; path_idx++) {
		ica_adapter_handle_t handle = (path_idx == 0) ? adapter_handle : DRIVER_NOT_LOADED;

		if (path_idx == 0) {
			V_(printf("--- Running RSA tests with default adapter handle ---\n"));
		} else {
			V_(printf("--- Running RSA tests with DRIVER_NOT_LOADED (forced SW fallback) ---\n"));
		}

		/* Iterate over key sizes (1024, 2048 and 4096) */
		for (i = 0; i < 6; i++) {
			/* encrypt with public key (ME) */
			V_(printf("\nmodulus size = %d\n", RSA_BYTE_LENGHT[i]));

			memset(my_result, 0, sizeof(my_result));
			memset(my_result2, 0, sizeof(my_result2));

#ifdef ICA_FIPS
			if ((ica_fips_status() & ICA_FIPS_MODE) && RSA_BYTE_LENGHT[i] < 384) {
				V_(printf("Skipping test for this modulus size: not FIPS 140-3 approved\n"));
				continue;
			}
#endif

			ica_rsa_key_mod_expo_t mod_expo_key = {RSA_BYTE_LENGHT[i],
							       n[i], e[i]};

			rc = ica_rsa_mod_expo(handle, input_data,
					      &mod_expo_key, my_result);
			check_rc(rc, "ica_rsa_key_mod_expo");

			VV_(printf("result of encrypt with public key\n"));
			dump_array(my_result, RSA_BYTE_LENGHT[i]);
			VV_(printf("Ciphertext \n"));
			dump_array(ciphertext[i], RSA_BYTE_LENGHT[i]);
			if (memcmp(my_result, ciphertext[i], RSA_BYTE_LENGHT[i])){
				printf("Ciphertext mismatch\n");
				return TEST_FAIL;
			}

			/* decrypt with private key (CRT) */
			ica_rsa_key_crt_t crt_key
			    = {RSA_BYTE_LENGHT[i], p[i], q[i], dp[i], dq[i], qinv[i]};

			gettimeofday(&start, NULL);
			rc = ica_rsa_crt(handle, ciphertext[i], &crt_key, my_result2);
			check_rc(rc, "ica_rsa_crt");
			gettimeofday(&end, NULL);

			V_(printf("RSA decrypt with key[%d] (l=%d) took %06lu µs.\n", i,
			    RSA_BYTE_LENGHT[i], (end.tv_sec * 1000000 + end.tv_usec)
			    - (start.tv_sec*1000000+start.tv_usec)));

			VV_(printf("Result of decrypt\n"));
			dump_array((unsigned char *)my_result2, RSA_BYTE_LENGHT[i]);
			VV_(printf("original data\n"));
			dump_array(input_data, RSA_BYTE_LENGHT[i]);
			if (memcmp(input_data, my_result2, RSA_BYTE_LENGHT[i]) != 0) {
				printf("Results do not match.  Failure!\n");
				return TEST_FAIL;
			}

			/*
			 * Test blinded CRT across multiple iterations to ensure
			 * random exponent blinding factors produce consistent results.
			 */
			int iter;
			for (iter = 0; iter < 10; iter++) {
				memset(my_result2, 0, sizeof(my_result2));
				rc = ica_rsa_crt(handle, ciphertext[i], &crt_key, my_result2);
				check_rc(rc, "ica_rsa_crt (blinded iter)");
				if (memcmp(input_data, my_result2, RSA_BYTE_LENGHT[i]) != 0) {
					printf("Blinded CRT decryption mismatch on iteration %d!\n", iter);
					return TEST_FAIL;
				}
			}

			/*
			 * Test zero input/result: encrypt 0 and decrypt 0 with CRT.
			 * Verifies m1 == m2 == 0 in mod_sub_sw and BN_bn2binpad zero padding.
			 */
			unsigned char zero_buf[RESULT_LENGTH];
			unsigned char zero_enc[RESULT_LENGTH];
			unsigned char zero_dec[RESULT_LENGTH];

			memset(zero_buf, 0, sizeof(zero_buf));
			memset(zero_enc, 0, sizeof(zero_enc));
			memset(zero_dec, 0, sizeof(zero_dec));

			rc = ica_rsa_mod_expo(handle, zero_buf, &mod_expo_key, zero_enc);
			check_rc(rc, "ica_rsa_mod_expo (zero)");
			rc = ica_rsa_crt(handle, zero_enc, &crt_key, zero_dec);
			check_rc(rc, "ica_rsa_crt (zero)");
			if (memcmp(zero_buf, zero_dec, RSA_BYTE_LENGHT[i]) != 0) {
				printf("Zero CRT decryption mismatch!\n");
				return TEST_FAIL;
			}

			/*
			 * Test mod_sub_sw cases: m1 == m2, m1 < m2, and m1 > m2:
			 * - m = 1: m mod p = 1, m mod q = 1  => m1 == m2 == 1
			 * - m = p: m mod p = 0, m mod q = p mod q > 0 => m1 < m2 (borrow case)
			 * - m = q: m mod p = q mod p > 0, m mod q = 0 => m1 > m2 (no borrow case)
			 */
			int ms = RSA_BYTE_LENGHT[i];
			int half = ms / 2;
			unsigned char test_m[RESULT_LENGTH];
			unsigned char test_enc[RESULT_LENGTH];
			unsigned char test_dec[RESULT_LENGTH];

			/* Case 1: m1 == m2 (m = 1) */
			memset(test_m, 0, ms);
			test_m[ms - 1] = 0x01;
			rc = ica_rsa_mod_expo(handle, test_m, &mod_expo_key, test_enc);
			check_rc(rc, "ica_rsa_mod_expo (mod_sub m1==m2)");
			rc = ica_rsa_crt(handle, test_enc, &crt_key, test_dec);
			check_rc(rc, "ica_rsa_crt (mod_sub m1==m2)");
			if (memcmp(test_m, test_dec, ms) != 0) {
				printf("mod_sub_sw m1 == m2 test failed!\n");
				return TEST_FAIL;
			}

			/* Case 2: m1 < m2 (m = p) */
			memset(test_m, 0, ms);
			memcpy(test_m + half, p[i] + 8, half);
			rc = ica_rsa_mod_expo(handle, test_m, &mod_expo_key, test_enc);
			check_rc(rc, "ica_rsa_mod_expo (mod_sub m1<m2)");
			rc = ica_rsa_crt(handle, test_enc, &crt_key, test_dec);
			check_rc(rc, "ica_rsa_crt (mod_sub m1<m2)");
			if (memcmp(test_m, test_dec, ms) != 0) {
				printf("mod_sub_sw m1 < m2 (borrow) test failed!\n");
				return TEST_FAIL;
			}

			/* Case 3: m1 > m2 (m = q) */
			memset(test_m, 0, ms);
			memcpy(test_m + half, q[i], half);
			rc = ica_rsa_mod_expo(handle, test_m, &mod_expo_key, test_enc);
			check_rc(rc, "ica_rsa_mod_expo (mod_sub m1>m2)");
			rc = ica_rsa_crt(handle, test_enc, &crt_key, test_dec);
			check_rc(rc, "ica_rsa_crt (mod_sub m1>m2)");
			if (memcmp(test_m, test_dec, ms) != 0) {
				printf("mod_sub_sw m1 > m2 test failed!\n");
				return TEST_FAIL;
			}
		}
	}

	rc = ica_close_adapter(adapter_handle);
	if (rc != 0) {
		printf("ica_close_adapter failed and returned %d (0x%x).\n", rc, rc);
		return TEST_FAIL;
	}

	printf("All RSA tests passed.\n");
	return TEST_SUCC;
}

