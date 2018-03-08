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
	unsigned char my_result[RESULT_LENGTH];
	unsigned char my_result2[RESULT_LENGTH];
	int i, rc;
	struct timeval start,end;

	set_verbosity(argc, argv);

	rc = ica_open_adapter(&adapter_handle);
	if (rc != 0) {
		V_(printf("ica_open_adapter failed and returned %d (0x%x).\n", rc, rc));
	}

	/* Iterate over key sizes (1024, 2048 and 4096) */
	for (i = 0; i < 6; i++) {
		/* encrypt with public key (ME) */
		V_(printf("\nmodulus size = %d\n", RSA_BYTE_LENGHT[i]));

		memset(my_result, 0, sizeof(my_result));
		memset(my_result2, 0, sizeof(my_result2));

		ica_rsa_key_mod_expo_t mod_expo_key = {RSA_BYTE_LENGHT[i],
						       n[i], e[i]};

		rc = ica_rsa_mod_expo(adapter_handle, input_data,
				      &mod_expo_key, my_result);
		if (rc)
			exit(handle_ica_error(rc, "ica_rsa_key_mod_expo"));

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
		rc = ica_rsa_crt(adapter_handle, ciphertext[i], &crt_key, my_result2);
		if(rc)
			exit(handle_ica_error(rc, "ica_rsa_crt"));
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

	}

	rc = ica_close_adapter(adapter_handle);
	if (rc != 0) {
		printf("ica_close_adapter failed and returned %d (0x%x).\n", rc, rc);
		return TEST_FAIL;
	}

	printf("All RSA tests passed.\n");
	return TEST_SUCC;
}

