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

int main(int argc, char **argv)
{
	int i, rc;
	struct timeval start,end;

	(void)e;	/* suppress unused var warning */
	(void)n;
	(void)input_data;
	(void)ciphertext;

	set_verbosity(argc, argv);

	/* Iterate over keys (1024, 2048 and 4096 bit length */
	/* privileged keys */
	for (i = 0; i < 3; i++) {
		V_(printf("modulus size = %d\n", RSA_BYTE_LENGHT[i]));

		ica_rsa_key_crt_t crt_key = {RSA_BYTE_LENGHT[i], p[i], q[i], dp[i],
									 dq[i], qinv[i]};

		gettimeofday(&start, NULL);
		rc = ica_rsa_crt_key_check(&crt_key);
		if(rc){
			V_(printf("ica_rsa_crt_key_check failed!\n"));
		}

		gettimeofday(&end, NULL);
		V_(printf("RSA CRT Key check: key[%d], l=%d (keyset I): %06lu µs.\n",
		    i, RSA_BYTE_LENGHT[i], (end.tv_sec * 1000000 + end.tv_usec)
		    - (start.tv_sec * 1000000 + start.tv_usec)));
	}

	/* unprivileged keys */
	for (i = 3; i < 6; i++) {
		V_(printf("modulus size = %d\n", RSA_BYTE_LENGHT[i]));

		ica_rsa_key_crt_t crt_key = {RSA_BYTE_LENGHT[i], p[i], q[i], dp[i],
									 dq[i], qinv[i]};

		gettimeofday(&start, NULL);
		rc = ica_rsa_crt_key_check(&crt_key);
		if(!rc){
			V_(printf("ica_rsa_crt_key_check failed!\n"));
		}

		gettimeofday(&end, NULL);
		V_(printf("RSA CRT key check: key[%d], l=%d (keyset II): %06lu µs.\n",
		    i, RSA_BYTE_LENGHT[i], (end.tv_sec * 1000000 + end.tv_usec)
		    - (start.tv_sec * 1000000 + start.tv_usec)));

		V_(printf("Result of recalculated key part (qInv)\n"));
		dump_array((unsigned char *)crt_key.qInverse, RSA_BYTE_LENGHT[i]/2);
		V_(printf("Result of expected key part (qInv)\n"));
		dump_array((unsigned char *)qinv[i-3], RSA_BYTE_LENGHT[i]/2);
		if( memcmp(crt_key.qInverse, qinv[i-3], RSA_BYTE_LENGHT[i]/2) != 0) {
			V_(printf("Calculated 'qInv' do not match. Failure!\n"));
			return TEST_FAIL;
		}
		if( memcmp(crt_key.p, p[i-3], RSA_BYTE_LENGHT[i]/2 + 8) != 0) {
			V_(printf("Prime 'p' do not match. Failure!\n"));
			return TEST_FAIL;
		}
		if( memcmp(crt_key.q, q[i-3], RSA_BYTE_LENGHT[i]/2) != 0) {
			V_(printf("Prime 'q' do not match. Failure!\n"));
			return TEST_FAIL;
		}
		if( memcmp(crt_key.dp, dp[i-3], RSA_BYTE_LENGHT[i]/2 + 8) != 0) {
			V_(printf("Parameter 'dp' do not match. Failure!\n"));
			return TEST_FAIL;
		}
		if( memcmp(crt_key.dq, dq[i-3], RSA_BYTE_LENGHT[i]/2) != 0) {
			V_(printf("Parameter 'dq' do not match. Failure!\n"));
			return TEST_FAIL;
		}

	}

	printf("All RSA key check tests passed.\n");
	return TEST_SUCC;
}
