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

#include "libica_rsa_test.h"

extern int errno;

void dump_array(unsigned char *ptr, unsigned int size)
{
	unsigned char *ptr_end;
	unsigned char *h;
	int i = 1;

	h = ptr;
	ptr_end = ptr + size;
	while (h < (unsigned char *)ptr_end) {
		printf("0x%02x ",(unsigned char ) *h);
		h++;
		if (i == 8) {
			printf("\n");
			i = 1;
		} else {
			++i;
		}
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	int i, rc;
	unsigned int silent = 0;
	struct timeval start,end;

	if (argc > 1) {
		if (strstr(argv[1], "silent"))
			silent = 1;
	}

	/* Iterate over keys (1024, 2048 and 4096 bit length */
	/* privileged keys */
	for (i = 0; i < 3; i++) {
		if (!silent) {
			printf("modulus size = %d\n", RSA_BYTE_LENGHT[i]);
		}

		ica_rsa_key_crt_t crt_key = {RSA_BYTE_LENGHT[i], p[i], q[i], dp[i],
									 dq[i], qinv[i]};

		gettimeofday(&start, NULL);
		rc = ica_rsa_crt_key_check(&crt_key);
		if(rc)
			printf("ica_rsa_crt_key_check failed!\n");

		gettimeofday(&end, NULL);
		if (!silent)
			printf("RSA CRT Key check: key[%d], l=%d (keyset I): %06lu µs.\n",
					i, RSA_BYTE_LENGHT[i], (end.tv_sec*1000000+end.tv_usec)-
										(start.tv_sec*1000000+start.tv_usec));
	}

	/* unprivileged keys */
	for (i = 3; i < 6; i++) {
		if (!silent) {
			printf("modulus size = %d\n", RSA_BYTE_LENGHT[i]);
		}

		ica_rsa_key_crt_t crt_key = {RSA_BYTE_LENGHT[i], p[i], q[i], dp[i],
									 dq[i], qinv[i]};

		gettimeofday(&start, NULL);
		rc = ica_rsa_crt_key_check(&crt_key);
		if(!rc)
			printf("ica_rsa_crt_key_check failed!\n");

		gettimeofday(&end, NULL);
		if (!silent)
			printf("RSA CRT key check: key[%d], l=%d (keyset II): %06lu µs.\n",
					i, RSA_BYTE_LENGHT[i], (end.tv_sec*1000000+end.tv_usec)-
									   (start.tv_sec*1000000+start.tv_usec));

		if (!silent) {
			printf("Result of recalculated key part (qInv)\n");
			dump_array((unsigned char *)crt_key.qInverse, RSA_BYTE_LENGHT[i]/2);
			printf("Result of expected key part (qInv)\n");
			dump_array((unsigned char *)qinv[i-3], RSA_BYTE_LENGHT[i]/2);
		}
		if( memcmp(crt_key.qInverse, qinv[i-3], RSA_BYTE_LENGHT[i]/2) != 0) {
			printf("Calculated 'qInv' do not match.  Failure!\n");
			return -1;
		}
		if( memcmp(crt_key.p, p[i-3], RSA_BYTE_LENGHT[i]/2 + 8) != 0) {
			printf("Prime 'p' do not match.  Failure!\n");
			return -1;
		}
		if( memcmp(crt_key.q, q[i-3], RSA_BYTE_LENGHT[i]/2) != 0) {
			printf("Prime 'q' do not match.  Failure!\n");
			return -1;
		}
		if( memcmp(crt_key.dp, dp[i-3], RSA_BYTE_LENGHT[i]/2 + 8) != 0) {
			printf("Parameter 'dp' do not match.  Failure!\n");
			return -1;
		}
		if( memcmp(crt_key.dq, dq[i-3], RSA_BYTE_LENGHT[i]/2) != 0) {
			printf("Parameter 'dq' do not match.  Failure!\n");
			return -1;
		}

	} // end loop

	printf("All RSA KEY Check testcases finished successfully\n");
	return 0;
}
