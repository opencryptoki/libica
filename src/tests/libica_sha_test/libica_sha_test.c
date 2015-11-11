/*
 * usage: libica_sha_test filelist
 * test for old and new libica api for sha1/224/256/384/512
 * test vectors are read from .rsp files and put in the queue
 * the included .rsp files are obtained from nist:
 * http://csrc.nist.gov/groups/STM/cavp/index.html#03
 */

#include <stdlib.h>
#include <string.h>
#include "ica_api.h"
#include "sha_tests.h"
#include "read_rsp.h"
#include "queue_t.h"
#include "critical_error.h"

queue_t queue;

int main(int argc, char *argv[])
{
	test_t *curr_test;
	FILE *test_data;
	int i, rc, first = 1;

	queue = new_queue_t();

	if (argc < 2) {
		printf("error: no input files.\n");
	}

	if (argv[1]) {
		if (strstr(argv[1], "silent")) {
			silent = 1; first = 2;
		}
	}
	/* read test vectors from .rsp file(s) and put on queue */
	for (i = first; i < argc; i++) {
		if ((test_data = fopen(argv[i], "r")) != NULL) {
			//printf("reading test data from %s ... ", argv[i]);
			if (read_test_data(test_data) == EXIT_SUCCESS)
			//	printf("done.\n");
			if ((fclose(test_data)) == EOF)
				printf("error: couldn't close file %s.\n",
				       argv[i]);
		} else
			printf("error: couldn't open file %s.\n", argv[i]);
	}

	if (!silent) {
		printf("%u test vectors found.\n", queue.size);
	}
	if (queue.size > 0)
		if (!silent) {
			printf("starting tests ...\n\n");
		}
	/* run each test in queue with new and old api */
	for (curr_test = queue.head, i = 1; curr_test != NULL;
	     curr_test = curr_test->next, i++) {
		if (!silent)
			printf("test #%d : %u byte input message, ", i,
		       curr_test->msg_length);
		switch (curr_test->type) {
		case SHA1:
			if (!silent)
				printf("SHA1 ...\n");
			rc = sha1_new_api_test(curr_test);
			break;
		case SHA224:
			if (!silent)
				printf("SHA224 ...\n");
			rc = sha224_new_api_test(curr_test);
			break;
		case SHA256:
			if (!silent)
				printf("SHA256 ...\n");
			rc = sha256_new_api_test(curr_test);
			break;
		case SHA384:
			if (!silent)
				printf("SHA384 ...\n");
			rc = sha384_new_api_test(curr_test);
			break;
		case SHA512:
			if (!silent)
				printf("SHA512 ...\n");
			rc = sha512_new_api_test(curr_test);
			break;
		default:
			CRITICAL_ERROR("Unknown algorithm.\n");
			rc = -1;
			break;
		}
		if (!rc) {
			if (!silent)
				printf("... Passed.\n");
			queue.passed++;
		}
		else {
			printf("error: (%x).\n", rc);
			queue.failed++;
		}

	}
	if (!silent) {
		printf("[SHA test case results: tests: %u,  passed: %u, failed: %u]\n",
			queue.passed + queue.failed, queue.passed, queue.failed);
	}
	else {
		if (queue.failed == 0)
			printf("All SHA testcases finished successfully\n");
		else
			printf("SHA testcases failed\n");
	}
	return EXIT_SUCCESS;
}
