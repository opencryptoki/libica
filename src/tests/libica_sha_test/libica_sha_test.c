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

static void test_sha(test_t * test, int (*sha_old_api) (test_t *),
		     int (*sha_new_api) (test_t *));

int main(int argc, char *argv[])
{
	test_t *curr_test;
	FILE *test_data;
	int i, first = 1;

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
			test_sha(curr_test, sha1_old_api_test,
				 sha1_new_api_test);
			break;
		case SHA224:
			if (!silent)
				printf("SHA224 ...\n");
			test_sha(curr_test, sha224_old_api_test,
				 sha224_new_api_test);
			break;
		case SHA256:
			if (!silent)
				printf("SHA256 ...\n");
			test_sha(curr_test, sha256_old_api_test,
				 sha256_new_api_test);
			break;
		case SHA384:
			if (!silent)
				printf("SHA384 ...\n");
			test_sha(curr_test, sha384_old_api_test,
				 sha384_new_api_test);
			break;
		case SHA512:
			if (!silent)
				printf("SHA512 ...\n");
			test_sha(curr_test, sha512_old_api_test,
				 sha512_new_api_test);
			break;
		default:
			CRITICAL_ERROR("Unknown algorithm.\n");
			break;
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

static void test_sha(test_t * test, int (*sha_old_api_test) (test_t *),
		     int (*sha_new_api_test) (test_t *))
{
	int rc_old_api_test = 0, rc_new_api_test = 0;

	if ((rc_old_api_test = (*sha_old_api_test) (test)) == 0) {
		if (!silent)
			printf("OK.\n");
	}
	else
		printf("error: (%d).\n", rc_old_api_test);

	if ((rc_new_api_test = (*sha_new_api_test) (test)) == 0) {
		if (!silent)
			printf("OK.\n");
	}
	else
		printf("error: (%d).\n", rc_new_api_test);

	if ((rc_old_api_test == 0) && (rc_new_api_test == 0)) {
		if (!silent)
			printf("... done. test passed.\n\n");
		queue.passed++;
	} else {
		printf("... done. test failed.\n\n");
		queue.failed++;
	}
}
