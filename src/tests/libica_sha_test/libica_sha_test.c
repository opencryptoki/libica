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
#include "../testcase.h"

queue_t queue;

int main(int argc, char *argv[])
{
	test_t *curr_test;
	FILE *test_data;
	int i, rc;

	/* first cmd line arg may be verbosity */
	if ((argc >= 2) && (argv[1][0] == '-')) {
		set_verbosity(2, argv);
		i = 2;
	}
	else
		i = 1;

	if (argc - i == 0) {
		printf("error: no input files.\n");
		return EXIT_FAILURE;
	}

	queue = new_queue_t();

	/* read test vectors from .rsp file(s) and put on queue */
	for (; i < argc; i++) {
		if ((test_data = fopen(argv[i], "r")) != NULL) {
			VV_(printf("reading test data from %s ... ", argv[i]));
			if (read_test_data(test_data) == EXIT_SUCCESS) {
				VV_(printf("done.\n"));
			}
			if ((fclose(test_data)) == EOF) {
				V_(printf("error: couldn't close file %s.\n",
				       argv[i]));
			}
		} else {
			V_(printf("error: couldn't open file %s.\n", argv[i]));
		}
	}

	VV_(printf("%u test vectors found.\n", queue.size));

	if (queue.size > 0) {
		V_(printf("starting tests ...\n\n"));
	} else {
		printf("error: no SHA test vectors found.\n");
		return EXIT_FAILURE;
	}
	/* run each test in queue with new and old api */
	for (curr_test = queue.head, i = 1; curr_test != NULL;
	     curr_test = curr_test->next, i++) {
		V_(printf("test #%d : %u byte input message, ", i,
		       curr_test->msg_length));
		switch (curr_test->type) {
		case SHA1:
			V_(printf("SHA1 ...\n"));
			rc = sha1_new_api_test(curr_test);
			break;
		case SHA224:
			V_(printf("SHA224 ...\n"));
			rc = sha224_new_api_test(curr_test);
			break;
		case SHA256:
			V_(printf("SHA256 ...\n"));
			rc = sha256_new_api_test(curr_test);
			break;
		case SHA384:
			V_(printf("SHA384 ...\n"));
			rc = sha384_new_api_test(curr_test);
			break;
		case SHA512:
			V_(printf("SHA512 ...\n"));
			rc = sha512_new_api_test(curr_test);
			break;
		default:
			CRITICAL_ERROR("Unknown algorithm.\n");
			rc = -1;
			break;
		}
		if (!rc) {
			V_(printf("... Passed.\n"));
			queue.passed++;
		}
		else {
			V_(printf("error: (%x).\n", rc));
			queue.failed++;
		}

	}
	V_(printf("[SHA test case results: tests: %u,  passed: %u, failed: %u]\n",
			queue.passed + queue.failed, queue.passed, queue.failed));

	if (queue.failed == 0) {
		printf("All SHA tests passed.\n");
		return EXIT_SUCCESS;
	}
	else {
		printf("SHA tests failed.\n");
		return EXIT_FAILURE;
	}
}
