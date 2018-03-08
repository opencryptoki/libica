/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2010, 2011 */

/*
 * Test program for libica API call ica_get_version().
 *
 * Test 1: invalid input.
 * Test 2: Valid input.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "ica_api.h"
#include <string.h>
#include "testcase.h"

int main(int argc, char **argv)
{
	libica_version_info version_info;
	int rc;
	int failed = 0;

	set_verbosity(argc, argv);

	V_(printf("Testing libica API ica_get_version() w/ invalid input (NULL).\n"));
	rc = ica_get_version(NULL);
	if (rc == EINVAL) {
		V_(printf("Test successful\n"));
	}
	else {
		printf("Test failed: rc=%x, expected: %x \n", rc, EINVAL);
		failed++;
	}

	V_(printf("Testing libica API ica_get_version_() w/ valid input.\n"));
	rc = ica_get_version(&version_info);
	if (rc == 0) {
		V_(printf("Test successful\n"));
		V_(printf("Major_version:%d, minor_version %d, fixpack_version %d\n",
			version_info.major_version, version_info.minor_version,
			version_info.fixpack_version));
	}
	else {
		V_(printf("Test failed rc=%d, expected: %d \n", rc, 0));
		failed++;
	}

	if (failed) {
		printf("Failed ica_get_version tests: %d\n", failed);
		return TEST_FAIL;
	}

	printf("All ica_get_version tests passed.\n");
	return TEST_SUCC;
}
