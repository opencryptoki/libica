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

int main(int argc, char **argv)
{
	libica_version_info version_info;
	int rc;
	int failed = 0;

	printf("Testing libica API ica_get_version() w/ invalid input (NULL).\n");
	rc = ica_get_version(NULL);
	if (rc == EINVAL)
		printf("Test successful");
	else {
		printf("Test failed");
		failed++;
	}
	printf(" (rc=%d, expected: %d)\n", rc, EINVAL);

	printf("Testing libica API ica_get_version_() w/ valid input.\n");
	rc = ica_get_version(&version_info);
	if (rc == 0)
		printf("Test successful");
	else {
		printf("Test failed");
		failed++;
	}
	printf(" (rc=%d, expected: %d)\n", rc, 0);

	printf("Major_version:%d, minor_version %d, fixpack_version %d\n",
	       version_info.major_version,
	       version_info.minor_version,
	       version_info.fixpack_version);

	if (failed) {
		printf("Failed tests: %d\n", failed);
		return 1;
	} else {
		printf("All tests completed sucessfully\n");
		return 0;
	}
}
