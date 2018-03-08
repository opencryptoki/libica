/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2010, 2013 */

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
	libica_func_list_element* libica_func_list;
	int rc;
	int failed = 0;
	unsigned int count, x;

	set_verbosity(argc, argv);

	//========== Test#1 good case ============
	V_(printf("Testing libica API ica_get_functionlist().\n"));
	rc = ica_get_functionlist(NULL, &count);
	if (rc) {
		V_(printf("ica_get_functionlist failed with rc=%02x\n", rc));
		return TEST_FAIL;
	}
	V_(printf("Retrieved number of elements: %d\n", count));

	libica_func_list = malloc(sizeof(libica_func_list_element) * count);
	rc = ica_get_functionlist(libica_func_list, &count);
	if (rc) {
		V_(printf("Retrieving function list failed with rc=%02x\n", rc));
		failed++;
	}
	else {
		for (x = 0; x < count; x++) {
			V_(printf("ID: %d Flags: %d Property: %d\n",
				libica_func_list[x].mech_mode_id,
				libica_func_list[x].flags, libica_func_list[x].property));
		}
	}

	//========== Test#2 bad parameter ============
	rc = ica_get_functionlist(NULL, NULL);
	if (rc != EINVAL) {
		V_(printf("Operation failed: Expected: %d Actual: %d\n", EINVAL, rc));
		failed++;
	}

	if (failed) {
		printf("ica_get_functionlist tests failed.\n");
		return TEST_FAIL;
	}

	printf("All ica_get_functionlist tests passed.\n");
	return TEST_SUCC;
}
