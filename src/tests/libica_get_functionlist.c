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

int main(int argc, char **argv)
{
	libica_func_list_element* libica_func_list;
	int rc, x;
	int failed = 0;
	unsigned int count;
	unsigned int silent = 0;

	if (argc > 1) {
		if (strstr(argv[1], "silent"))
			silent = 1;
	}
	//========== Test#1 good case ============
	if (!silent) {
		printf("Testing libica API ica_get_functionlist().\n");
	}
	rc = ica_get_functionlist(NULL, &count);
	if (rc) {
		printf("ica_get_functionlist failed with rc=%02x\n", rc);
		return -1;
	}
	if (!silent) {
		printf("Retrieved number of elements: %d\n", count);
	}

	libica_func_list = malloc(sizeof(libica_func_list_element) * count);
	rc = ica_get_functionlist(libica_func_list, &count);
	if (rc) {
		printf("Retrieving function list failed with rc=%02x\n", rc);
		failed++;
	}
	else {
		if (!silent) {
			for (x=0; x<count; x++) {
				printf("ID: %d Flags: %d Property: %d\n",
					libica_func_list[x].mech_mode_id,
					libica_func_list[x].flags, libica_func_list[x].property);
			}
		}
	}

	//========== Test#2 bad parameter ============
	rc = ica_get_functionlist(NULL, NULL);
	if (rc != EINVAL) {
		printf("Operation failed: Expected: %d Actual: %d\n", EINVAL, rc);
		failed++;
	}

	if (failed) {
		printf("Testcases failed!\n");
		return 1;
	} else {
		printf("All ica_get_functionlist tests completed sucessfully\n");
		return 0;
	}
}
