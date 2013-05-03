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

int main(int argc, char **argv)
{
	libica_func_list_element* libica_func_list;
	//libica_version_info version_info;
	int rc, x;
	int failed = 0;
        unsigned int count;

	//========== Test#1 good case ============
	printf("Testing libica API ica_get_functionlist().\n");
	rc = ica_get_functionlist(NULL, &count);
	if (rc == 0) 
		printf("Retrieved length: %d\n", count);
	else {
		printf("Test failed");
		failed++;
	}
	//printf(" (rc=%d, expected: %d)\n", rc, 0);

        libica_func_list = malloc(sizeof(libica_func_list_element) * count);
	rc = ica_get_functionlist(libica_func_list, &count);
        if (rc != 0) {
                printf("Operation failed\n");
     		failed = 1;
	}
 	else {
 	   for (x=0; x<count; x++) {
		printf("ID: %d Flags: %d Property: %d\n", libica_func_list[x].mech_mode_id, 
				libica_func_list[x].flags, libica_func_list[x].property);
	   }
	}

	//========== Test#2 bad parameter ============
	rc = ica_get_functionlist(NULL, NULL);
	if (rc != EINVAL) {
		printf("Operation failed: Expected: %d Actual: %d\n", EINVAL, rc);
                failed = 1;
	}

	if (failed) {
		printf("Failed tests \n");
		return 1;
	} else {
		printf("All tests completed sucessfully\n");
		return 0;
	}
}
