/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2021 */

/*
 * Test program for libica-cex API call ica_get_functionlist().
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

/**
 * For libica-cex, all CPACF-related functions and software fallbacks are
 * unavailable. Only RSA-ME, RSA-CRT, ECDH, ECDSA, and EC keygen may be
 * available via a CCA card. As we don't check for a CCA card here, just
 * skip these. Also RSA keygen is an exception: it's no sw fallback, but
 * a sw implementation.
 */
int cex_check_ok(libica_func_list_element func)
{
	switch (func.mech_mode_id) {
	case RSA_KEY_GEN_ME:
	case RSA_KEY_GEN_CRT:
	case RSA_ME:
	case RSA_CRT:
	case EC_DH:
	case EC_DSA_SIGN:
	case EC_DSA_VERIFY:
	case EC_KGEN:
		return 1;
		break;
	default:
		if (func.flags != 0)
			return 0;
		break;
	}

	return 1;
}

int main(int argc, char **argv)
{
	libica_func_list_element* libica_func_list;
	int rc;
	int failed = 0;
	unsigned int count, x;

	set_verbosity(argc, argv);

	//========== Test#1 good case ============
	V_(printf("Testing libica-cex API ica_get_functionlist().\n"));
	rc = ica_get_functionlist(NULL, &count);
	if (rc) {
		V_(printf("ica_get_functionlist for libica-cex failed with rc=%02x\n", rc));
		return TEST_FAIL;
	}
	V_(printf("Retrieved number of elements: %d\n", count));

	libica_func_list = malloc(sizeof(libica_func_list_element) * count);
	rc = ica_get_functionlist(libica_func_list, &count);
	if (rc) {
		V_(printf("Retrieving function list for libica-cex failed with rc=%02x\n", rc));
		failed++;
	} else {
		for (x = 0; x < count; x++) {
			V_(printf("ID: %d Flags: %d Property: %d\n",
				libica_func_list[x].mech_mode_id,
				libica_func_list[x].flags, libica_func_list[x].property));
			if (!cex_check_ok(libica_func_list[x])) {
				V_(printf("Error: mech mode %d has flags unequal to zero!\n",
					libica_func_list[x].mech_mode_id));
				failed++;
			}
		}
	}

	//========== Test#2 bad parameter ============
	rc = ica_get_functionlist(NULL, NULL);
	if (rc != EINVAL) {
		V_(printf("Operation failed: Expected: %d Actual: %d\n", EINVAL, rc));
		failed++;
	}

	if (failed) {
		printf("ica_get_functionlist tests for libica-cex failed.\n");
		return TEST_FAIL;
	}

	printf("All ica_get_functionlist tests for libica-cex passed.\n");
	return TEST_SUCC;
}
