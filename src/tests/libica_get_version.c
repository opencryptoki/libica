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
#include "ica_api.h"

int main(int argc, char **argv)
{
	libica_version_info version_info;
	int rc;

	printf("Testing libica API ica_get_version(). Invalid input (NULL).\n");

	rc = ica_get_version(NULL);

	if (rc == 0) {
		printf("OK. Not expected (RC=%d).\n", rc);
	} else {
		printf("Error. Expected(RC=%d).\n", rc);
	}

	printf("Testing libica API ica_get_version_(). Valid input.\n");

	rc = ica_get_version(&version_info);

	if (rc == 0) {
		printf("OK. Expected (RC=%d).\n", rc);
	} else {
	printf("Error. Not expected (RC=%d).\n", rc);
		return rc;
	}

	printf("Major_version:%d\n", version_info.major_version);
	printf("Minor_version:%d\n", version_info.minor_version);
	printf("Fixpack_version:%d\n", version_info.fixpack_version);

	return 0;
}
