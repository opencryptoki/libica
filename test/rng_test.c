/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2010, 2011 */
#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include "ica_api.h"
#include <string.h>
#include "testcase.h"

unsigned char R[512];

extern int errno;

int main(int argc, char **argv)
{
	int rc;
	ica_adapter_handle_t adapter_handle;

	set_verbosity(argc, argv);

	rc = ica_open_adapter(&adapter_handle);
	if (rc != 0) {
		V_(printf("ica_open_adapter failed and returned %d (0x%x).\n", rc, rc));
	}

	rc = ica_random_number_generate(sizeof R, R);
	if (rc != 0) {
		V_(printf("ica_random_number_generate failed and returned %d (0x%x).\n", rc, rc));
#ifdef __s390__
		if (rc == ENODEV) {
			V_(printf("The usual cause of this on zSeries is that the CPACF instruction is not available.\n"));
		}
#endif
		return TEST_FAIL;
	}

	dump_array(R, sizeof R);
	VV_(printf("\nWell, does it look random?\n\n"));

	ica_close_adapter(adapter_handle);
	return TEST_SUCC;
}
