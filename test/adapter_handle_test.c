/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2022 */

#include <stdio.h>
#include <errno.h>

#include "ica_api.h"
#include "testcase.h"

int main(int argc, char **argv)
{
	ica_adapter_handle_t adapter_handle;
	int rc;

	set_verbosity(argc, argv);

	rc = ica_open_adapter(&adapter_handle);
	if (rc != 0) {
		V_(perror("ica_open_adapter failed"));
		return TEST_FAIL;
	}

	if (adapter_handle > 3) {
		V_(printf("ica_open_adapter: file descriptor value is greater than 3 (current %d).\n",
			  adapter_handle));
		return TEST_FAIL;
	}

	printf("All adapter handle tests passed.\n");
	return TEST_SUCC;
}
