/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Authors(s): Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2009
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/icastats.h"

const char *const STATS_DESC[ICA_NUM_STATS] = {
	"SHA-1",
	"SHA-224",
	"SHA-256",
	"SHA-384",
	"SHA-512",
	"RANDOM",
	"MOD EXPO",
	"RSA CRT",
	"DES ENC",
	"DES DEC",
	"3DES ENC",
	"3DES DEC",
	"AES ENC",
	"AES DEC"
};

int main(int argc, char *argv[])
{
	int reset = 0;

	if (argc != 1) {
		if (argc == 2 && strcmp(argv[1], "--reset") == 0) {
			reset = 1;
		}
		else {
			printf("Usage: %s [--reset]\n", argv[0]);
			return 0;
		}
	}

	if (stats_mmap() != 0) {
		fprintf(stderr, "Could not map shared memory region to local "
			"address space.");
		return 1;
	}

	if (reset) {
		stats_reset();
	} else {
		printf(" function | # hardware | # software \n");
		printf("----------+------------+------------\n");
		unsigned int i;
		for (i = 0; i != ICA_NUM_STATS; ++i) {
			printf(" %8s |%11d |%11d \n", STATS_DESC[i], stats_query(i, 1),
			stats_query(i, 0));
		}
	}

	stats_munmap();

	return 0;
}
