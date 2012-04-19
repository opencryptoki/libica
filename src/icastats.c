/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Authors(s): Christian Maaser <cmaaser@de.ibm.com>
 *             Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2010, 2011
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include "icastats.h"

#define CMD_NAME "icastats"
#define COPYRIGHT "Copyright IBM Corp. 2009, 2010, 2011."

void print_version(void)
{
	printf(CMD_NAME ": libica version " VERSION "\n" COPYRIGHT "\n");
}

void print_help(char *cmd)
{
	printf("Usage: %s [OPTION]\n\n", cmd);
	printf("This command is used to indicate whether libica uses hardware or works with\n"
	       "software fallbacks. It shows also which specific functions of libica are used.\n"
	       "All counters are not persistent and will be set to zero, if the last process\n"
	       "unloads the libica library.\n"
	       "\n"
	       "Options:\n"
	       " -r, --reset    sets the function counters to zero and exit\n"
	       " -v, --version  output version information and exit\n"
	       " -h, --help     displays help information for the command and exit\n");
}

#define getopt_string "rvh"
static struct option getopt_long_options[] = {
	{"reset", 0, 0, 'r'},
	{"version", 0, 0, 'v'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};



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
	"AES DEC",
	"CMAC GEN",
	"CMAC VER",
	"CCM ENC",
	"CCM DEC",
	"CCM AUTH",
	"GCM ENC",
	"GCM DEC",
	"GCM AUTH",
};

int main(int argc, char *argv[])
{
	int rc, index, reset = 0;

	while ((rc = getopt_long(argc, argv, getopt_string,
				 getopt_long_options, &index)) != -1) {
		switch (rc) {
		case 'r':
			reset = 1;
			break;
		case 'v':
			print_version();
			exit(0);
			break;
		case 'h':
			print_help(basename(argv[0]));
			exit(1);
		default:
			fprintf(stderr,
				"Try '%s --help' for more information.\n",
				basename(argv[0]));
			exit(1);
		}
	}

	if (optind < argc) {
		fprintf(stderr, "%s: invalid option.\n"
		        "Try '%s --help' for more information.\n",
		        argv[0], basename(argv[0]));
		exit(1);
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
