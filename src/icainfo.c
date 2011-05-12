/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Display a list of all CP Assist for Cryptographic Function (CPACF)
 * operations supported by libica on a system.
 *
 * Authors(s): Ralph Wuerthner <rwuerthn@de.ibm.com>
 * 	       Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2007, 2011
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include "s390_crypto.h"

#define CMD_NAME "icainfo"
#define COPYRIGHT "Copyright IBM Corp. 2007."

void print_version(void)
{
	printf(CMD_NAME ": libica version " VERSION "\n" COPYRIGHT "\n");
}

void print_help(char *cmd)
{
	printf("Usage: %s [OPTION]\n", cmd);
	printf
	    ("Display a list of all CP Assist for Cryptographic Function (CPACF) operations\n"
	     "supported by libica on this system.\n" "\n" "Options:\n"
	     " -q, --quiet    output supported operations list only\n"
	     " -v, --version  output version information and exit\n"
	     " -h, --help     display this help text and exit\n");
}

#define getopt_string "qvh"
static struct option getopt_long_options[] = {
	{"quiet", 0, 0, 'q'},
	{"version", 0, 0, 'v'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};

struct crypto_function {
	char *desc;
	int code;
};

struct crypto_function kimd_functions[] = {
	{"SHA-1:", S390_CRYPTO_SHA_1},
	{"SHA-256:", S390_CRYPTO_SHA_256},
	{"SHA-512:", S390_CRYPTO_SHA_512},
	{NULL, 0}
};

struct crypto_function kmc_functions[] = {
	{"DES:", S390_CRYPTO_DEA_ENCRYPT},
	{"TDES-128:", S390_CRYPTO_TDEA_128_ENCRYPT},
	{"TDES-192:", S390_CRYPTO_TDEA_192_ENCRYPT},
	{"AES-128:", S390_CRYPTO_AES_128_ENCRYPT},
	{"AES-192:", S390_CRYPTO_AES_192_ENCRYPT},
	{"AES-256:", S390_CRYPTO_AES_256_ENCRYPT},
	{"PRNG:", S390_CRYPTO_PRNG},
	{NULL, 0}
};

struct crypto_function kmac_functions[] = {
	{"CCM-AES-128:", S390_CRYPTO_AES_128_ENCRYPT},
	{"CMAC-AES-128:", S390_CRYPTO_AES_128_ENCRYPT},
	{"CMAC-AES-192:", S390_CRYPTO_AES_192_ENCRYPT},
	{"CMAC-AES-256:", S390_CRYPTO_AES_256_ENCRYPT},
	{NULL, 0}
};

int main(int argc, char **argv)
{
	unsigned char mask[16];
	int rc, index, n, quiet = 0;

	while ((rc = getopt_long(argc, argv, getopt_string,
				 getopt_long_options, &index)) != -1) {
		switch (rc) {
		case 'q':
			quiet = 1;
			break;
		case 'v':
			print_version();
			exit(0);
			break;
		case 'h':
			print_help(basename(argv[0]));
			exit(1);
		default:
			fprintf(stderr, "Try '%s --help' for more"
				" information.\n", basename(argv[0]));
			exit(1);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "%s: invalid option.\n"
			"Try '%s --help' for more information.\n",
			argv[0], basename(argv[0]));
		exit(1);
	}

	if (!quiet)
		printf("The following CP Assist for Cryptographic Function "
		       "(CPACF) operations are\nsupported by libica on this "
		       "system:\n");
	s390_kimd(S390_CRYPTO_QUERY, &mask, NULL, 0);
	for (n = 0; kimd_functions[n].desc != NULL; n++) {
		printf("%-14s", kimd_functions[n].desc);
		if (S390_CRYPTO_TEST_MASK(mask, kimd_functions[n].code))
			printf("yes\n");
		else
			printf("no\n");
	}
	s390_kmc(S390_CRYPTO_QUERY, &mask, NULL, NULL, 0);
	for (n = 0; kmc_functions[n].desc != NULL; n++) {
		printf("%-14s", kmc_functions[n].desc);
		if (S390_CRYPTO_TEST_MASK(mask, kmc_functions[n].code))
			printf("yes\n");
		else
			printf("no\n");
	}
	s390_kmac(S390_CRYPTO_QUERY, &mask, NULL, 0);
	for (n = 0; kmac_functions[n].desc != NULL; n++) {
		printf("%-14s", kmac_functions[n].desc);
		if (S390_CRYPTO_TEST_MASK(mask, kmac_functions[n].code))
			printf("yes\n");
		else
			printf("no\n");
	}
	return 0;
}
