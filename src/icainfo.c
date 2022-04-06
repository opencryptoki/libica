/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Display a list of all CP Assist for Cryptographic Function (CPACF)
 * operations supported by libica on a system.
 *
 * Author(s): Ralph Wuerthner <rwuerthn@de.ibm.com>
 * 	      Holger Dengler <hd@linux.vnet.ibm.com>
 * 	      Benedikt Klotz <benedikt.klotz@de.ibm.com>
 * 	      Ingo Tuchscherer <ingo.tuchscherer@de.ibm.com>
 *
 * Copyright IBM Corp. 2007, 2011, 2014
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/objects.h>

#include "fips.h"
#include "ica_api.h"
#include "s390_crypto.h"
#include "s390_ecc.h"

#if defined(NO_SW_FALLBACKS) && defined(NO_CPACF)
#define CMD_NAME "icainfo-cex"
#else
#define CMD_NAME "icainfo"
#endif
#define COPYRIGHT "Copyright IBM Corp. 2007, 2021."

#define CELL_SIZE 3

typedef struct {
	unsigned int nid;
	unsigned char *sname;
	unsigned int flags;
} s390_supported_curves_t;

static const unsigned int cca_nids[] = {
	NID_X9_62_prime192v1, NID_secp224r1, NID_X9_62_prime256v1,
	NID_secp384r1, NID_secp521r1, NID_brainpoolP160r1, NID_brainpoolP192r1,
	NID_brainpoolP224r1, NID_brainpoolP256r1, NID_brainpoolP320r1,
	NID_brainpoolP384r1, NID_brainpoolP512r1 };
static const unsigned int cca_nids_len = sizeof(cca_nids) / sizeof(unsigned int);

static const unsigned int cpacf_nids[] = {
	NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1,
	NID_ED25519, NID_ED448, NID_X25519, NID_X448 };
static const unsigned int cpacf_nids_len = sizeof(cpacf_nids) / sizeof(unsigned int);

static int is_msa9(void)
{
	unsigned int mech_len, j;
	libica_func_list_element *pmech_list = NULL;

	if (ica_get_functionlist(NULL, &mech_len) != 0) {
		perror("get_functionlist: ");
		return 0;
	}

	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (ica_get_functionlist(pmech_list, &mech_len) != 0) {
		perror("get_functionlist: ");
		free(pmech_list);
		return 0;
	}

	for (j = 0; j < mech_len; j++) {
		if (pmech_list[j].mech_mode_id == EC_DSA_SIGN) {
			if (pmech_list[j].flags & ICA_FLAG_SHW) {
				free(pmech_list);
				return 1;
			}
		}
	}

	free(pmech_list);
	return 0;
}

static int online_cca_card(void)
{
	unsigned int mech_len, j;
	libica_func_list_element *pmech_list = NULL;

	if (ica_get_functionlist(NULL, &mech_len) != 0) {
		perror("get_functionlist: ");
		return 0;
	}

	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (ica_get_functionlist(pmech_list, &mech_len) != 0) {
		perror("get_functionlist: ");
		free(pmech_list);
		return 0;
	}

	for (j = 0; j < mech_len; j++) {
		if (pmech_list[j].mech_mode_id == EC_DSA_SIGN) {
			if (pmech_list[j].flags & ICA_FLAG_DHW) {
				free(pmech_list);
				return 1;
			}
		}
	}

	free(pmech_list);
	return 0;
}

static int num_cpacf_curves(void)
{
	if (!is_msa9())
		return 0;

	return sizeof(cpacf_nids) / sizeof(unsigned int);
}

static int num_cca_curves(void)
{
	if (!online_cca_card())
		return 0;

	return sizeof(cca_nids) / sizeof(unsigned int);
}

void append_nid(unsigned int nid, unsigned int flag,
				s390_supported_curves_t *curve_array, size_t array_len)
{
	const char* sname;
	unsigned int i;

	for (i = 0; i < array_len; i++) {
		if (curve_array[i].nid == 0) {
			curve_array[i].nid = nid;
			sname = OBJ_nid2sn(nid);
			if (sname == NULL)
				sname = "";
			curve_array[i].sname = (unsigned char *)sname;
			curve_array[i].flags |= flag;
			if (curve_supported_via_openssl(nid) && sw_fallbacks_implemented(nid))
				curve_array[i].flags |= ICA_FLAG_SW;
			break;
		}
	}
}

void add_hw_curves(s390_supported_curves_t *curve_array, size_t array_len,
				 const unsigned int nids[], unsigned int nids_len,
				 unsigned int flag)
{
	unsigned int i, j, merged;

	for (i = 0; i < nids_len; i++) {
		merged = 0;
		for (j = 0; j < array_len; j++) {
			if (curve_array[j].nid == nids[i]) {
				curve_array[j].flags |= flag;
				if (curve_supported_via_openssl(nids[i]) && sw_fallbacks_implemented(nids[i]))
					curve_array[j].flags |= ICA_FLAG_SW;
				merged = 1;
				break;
			}
		}
		if (!merged)
			append_nid(nids[i], flag, curve_array, array_len);
	}
}

void add_curves(s390_supported_curves_t *curve_array, size_t array_len)
{
	if (online_cca_card())
		add_hw_curves(curve_array, array_len, cca_nids, cca_nids_len, ICA_FLAG_DHW);

	if (is_msa9())
		add_hw_curves(curve_array, array_len, cpacf_nids, cpacf_nids_len, ICA_FLAG_SHW);
}

/**
 * These are nids that are fips approved, but libica has no sw fallbacks
 * implemented for them. If they are supported via hw, we want them in the
 * icainfo output.
 */
unsigned int fips_override(unsigned int nid)
{
	switch (nid) {
	case NID_ED25519:
	case NID_ED448:
	case NID_X25519:
	case NID_X448:
		return 1;
	default:
		return 0;
	}
}

void print_ec_curves(void)
{
	s390_supported_curves_t *curve_array;
	unsigned int array_len, array_size, n;

	array_len = num_cca_curves() + num_cpacf_curves();
	array_size = array_len * sizeof(s390_supported_curves_t);
	curve_array = calloc(1, array_size);
	if (!curve_array) {
		fprintf(stderr, "Error: cannot allocate %d bytes for array of curves.\n", array_size);
		return;
	}

	add_curves(curve_array, array_len);

	printf("-------------------------------------------------------\n");
	printf("                 |         hardware        |           \n");
	printf("        EC curve |   dynamic  |   static   |  software \n");
	printf("-----------------+------------+------------+-----------\n");

	for (n = 0; n < array_len; n++) {
#ifdef ICA_FIPS
		/* In fips mode, only allow openssl-fips supported curves, and curves
		 * that are fips approved, but have no sw fallback implemented.*/
		if (curve_array[n].nid != 0 &&
			((curve_array[n].flags & ICA_FLAG_SW) || (fips_override(curve_array[n].nid)))) {
#else
		if (curve_array[n].nid != 0) {
#endif
			printf("%16s |    %*s     |    %*s     |    %*s\n",
				curve_array[n].sname,
				CELL_SIZE,
				curve_array[n].flags & ICA_FLAG_DHW ? "yes" : "no",
				CELL_SIZE,
#ifdef NO_CPACF
				"-",
#else
				curve_array[n].flags & ICA_FLAG_SHW ? "yes" : "no",
#endif
				CELL_SIZE,
#if defined(NO_SW_FALLBACKS) || defined(NO_CPACF)
				"-");
#else
				curve_array[n].flags & ICA_FLAG_SW ? "yes" : "no");
#endif
		}
	}
	printf("-------------------------------------------------------\n");
#ifdef ICA_FIPS
	printf("Built-in FIPS support: FIPS mode %s.\n",
	    ica_fips_status() & ICA_FIPS_MODE ? "active" : "inactive");
	if (ica_fips_status() >> 1)
		printf("FIPS SELF-TEST FAILURE. CHECK THE SYSLOG.\n");
#else
	printf("No built-in FIPS support.\n");
#endif /* ICA_FIPS */

	free(curve_array);
}

void print_version(void)
{
#if defined(NO_SW_FALLBACKS) && defined(NO_CPACF)
	printf(CMD_NAME ": libica-cex version " VERSION "\n" COPYRIGHT "\n");
#else
	printf(CMD_NAME ": libica version " VERSION "\n" COPYRIGHT "\n");
#endif
}

void print_help(char *cmd)
{
	printf("Usage: %s [OPTION]\n", cmd);
	printf
	    ("Display a list of all CP Assist for Cryptographic Function "
	     "(CPACF)\noperations supported by libica on this system.\n"
	     "\n" "Options:\n"
	     " -v, --version        show version information\n"
	     " -c, --list-curves    list supported EC curves\n"
	     " -h, --help           display this help text\n");
}

#define getopt_string "qcvh"
static struct option getopt_long_options[] = {
	{"list-curves", 0, 0, 'c'},
	{"version", 0, 0, 'v'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};


struct crypt_pair {
	char *name;
	unsigned int algo_id;
};

static struct crypt_pair crypt_map[] = {
	{"SHA-1", SHA1},
	{"SHA-224", SHA224},
	{"SHA-256", SHA256},
	{"SHA-384", SHA384},
	{"SHA-512", SHA512},
	{"SHA-512/224", SHA512_224},
	{"SHA-512/256", SHA512_256},
	{"SHA3-224", SHA3_224},
	{"SHA3-256", SHA3_256},
	{"SHA3-384", SHA3_384},
	{"SHA3-512", SHA3_512},
	{"SHAKE-128", SHAKE128},
	{"SHAKE-256", SHAKE128},
	{"GHASH", G_HASH},
	{"P_RNG", P_RNG},
	{"DRBG-SHA-512", SHA512_DRNG},
	{"ECDH", EC_DH},
	{"ECDSA Sign", EC_DSA_SIGN},
	{"ECDSA Verify", EC_DSA_VERIFY},
	{"EC Keygen", EC_KGEN},
	{"Ed25519 Keygen", ED25519_KEYGEN},
	{"Ed25519 Sign", ED25519_SIGN},
	{"Ed25519 Verify", ED25519_VERIFY},
	{"Ed448 Keygen", ED448_KEYGEN},
	{"Ed448 Sign", ED448_SIGN},
	{"Ed448 Verify", ED448_VERIFY},
	{"X25519 Keygen", X25519_KEYGEN},
	{"X25519 Derive", X25519_DERIVE},
	{"X448 Keygen", X448_KEYGEN},
	{"X448 Derive", X448_DERIVE},
	{"RSA Keygen ME", RSA_KEY_GEN_ME},
	{"RSA Keygen CRT", RSA_KEY_GEN_CRT},
	{"RSA ME", RSA_ME},
	{"RSA CRT", RSA_CRT},
	{"DES ECB", DES_ECB},
	{"DES CBC", DES_CBC},
	{"DES OFB", DES_OFB},
	{"DES CFB", DES_CFB},
	{"DES CTR", DES_CTR},
	{"DES CMAC", DES_CMAC},
	{"3DES ECB", DES3_ECB},
	{"3DES CBC", DES3_CBC},
	{"3DES OFB", DES3_OFB},
	{"3DES CFB", DES3_OFB},
	{"3DES CTR", DES3_CTR},
	{"3DES CMAC", DES3_CMAC},
	{"AES ECB", AES_ECB},
	{"AES CBC", AES_CBC},
	{"AES OFB", AES_OFB},
	{"AES CFB", AES_CFB},
	{"AES CTR", AES_CTR},
	{"AES CMAC", AES_CMAC},
	{"AES XTS", AES_XTS},
	{"AES GCM", AES_GCM_KMA},
	{NULL,0}
};


int main(int argc, char **argv)
{
	int rc;
	int index = 0;
	unsigned int mech_len, j;
	libica_func_list_element *pmech_list = NULL;
	unsigned int i;

	while ((rc = getopt_long(argc, argv, getopt_string,
				 getopt_long_options, &index)) != -1) {
		switch (rc) {
		case 'c':
			print_ec_curves();
			exit(0);
		case 'v':
			print_version();
			exit(0);
			break;
		case 'h':
			print_help(basename(argv[0]));
			exit(0);
		default:
			fprintf(stderr, "Try '%s --help' for more"
				" information.\n", basename(argv[0]));
			ica_cleanup();
			exit(1);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "%s: invalid option.\n"
			"Try '%s --help' for more information.\n",
			argv[0], basename(argv[0]));
		ica_cleanup();
		exit(1);
	}

	printf("              Cryptographic algorithm support      \n");
	printf("------------------------------------------------------\n");

	if (ica_get_functionlist(NULL, &mech_len) != 0){
		perror("get_functionlist: ");
		ica_cleanup();
		return EXIT_FAILURE;
	}
	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (ica_get_functionlist(pmech_list, &mech_len) != 0){
		perror("get_functionlist: ");
		free(pmech_list);
		ica_cleanup();
		return EXIT_FAILURE;
	}

	printf("               |         hardware        |            \n");
	printf(" function      |   dynamic  |   static   |  software  \n");
	printf("---------------+------------+------------+------------\n");
	for(i = 0; crypt_map[i].algo_id; i++){
		for(j = 0; j < mech_len; j++){
			if(crypt_map[i].algo_id == pmech_list[j].mech_mode_id){
#ifdef ICA_FIPS
				if (((ica_fips_status() & ICA_FIPS_MODE)
				    && !fips_approved(pmech_list[j].mech_mode_id))
				    || ica_fips_status() >> 1) {
#if defined(NO_SW_FALLBACKS) && defined(NO_CPACF)
					printf("%14s |  blocked   |      -     |      -   \n",
#elif defined (NO_CPACF)
					printf("%14s |  blocked   |      -     |      -   \n",
#elif defined (NO_SW_FALLBACKS)
					printf("%14s |  blocked   |   blocked  |      -   \n",
#else
					printf("%14s |  blocked   |   blocked  |   blocked\n",
#endif
						crypt_map[i].name);
					break;
				}
#endif /* ICA_FIPS */
				printf("%14s |    %*s     |    %*s     |    %*s\n",
					crypt_map[i].name,
					CELL_SIZE,
					pmech_list[j].flags & ICA_FLAG_DHW ? "yes" : "no",
					CELL_SIZE,
#ifdef NO_CPACF
					pmech_list[j].flags & ICA_FLAG_SHW ? "yes" : "-",
#else
					pmech_list[j].flags & ICA_FLAG_SHW ? "yes" : "no",
#endif
					CELL_SIZE,
#if defined(NO_SW_FALLBACKS) || defined(NO_CPACF)
					pmech_list[j].flags & ICA_FLAG_SW ? "yes" : "-");
#else
					pmech_list[j].flags & ICA_FLAG_SW ? "yes" : "no");
#endif
			}
		}
	}
	free(pmech_list);
	printf("------------------------------------------------------\n");

#ifdef ICA_FIPS
	printf("Built-in FIPS support: FIPS mode %s.\n",
	    ica_fips_status() & ICA_FIPS_MODE ? "active" : "inactive");
	if (ica_fips_status() >> 1)
		printf("FIPS SELF-TEST FAILURE. CHECK THE SYSLOG.\n");
#else
	printf("No built-in FIPS support.\n");
#endif /* ICA_FIPS */

#ifdef NO_SW_FALLBACKS
	printf("Software fallbacks are disabled.\n");
#endif
#ifdef NO_CPACF
	printf("CPACF support (including fallbacks) is disabled in libica-cex.\n");
#endif

	ica_cleanup();
	return EXIT_SUCCESS;
}
