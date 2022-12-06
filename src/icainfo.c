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
#define COPYRIGHT "Copyright IBM Corp. 2007, 2022."

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

#ifdef ICA_FIPS
static const unsigned int cpacf_fips_nids[] = {
	NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1 };
static const unsigned int cpacf_fips_nids_len = sizeof(cpacf_fips_nids) / sizeof(unsigned int);
#endif

static int is_msa9(void)
{
	unsigned int mech_len, j;
	libica_func_list_element *pmech_list = NULL;

	if (ica_get_functionlist(NULL, &mech_len) != 0) {
		perror("get_functionlist: ");
		return 0;
	}

	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (!pmech_list) {
		perror("is_msa9: error malloc");
		return 0;
	}

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
	if (!pmech_list) {
		perror("online_cca_card: error malloc");
		return 0;
	}

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

int rsa_keylen_supported_by_openssl(unsigned int modulus_bitlength)
{
	unsigned char modexpo_public_e[512] = { 0 };
	unsigned char modexpo_public_n[512] = { 0 };
	unsigned char crt_private_p[256] = { 0 };
	unsigned char crt_private_q[256] = { 0 };
	unsigned char crt_private_dp[256] = { 0 };
	unsigned char crt_private_dq[256] = { 0 };
	unsigned char crt_private_inv_q[256] = { 0 };
	ica_adapter_handle_t ah;
	ica_rsa_key_mod_expo_t public_key;
	ica_rsa_key_crt_t private_key;
	int rc;

	rc = ica_open_adapter(&ah);
	if (rc != 0)
		return 0;

	public_key.modulus = modexpo_public_n;
	public_key.exponent = modexpo_public_e;
	public_key.key_length = (modulus_bitlength + 7) / 8;

	private_key.p = crt_private_p;
	private_key.q = crt_private_q;
	private_key.dp = crt_private_dp;
	private_key.dq = crt_private_dq;
	private_key.qInverse = crt_private_inv_q;
	private_key.key_length = (modulus_bitlength + 7) / 8;

	rc = ica_rsa_key_generate_crt(ah, modulus_bitlength,
							&public_key, &private_key);

	ica_close_adapter(ah);

	return rc == 0 ? 1 : 0;
}

int get_rsa_minlen(void)
{
	int keylen_array[] = { 57, 512, 1024, 2048, 4096 };
	size_t i;

	for (i = 0; i < sizeof(keylen_array) / sizeof(int); i++) {
		if (rsa_keylen_supported_by_openssl(keylen_array[i])) {
			return keylen_array[i];
		}
	}

	return -1;
}

/**
 * Print out the minimum and maximum RSA key length. The maximum length is
 * restricted to 4096 bits by crypto cards. The minimum accepted length in
 * libica is 57 bits, but the available min length depends on the openssl
 * version and fips mode.
 */
void print_rsa(void)
{
	int minlen = get_rsa_minlen();

	if (minlen > 0)
		printf("RSA key lengths: %d ... 4096 bits.\n", minlen);
	else
		printf("Error: cannot determine supported RSA key lengths via openssl.\n");

#ifdef ICA_FIPS
	printf("Built-in FIPS support: FIPS 140-3 mode %s.\n",
	    ica_fips_status() & ICA_FIPS_MODE ? "active" : "inactive");
	if (ica_fips_status() >> 1)
		printf("FIPS SELF-TEST FAILURE. CHECK THE SYSLOG.\n");
#else
	printf("No built-in FIPS support.\n");
#endif /* ICA_FIPS */
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
#ifndef NO_SW_FALLBACKS
			if (curve_supported_via_openssl(nid) && sw_fallbacks_implemented(nid))
				curve_array[i].flags |= ICA_FLAG_SW;
#endif
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
#ifndef NO_SW_FALLBACKS
				if (curve_supported_via_openssl(nids[i]) && sw_fallbacks_implemented(nids[i]))
					curve_array[j].flags |= ICA_FLAG_SW;
#endif
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
#ifdef ICA_FIPS
	if (is_msa9()) {
		if (ica_fips_status() & ICA_FIPS_MODE) {
			add_hw_curves(curve_array, array_len, cpacf_fips_nids, cpacf_fips_nids_len, ICA_FLAG_SHW);
		} else {
			add_hw_curves(curve_array, array_len, cpacf_nids, cpacf_nids_len, ICA_FLAG_SHW);
			if (online_cca_card())
				add_hw_curves(curve_array, array_len, cca_nids, cca_nids_len, ICA_FLAG_DHW);
		}
	} else {
		/* No MSA9, ECC only available via CEX cards */
		if (online_cca_card())
			add_hw_curves(curve_array, array_len, cca_nids, cca_nids_len, ICA_FLAG_DHW);
	}
#else
	if (online_cca_card())
		add_hw_curves(curve_array, array_len, cca_nids, cca_nids_len, ICA_FLAG_DHW);

	if (is_msa9())
		add_hw_curves(curve_array, array_len, cpacf_nids, cpacf_nids_len, ICA_FLAG_SHW);
#endif
}

void print_ec_curves(void)
{
	s390_supported_curves_t *curve_array;
	unsigned int array_len, array_size, n;
#ifdef NO_CPACF
	char *no_shw = "-";
#else
	char *no_shw = "no";
#endif
#ifdef NO_SW_FALLBACKS
	char *no_sw = "-";
#else
	char *no_sw = "no";
#endif

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
	printf("                 |            |  (msa=%02d)  |         \n",ica_get_msa_level());
	printf("-----------------+------------+------------+-----------\n");

	for (n = 0; n < array_len; n++) {
		if (curve_array[n].nid != 0) {
			printf("%16s |    %*s     |    %*s     |    %*s\n",
				curve_array[n].sname,
				CELL_SIZE,
				curve_array[n].flags & ICA_FLAG_DHW ? "yes" : "no",
				CELL_SIZE,
				curve_array[n].flags & ICA_FLAG_SHW ? "yes" : no_shw,
				CELL_SIZE,
				curve_array[n].flags & ICA_FLAG_SW ? "yes" : no_sw);
		}
	}
	printf("-------------------------------------------------------\n");
#ifdef ICA_FIPS
	printf("Built-in FIPS support: FIPS 140-3 mode %s.\n",
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

	if (strcmp(BUILD_VERSION, DEFAULT_BUILD_VERSION) != 0)
		printf("build: " BUILD_VERSION "\n");
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
	     " -r, --list-rsa       list supported RSA key lengths\n"
	     " -f, --list-fips-exceptions   show fips exception list\n"
	     " -h, --help           display this help text\n");
}

#define getopt_string "qcrfvh"
static struct option getopt_long_options[] = {
	{"list-curves", 0, 0, 'c'},
	{"list-rsa", 0, 0, 'r'},
	{"list-fips-exceptions", 0, 0, 'f'},
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

int get_index_in_fips_list(libica_fips_indicator_element *fips_list,
		unsigned int fips_len, unsigned int algo_id)
{
	size_t i;

	for (i = 0; i < fips_len; i++) {
		if (fips_list[i].mech_mode_id == algo_id)
			return i;
	}

	return -1;
}

int get_index_in_mech_list(libica_func_list_element *mech_list,
		unsigned int mech_len, unsigned int algo_id)
{
	size_t i;

	for (i = 0; i < mech_len; i++) {
		if (mech_list[i].mech_mode_id == algo_id)
			return i;
	}

	return -1;
}

void print_fips_indicator(void)
{
#ifndef ICA_FIPS
	printf("Built-in FIPS support: FIPS 140-3 mode inactive.\n");
#else
	unsigned int fips_len, mech_len, i;
	int j, k;
	libica_fips_indicator_element *fips_list = NULL;
	libica_func_list_element *pmech_list = NULL;

	if (!(ica_fips_status() & ICA_FIPS_MODE)) {
		printf("Built-in FIPS support: Not running in active fips mode.\n");
		return;
	}

	/* Get functionlist */
	if (ica_get_functionlist(NULL, &mech_len) != 0){
		perror("get_functionlist: ");
		goto done;
	}

	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (!pmech_list) {
		perror("error malloc");
		goto done;
	}

	if (ica_get_functionlist(pmech_list, &mech_len) != 0){
		perror("get_functionlist: ");
		goto done;
	}

	/* Get fips indicator list */
	if (ica_get_fips_indicator(NULL, &fips_len) != 0){
		perror("get_fips_indicator: ");
		goto done;
	}

	fips_list = malloc(sizeof(libica_fips_indicator_element)*fips_len);
	if (!fips_list) {
		perror("error malloc");
		goto done;
	}

	if (ica_get_fips_indicator(fips_list, &fips_len) != 0){
		perror("get_fips_indicator: ");
		goto done;
	}

	printf("              FIPS service indicator                  \n");
	printf("------------------------------------------------------\n");
	printf("               |      Available but non-approved      \n");
	printf(" function      |   dynamic  |   static   |  software  \n");
	printf("---------------+--------------------------------------\n");

	for (i = 0; crypt_map[i].algo_id; i++) {
		j = get_index_in_fips_list(fips_list, fips_len, crypt_map[i].algo_id);
		k = get_index_in_mech_list(pmech_list, mech_len, crypt_map[i].algo_id);
		if (j < 0 || k < 0)
			continue;
		if (pmech_list[k].flags != 0 && fips_list[j].fips_approved == 0 &&
			fips_list[j].fips_override == 1) {
			printf("%14s |    %*s     |    %*s     |    %*s     \n",
				crypt_map[i].name,
				CELL_SIZE,
				pmech_list[k].flags & ICA_FLAG_DHW ? "yes" : "-",
				CELL_SIZE,
				pmech_list[k].flags & ICA_FLAG_SHW ? "yes" : "-",
				CELL_SIZE,
				pmech_list[k].flags & ICA_FLAG_SW ? "yes" : "-");
		}
	}

	printf("------------------------------------------------------\n");

done:
	free(fips_list);
	free(pmech_list);
	ica_cleanup();
#endif
}

int main(int argc, char **argv)
{
	int rc;
	int index = 0;
	unsigned int mech_len, j;
	libica_func_list_element *pmech_list = NULL;
	unsigned int i;
	char *no_dhw = "no";
#ifdef NO_CPACF
	char *no_shw = "-";
#else
	char *no_shw = "no";
#endif
#ifdef NO_SW_FALLBACKS
	char *no_sw = "-";
#else
	char *no_sw = "no";
#endif

	while ((rc = getopt_long(argc, argv, getopt_string,
				 getopt_long_options, &index)) != -1) {
		switch (rc) {
		case 'f':
			print_fips_indicator();
			exit(0);
		case 'c':
			print_ec_curves();
			exit(0);
		case 'r':
			print_rsa();
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
	if (!pmech_list) {
		perror("error malloc");
		return EXIT_FAILURE;
	}

	if (ica_get_functionlist(pmech_list, &mech_len) != 0){
		perror("get_functionlist: ");
		free(pmech_list);
		ica_cleanup();
		return EXIT_FAILURE;
	}

	printf("               |         hardware        |            \n");
	printf(" function      |   dynamic  |   static   |  software  \n");
	printf("               |            |  (msa=%02d)  |            \n",ica_get_msa_level());
	printf("---------------+------------+------------+------------\n");
	for (i = 0; crypt_map[i].algo_id; i++) {
		for (j = 0; j < mech_len; j++) {
			if (crypt_map[i].algo_id == pmech_list[j].mech_mode_id) {
#ifdef ICA_FIPS
				if (((ica_fips_status() & ICA_FIPS_MODE) &&
					!fips_approved(pmech_list[j].mech_mode_id) &&
					!fips_override(pmech_list[j].mech_mode_id)) ||
					ica_fips_status() >> 1) {
					printf("%14s |  blocked   |  blocked   |  blocked\n",
						crypt_map[i].name);
					break;
				}
#endif /* ICA_FIPS */
				printf("%14s |    %*s     |    %*s     |    %*s     \n",
					crypt_map[i].name,
					CELL_SIZE,
					pmech_list[j].flags & ICA_FLAG_DHW ? "yes" : no_dhw,
					CELL_SIZE,
					pmech_list[j].flags & ICA_FLAG_SHW ? "yes" : no_shw,
					CELL_SIZE,
					pmech_list[j].flags & ICA_FLAG_SW ? "yes" : no_sw);
			}
		}
	}
	free(pmech_list);
	printf("------------------------------------------------------\n");

#ifdef ICA_FIPS
	printf("Built-in FIPS support: FIPS 140-3 mode %s.\n",
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
