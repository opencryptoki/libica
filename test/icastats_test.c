/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 **/

/* Copyright IBM Corp. 2014 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include "ica_api.h"
#include "testcase.h"

#define DATA_LENGHT 32
#define DES_CIPHER_BLOCK 8
#define AES_CIPHER_BLOCK 16
#define RSA_BYTE_LENGHT 128

unsigned char plain_data[] = {
	0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x6c, 0x69,
	0x62, 0x69, 0x63, 0x61, 0x20, 0x69, 0x73, 0x20,
	0x73, 0x6d, 0x61, 0x72, 0x74, 0x20, 0x61, 0x6e,
	0x64, 0x20, 0x65, 0x61, 0x73, 0x79, 0x21, 0x00,
};

int hw_flag;
unsigned int mech_len;
libica_func_list_element *pmech_list = NULL;

static int handle_ica_error(int rc, char *message);
static int is_crypto_card_loaded();
void create_hw_info();
int check_hw(unsigned int algo_id);
void check_icastats(int algo_id, char *stat);
void des_tests(unsigned char *iv, unsigned char *cmac, unsigned char *ctr);
void tdes_tests(unsigned char *iv, unsigned char *cmac, unsigned char *ctr);
void sha_tests();
void rsa_tests(ica_adapter_handle_t handle);
void aes_tests(unsigned char *iv, unsigned char *cmac, unsigned char *ctr);

int main (int argc, char **argv)
{
	int rc = 0;
	int value;
	const char *ptr;
	ica_adapter_handle_t adapter_handle;

	unsigned char *cmac;
	unsigned char *ctr;
	unsigned char *iv;

	set_verbosity(argc, argv);

	/* Skip test if stats are not counted. */
	ptr = getenv(ICA_STATS_ENV);
	if (ptr && sscanf(ptr, "%i", &value) == 1 && !value)
		exit(TEST_SKIP);

	if((cmac = malloc(AES_CIPHER_BLOCK*sizeof(char))) == NULL){
		perror("Error in malloc: ");
		exit(TEST_FAIL);
	}
	if((ctr = malloc(AES_CIPHER_BLOCK*sizeof(char))) == NULL){
		perror("Error in malloc: ");
		exit(TEST_FAIL);
	}

	if((iv = malloc(AES_CIPHER_BLOCK*sizeof(char))) == NULL){
		perror("Error in malloc: ");
		exit(TEST_FAIL);
	}

	  /*
	 * Open crypto adapter
	 **/
	rc = ica_open_adapter(&adapter_handle);
	if (rc != 0) {
		V_(printf("ica_open_adapter failed and returned %d (0x%x).\n", rc, rc));
	}

	create_hw_info();


	  /*
	 * Reset Counters
	 **/
	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));
	rc = ica_random_number_generate(AES_CIPHER_BLOCK, ctr);
	if (rc)
		exit(handle_ica_error(rc, "ica_random_number_generate"));

	  /*
	 * Check if counter for Random operations has incremneted
	 **/
	/* ica_random_number_generate uses ica_drbg if available. Otherwise the
	 * old prng code is used. */
	if (check_hw(SHA512_DRNG) == 1 || check_hw(SHA512) == 1)
		check_icastats(SHA512_DRNG, "DRBG-SHA-512");
	else
		check_icastats(P_RNG, "P_RNG");

	rc = ica_random_number_generate(AES_CIPHER_BLOCK, iv);
	if (rc)
		exit(handle_ica_error(rc, "ica_random_number_generate"));

	  /*
	 * Check counters for all crypto operations
	 **/
	des_tests(iv, cmac, ctr);
	tdes_tests(iv, cmac, ctr);
	sha_tests();
	rsa_tests(adapter_handle);
	aes_tests(iv, cmac, ctr);

	free(cmac);
	free(ctr);
	free(iv);

	printf("All icastats tests passed.\n");
	return TEST_SUCC;
}


int is_crypto_card_loaded()
{
	DIR* sysDir;
	FILE *file;
	char dev[PATH_MAX] = "/sys/devices/ap/";
	struct dirent *direntp;
	char *type = NULL;
	size_t size;
	char c;

	if ((sysDir = opendir(dev)) == NULL )
		return 0;

	while((direntp = readdir(sysDir)) != NULL){
		if(strstr(direntp->d_name, "card") != 0){
			snprintf(dev, PATH_MAX, "/sys/devices/ap/%s/type",
				 direntp->d_name);

			if ((file = fopen(dev, "r")) == NULL){
				closedir(sysDir);
				return 0;
			}

			if (getline(&type, &size, file) == -1){
				fclose(file);
				closedir(sysDir);
				return 0;
			}

			/* ignore \n
			 * looking for CEX??A and CEX??C
			 * Skip type CEX??P cards
			 **/
			if (type[strlen(type)-2] == 'P'){
				free(type);
				type = NULL;
				fclose(file);
				continue;
			}
			free(type);
			type = NULL;
			fclose(file);

			snprintf(dev, PATH_MAX, "/sys/devices/ap/%s/online",
				direntp->d_name);
			if ((file = fopen(dev, "r")) == NULL){
				closedir(sysDir);
				return 0;
			}
			if((c = fgetc(file)) == '1'){
				fclose(file);
				return 1;
			}
			fclose(file);
		}
	}
	closedir(sysDir);
	return 0;
}

/*
 * Create Hardware Info database
 **/
void create_hw_info()
{
	if (ica_get_functionlist(NULL, &mech_len) != 0){
		perror("get_functionlist: ");
		exit(TEST_FAIL);
	}
	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (ica_get_functionlist(pmech_list, &mech_len) != 0){
		perror("get_functionlist: ");
		free(pmech_list);
		exit(TEST_FAIL);
	}

	hw_flag = is_crypto_card_loaded();
}

/*
 * check if a cryptp operation is supported in hardware
 **/
int check_hw(unsigned int algo_id)
{
	int i;
	for (i = mech_len - 1; i >= 0; i--)
		if (pmech_list[i].mech_mode_id == algo_id)
			break;
	if (i < 0) return -1;

	if (hw_flag) {
		if(pmech_list[i].flags & (ICA_FLAG_SHW | ICA_FLAG_DHW))
			return 1;
		else
			return 0;
	} else {
		if(pmech_list[i].flags & ICA_FLAG_SHW)
			return 1;
		else
			return 0;
	}
}

/*
 * Check if icastats has counted correctly
 **/
void check_icastats(int algo_id, char *stat)
{
	char cmd[256], line[256], *p;
	FILE *f;
	int i, hw, rc=-1, counters=0;
	int hwcounter1=0, hwcounter2=0, swcounter1=0, swcounter2=0;

	hw = check_hw(algo_id);
	if (hw < 0) return; /* unknown algo_id */

	sprintf(cmd, "icastats | grep '%s'", stat);
	f = popen(cmd, "r");
	if (!f) {
		perror("error in peopen");
		exit(TEST_FAIL);
	}
	if (fgets(line, sizeof(line), f) == NULL) {
		perror("error in fgets");
		exit(TEST_FAIL);
	}
	pclose(f);

	/* remove trailing whitespace from the line */
	i = strlen(line);
	while (i > 0 && isspace(line[i-1])) {
		line[i-1] = 0;
		i--;
	}

	p = strstr(line, "|");
	if (!p) goto out; /* no | in the output. Wrong algo string ? */
	p++;
	while (isspace(*p)) p++;
	hwcounter1 = atoi(p); /* parse 1st hw counter value */
	counters++;
	while (*p && !isspace(*p)) p++; /* parse over counter value */
	while (isspace(*p)) p++;
	/* now either a | or another counter value follows */
	if (isdigit(*p)) {
		hwcounter2 = atoi(p); /* parse 2nd hw counter value */
		counters++;
		while (*p && !isspace(*p)) p++; /* parse over counter value */
		while (isspace(*p)) p++;
	}
	/* now there should be a | */
	if (*p != '|') {
		V_(fprintf(stderr, "parse error, missing '|' in line '%s'\n", line));
		goto out;
	}
	p++;
	while (isspace(*p)) p++;
	swcounter1 = atoi(p); /* parse 1st sw counter value */
	counters++;
	while (*p && !isspace(*p)) p++; /* parse over counter value */
	while (isspace(*p)) p++;
	/* maybe another counter value follows */
	if (isdigit(*p)) {
		swcounter2 = atoi(p); /* parse 2nd sw counter value */
		counters++;
	}

	/* counters should be 2 or 4 now */
	if (counters == 2) {
		if (hw) {
			/* hwcounter1 should be > 0 */
			if (hwcounter1 > 0)
				rc = 0;
			else
				goto out;
		} else {
			/* swcounter1 should be > 0 */
			if (swcounter1 > 0)
				rc = 0;
			else
				goto out;
		}
	} else if (counters == 4) {
		if (hw) {
			/* hwcounter1 or hwcounter2 should be > 0 */
			if (hwcounter1 > 0 || hwcounter2 > 0)
				rc = 0;
			else
				goto out;
		} else {
			/* swcounter1 or swcounter2 should be > 0 */
			if (swcounter1 > 0 || swcounter2 > 0)
				rc = 0;
			else
				goto out;
		}
	} else {
		V_(printf("parse error, could not parse 2 or 4 counter values\n"));
		goto out;
	}
out:
	if (rc == 0) {
		V_(printf("Test %s SUCCESS.\n", stat));
	} else {
		printf("icastats %s test FAILED!\n", stat);
		V_(printf("icastats line for %s was '%s'\n", stat, line));
		exit(TEST_FAIL);
	}
}

static int handle_ica_error(int rc, char *message)
{
	printf("Error in %s: ", message);
	switch (rc) {
		case 0:
		  V_(printf("OK\n"));
		  break;
		case EINVAL:
		  V_(printf("Incorrect parameter.\n"));
		  break;
		case ENODEV:
		  V_(printf("No hardware device available.\n"));
		  break;
		case EPERM:
		  V_(printf("Operation not permitted by Hardware.\n"));
		  break;
		case EIO:
		  V_(printf("I/O error.\n"));
		  break;
		default:
		  V_(perror(""));
	}
	return TEST_FAIL;
}



void des_tests(unsigned char *iv, unsigned char *cmac, unsigned char *ctr)
{
	int rc = 0;
	int mode;
	unsigned char *out_buffer;
	unsigned char *inp_buffer = plain_data;
	unsigned char des_key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	};

#ifdef ICA_FIPS
	if (ica_fips_status() & ICA_FIPS_MODE) {
		V_(printf("All icastats DES tests skipped."
		    " (DES not FIPS approved)\n"));
		return;
	}
#endif /* ICA_FIPS */

	if((out_buffer = malloc(DATA_LENGHT*sizeof(char))) == NULL){
		perror("Error in malloc: ");
		exit(TEST_FAIL);
	}


	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_des_ecb(inp_buffer, out_buffer, DATA_LENGHT,
				 des_key, mode);
		if (rc)
			exit(handle_ica_error(rc, "ica_des_ecb"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES_ECB, "DES ECB");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_des_cbc(inp_buffer, out_buffer, DATA_LENGHT,
				 des_key, iv, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_des_ecb"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES_CBC, "DES CBC");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_des_cfb(inp_buffer, out_buffer, DATA_LENGHT,
				 des_key, iv, DES_CIPHER_BLOCK, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_des_cfb"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES_CFB, "DES CFB");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_des_cmac(inp_buffer, DATA_LENGHT, cmac, DES_CIPHER_BLOCK,
				  des_key, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_des_cmac"));
	}
	check_icastats(DES_CMAC, "DES CMAC");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_des_ctr(inp_buffer, out_buffer, DATA_LENGHT, des_key,
				 ctr, DES_CIPHER_BLOCK, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_des_ctr"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES_CTR, "DES CTR");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc =  ica_des_ofb(inp_buffer, out_buffer, DATA_LENGHT,
				  des_key, iv, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_des_ofb"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES_OFB, "DES OFB");

	free(out_buffer);
}

void tdes_tests(unsigned char *iv, unsigned char *cmac, unsigned char *ctr)
{
	int rc = 0;
	int mode;
	unsigned char *out_buffer;
	unsigned char *inp_buffer = plain_data;
	unsigned char des_key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	};

	if((out_buffer = malloc(DATA_LENGHT*sizeof(char))) == NULL){
		perror("Error in malloc: ");
		exit(TEST_FAIL);
	}

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_3des_ecb(inp_buffer, out_buffer, DATA_LENGHT,
				 des_key, mode);
		if (rc)
			exit(handle_ica_error(rc, "ica_3des_ecb"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES3_ECB, "3DES ECB");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_3des_cbc(inp_buffer, out_buffer, DATA_LENGHT,
				 des_key, iv, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_3des_cbc"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES3_CBC, "3DES CBC");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_3des_cfb(inp_buffer, out_buffer, DATA_LENGHT,
				 des_key, iv, DES_CIPHER_BLOCK, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_3des_cfb"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES3_CFB, "3DES CFB");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_3des_cmac(inp_buffer, DATA_LENGHT, cmac, DES_CIPHER_BLOCK,
				  des_key, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_3des_cmac"));
	}
	check_icastats(DES3_CMAC, "3DES CMAC");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc = ica_3des_ctr(inp_buffer, out_buffer, DATA_LENGHT, des_key,
				 ctr, DES_CIPHER_BLOCK, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_3des_ctr"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES3_CTR, "3DES CTR");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1; mode >= 0; mode--){
		rc =  ica_3des_ofb(inp_buffer, out_buffer, DATA_LENGHT,
				  des_key, iv, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_3des_ofb"));

		if(mode == ICA_ENCRYPT)
			inp_buffer = out_buffer;
		else if(mode == ICA_DECRYPT)
			inp_buffer = plain_data;
	}
	check_icastats(DES3_OFB, "3DES OFB");

	free(out_buffer);
}

#define SHA3_PARMBLOCK_LENGTH     200
#define SHAKE128_64_HASH_LENGTH    64
#define SHAKE256_256_HASH_LENGTH  256

void sha_tests()
{
	int rc = 0;
	unsigned char hash[SHA512_HASH_LENGTH];
	unsigned char shake[SHAKE256_256_HASH_LENGTH];

	sha_context_t sha_context0;
	sha256_context_t sha_context1;
	sha512_context_t sha_context2;
	sha3_224_context_t sha3_224_context;
	sha3_256_context_t sha3_256_context;
	sha3_384_context_t sha3_384_context;
	sha3_512_context_t sha3_512_context;
	shake_128_context_t shake_128_context;
	shake_256_context_t shake_256_context;

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	rc = ica_sha1(SHA_MSG_PART_ONLY, DATA_LENGHT,
		      plain_data, &sha_context0, hash);
	if(rc)
		exit(handle_ica_error(rc, "ica_sha1"));
	check_icastats(SHA1, "SHA-1");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	rc = ica_sha224(SHA_MSG_PART_ONLY, DATA_LENGHT,
			plain_data, &sha_context1, hash);
	if(rc)
		exit(handle_ica_error(rc, "ica_sha224"));
	check_icastats(SHA224, "SHA-224");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	rc = ica_sha256(SHA_MSG_PART_ONLY, DATA_LENGHT,
			plain_data, &sha_context1, hash);
	if(rc)
		exit(handle_ica_error(rc, "ica_sha256"));
	check_icastats(SHA256, "SHA-256");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	rc = ica_sha384(SHA_MSG_PART_ONLY, DATA_LENGHT,
			plain_data, &sha_context2, hash);
	if(rc)
		exit(handle_ica_error(rc, "ica_sha384"));
	check_icastats(SHA384, "SHA-384");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	rc = ica_sha512(SHA_MSG_PART_ONLY, DATA_LENGHT,
			plain_data, &sha_context2, hash);
	if(rc)
		exit(handle_ica_error(rc, "ica_sha512"));
	check_icastats(SHA512, "SHA-512");

	if (check_hw(SHA3_224)) {
		rc = system("icastats -r");
		if (rc == -1)
			exit(handle_ica_error(rc, "system"));

		rc = ica_sha3_224(SHA_MSG_PART_ONLY, DATA_LENGHT,
				plain_data, &sha3_224_context, hash);
		if(rc)
			exit(handle_ica_error(rc, "ica_sha3_224"));
		check_icastats(SHA3_224, "SHA3-224");

		rc = system("icastats -r");
		if (rc == -1)
			exit(handle_ica_error(rc, "system"));

		rc = ica_sha3_256(SHA_MSG_PART_ONLY, DATA_LENGHT,
				plain_data, &sha3_256_context, hash);
		if(rc)
			exit(handle_ica_error(rc, "ica_sha3_256"));
		check_icastats(SHA3_256, "SHA3-256");

		rc = system("icastats -r");
		if (rc == -1)
			exit(handle_ica_error(rc, "system"));

		rc = ica_sha3_384(SHA_MSG_PART_ONLY, DATA_LENGHT,
				plain_data, &sha3_384_context, hash);
		if(rc)
			exit(handle_ica_error(rc, "ica_sha3_384"));
		check_icastats(SHA3_384, "SHA3-384");

		rc = system("icastats -r");
		if (rc == -1)
			exit(handle_ica_error(rc, "system"));

		rc = ica_sha3_512(SHA_MSG_PART_ONLY, DATA_LENGHT,
				plain_data, &sha3_512_context, hash);
		if(rc)
			exit(handle_ica_error(rc, "ica_sha3_512"));
		check_icastats(SHA3_512, "SHA3-512");

		rc = system("icastats -r");
		if (rc == -1)
			exit(handle_ica_error(rc, "system"));

		rc = ica_shake_128(SHA_MSG_PART_ONLY, DATA_LENGHT,
				plain_data, &shake_128_context, shake,
				SHAKE128_64_HASH_LENGTH);
		if(rc)
			exit(handle_ica_error(rc, "ica_shake_128"));
		check_icastats(SHAKE128, "SHAKE-128");

		rc = system("icastats -r");
		if (rc == -1)
			exit(handle_ica_error(rc, "system"));

		rc = ica_shake_256(SHA_MSG_PART_ONLY, DATA_LENGHT,
					plain_data, &shake_256_context, shake,
					SHAKE256_256_HASH_LENGTH);
		if(rc)
			exit(handle_ica_error(rc, "ica_shake_256"));
		check_icastats(SHAKE256, "SHAKE-256");

	}
}

void rsa_tests(ica_adapter_handle_t handle)
{

unsigned char e[] =
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 };

unsigned char n[] =
		  { 0xec, 0x51, 0xab, 0xa1, 0xf8, 0x40, 0x2c, 0x08,
		    0x2e, 0x24, 0x52, 0x2e, 0x3c, 0x51, 0x6d, 0x98,
		    0xad, 0xee, 0xc7, 0x7d, 0x00, 0xaf, 0xe1, 0xa8,
		    0x61, 0xda, 0x32, 0x97, 0xb4, 0x32, 0x97, 0xe3,
		    0x52, 0xda, 0x28, 0x45, 0x55, 0xc6, 0xb2, 0x46,
		    0x65, 0x1b, 0x02, 0xcb, 0xbe, 0xf4, 0x2c, 0x6b,
		    0x2a, 0x5f, 0xe1, 0xdf, 0xe9, 0xe3, 0xbc, 0x47,
		    0xb7, 0x38, 0xb5, 0xa2, 0x78, 0x9d, 0x15, 0xe2,
		    0x59, 0x81, 0x77, 0x6b, 0x6b, 0x2e, 0xa9, 0xdb,
		    0x13, 0x26, 0x9c, 0xca, 0x5e, 0x0a, 0x1f, 0x3c,
		    0x50, 0x9d, 0xd6, 0x79, 0x59, 0x99, 0x50, 0xe5,
		    0x68, 0x1a, 0x98, 0xca, 0x11, 0xce, 0x37, 0x63,
		    0x58, 0x22, 0x40, 0x19, 0x29, 0x72, 0x4c, 0x41,
		    0x89, 0x0b, 0x56, 0x9e, 0x3e, 0xd5, 0x6d, 0x75,
		    0x9e, 0x3f, 0x8a, 0x50, 0xf1, 0x0a, 0x59, 0x4a,
		    0xc3, 0x59, 0x4b, 0xf6, 0xbb, 0xc9, 0xa5, 0x93 };

unsigned char input_data[] =
		  { 0x00, 0x02, 0x08, 0x68, 0x30, 0x9a, 0x32, 0x08,
		    0x57, 0xb0, 0x28, 0xaa, 0x76, 0x30, 0x3d, 0x84,
		    0x5f, 0x92, 0x0d, 0x8e, 0x34, 0xe0, 0xd5, 0xcc,
		    0x36, 0x97, 0xed, 0x00, 0x00, 0x01, 0x02, 0x03,
		    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
		    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
		    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
		    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
		    0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
		    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		    0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43,
		    0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
		    0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
		    0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
		    0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63 };

unsigned char p[] =
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0xfb, 0xb7, 0x73, 0x24, 0x42, 0xfe, 0x8f, 0x16,
		    0xf0, 0x6e, 0x2d, 0x86, 0x22, 0x46, 0x79, 0xd1,
		    0x58, 0x6f, 0x26, 0x24, 0x17, 0x12, 0xa3, 0x1a,
		    0xfd, 0xf7, 0x75, 0xd4, 0xcd, 0xf9, 0xde, 0x4b,
		    0x8c, 0xb7, 0x04, 0x5d, 0xd9, 0x18, 0xc8, 0x26,
		    0x61, 0x54, 0xe0, 0x92, 0x2f, 0x47, 0xf7, 0x33,
		    0xc2, 0x17, 0xd8, 0xda, 0xe0, 0x6d, 0xb6, 0x30,
		    0xd6, 0xdc, 0xf9, 0x6a, 0x4c, 0xa1, 0xa2, 0x4b };

unsigned char q[] =
		  { 0xf0, 0x57, 0x24, 0xf6, 0x2a, 0x5a, 0x6d, 0x8e,
		    0xb8, 0xc6, 0x6f, 0xd2, 0xbb, 0x36, 0x4f, 0x6d,
		    0xd8, 0xbc, 0xa7, 0x2f, 0xbd, 0x43, 0xdc, 0x9a,
		    0x0e, 0x2a, 0x36, 0xb9, 0x21, 0x05, 0xfa, 0x22,
		    0x6c, 0xe8, 0x22, 0x68, 0x2f, 0x1c, 0xe8, 0x27,
		    0xc1, 0xed, 0x08, 0x7a, 0x43, 0x70, 0x7b, 0xe3,
		    0x46, 0x74, 0x02, 0x6e, 0xb2, 0xb1, 0xeb, 0x44,
		    0x72, 0x86, 0x0d, 0x55, 0x3b, 0xc8, 0xbc, 0xd9 };

unsigned char dp[] =
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0xa7, 0xcf, 0xa2, 0x18, 0x2c, 0xa9, 0xb4, 0xb9,
		    0xf5, 0x9e, 0xc9, 0x04, 0x16, 0xd9, 0xa6, 0x8b,
		    0x90, 0x4a, 0x19, 0x6d, 0x64, 0xb7, 0x17, 0x67,
		    0x53, 0xfa, 0x4e, 0x8d, 0xde, 0xa6, 0x94, 0x32,
		    0x5d, 0xcf, 0x58, 0x3e, 0x90, 0xbb, 0x30, 0x19,
		    0x96, 0x38, 0x95, 0xb6, 0xca, 0x2f, 0xfa, 0x22,
		    0x81, 0x65, 0x3b, 0x3c, 0x95, 0x9e, 0x79, 0x75,
		    0xe4, 0x93, 0x50, 0xf1, 0x88, 0x6b, 0xc1, 0x87 };

unsigned char dq[] =
		  { 0xa0, 0x3a, 0x18, 0xa4, 0x1c, 0x3c, 0x49, 0x09,
		    0xd0, 0x84, 0x4a, 0x8c, 0x7c, 0xce, 0xdf, 0x9e,
		    0x90, 0x7d, 0xc4, 0xca, 0x7e, 0x2d, 0x3d, 0xbc,
		    0x09, 0x71, 0x79, 0xd0, 0xc0, 0xae, 0xa6, 0xc1,
		    0x9d, 0xf0, 0x16, 0xf0, 0x1f, 0x68, 0x9a, 0xc5,
		    0x2b, 0xf3, 0x5a, 0xfc, 0x2c, 0xf5, 0xa7, 0xec,
		    0xd9, 0xa2, 0xac, 0x49, 0xcc, 0x76, 0x9c, 0xd8,
		    0x4c, 0x59, 0x5e, 0x38, 0xd2, 0x85, 0xd3, 0x3b };

unsigned char qinv[] =
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x83, 0xf1, 0xca, 0x06, 0x58, 0x4a, 0x04, 0x5e,
		    0x96, 0xb5, 0x30, 0x32, 0x40, 0x36, 0x48, 0xb9,
		    0x02, 0x0c, 0xe3, 0x37, 0xb7, 0x51, 0xbc, 0x22,
		    0x26, 0x5d, 0x74, 0x03, 0x47, 0xd3, 0x33, 0x20,
		    0x8e, 0x75, 0x62, 0xf2, 0x9d, 0x4e, 0xc8, 0x7d,
		    0x5d, 0x8e, 0xb6, 0xd9, 0x69, 0x4a, 0x9a, 0xe1,
		    0x36, 0x6e, 0x1c, 0xbe, 0x8a, 0x14, 0xb1, 0x85,
		    0x39, 0x74, 0x7c, 0x25, 0xd8, 0xa4, 0x4f, 0xde };

	unsigned char *output_data;
	unsigned char *data = input_data;
	int rc = 0;

	if((output_data = malloc(RSA_BYTE_LENGHT*sizeof(char))) == NULL){
		perror("error in malloc: ");
		exit(TEST_FAIL);
	}

	ica_rsa_key_mod_expo_t mod_expo_key= {RSA_BYTE_LENGHT, n, e};
	ica_rsa_key_crt_t crt_key = {RSA_BYTE_LENGHT, p, q, dp, dq, qinv};

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	rc = ica_rsa_mod_expo(handle, data, &mod_expo_key,
			      output_data);
	if(rc)
		exit(handle_ica_error(rc, "ica_rsa_key_mod_expo"));
	check_icastats(RSA_ME, "RSA-ME");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	rc = ica_rsa_crt(handle, data, &crt_key,
			 output_data);
	if(rc)
		exit(handle_ica_error(rc, "ica_rsa_crt"));
	check_icastats(RSA_CRT, "RSA-CRT");

	free(output_data);
}

void aes_tests(unsigned char *iv, unsigned char *cmac, unsigned char *ctr)
{
	int rc = 0;
	int mode;
	unsigned char *output_buffer, *tag, *nonce;
	unsigned char *input_buffer = plain_data;



	unsigned char aes_key[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,

	};
	unsigned char aes_key2[] = {
		0x2c, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,

	};

	unsigned char tweak[] = {
		0x72, 0xf3, 0xb0, 0x54, 0xcb, 0xdc, 0x2f, 0x9e,
		0x3c, 0x5b, 0xc5, 0x51, 0xd4, 0x4d, 0xdb, 0xa0,
	};

	#define NONCE_LENGHT 10

	if((nonce = malloc(NONCE_LENGHT*sizeof(char))) == NULL){
		perror("Error in malloc: ");
		exit(TEST_FAIL);
	}

	if((tag = malloc(AES_CIPHER_BLOCK*sizeof(char))) == NULL){
		perror("Error in malloc: ");
		exit(TEST_FAIL);
	}

	if((output_buffer = malloc((DATA_LENGHT+AES_CIPHER_BLOCK)
				   *sizeof(char))) == NULL){
		perror("Error in malloc: ");
		exit(TEST_FAIL);
	}

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1;mode >= 0;mode--){
		rc = ica_aes_cbc(input_buffer, output_buffer, DATA_LENGHT,
				 aes_key, AES_KEY_LEN128, iv, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_aes_cbc"));
		if(mode == ICA_ENCRYPT)
			input_buffer = output_buffer;
		else if(mode == ICA_DECRYPT)
			input_buffer = plain_data;
	}
	check_icastats(AES_CBC, "AES CBC");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1;mode >= 0;mode--){
		rc = ica_aes_cfb(input_buffer, output_buffer, DATA_LENGHT,
				 aes_key, AES_KEY_LEN128, iv, AES_CIPHER_BLOCK,
				 mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_aes_cfb"));

		if(mode == ICA_ENCRYPT)
			input_buffer = output_buffer;
		else if(mode == ICA_DECRYPT)
			input_buffer = plain_data;
	}
	check_icastats(AES_CFB, "AES CFB");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1;mode >= 0;mode--){
		rc = ica_aes_cmac(input_buffer, DATA_LENGHT, cmac,
				  AES_CIPHER_BLOCK, aes_key,
				  AES_KEY_LEN128, mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_aes_cmac"));
	}
	check_icastats(AES_CMAC, "AES CMAC");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1;mode >= 0;mode--){
		rc = ica_aes_ctr(input_buffer, output_buffer, DATA_LENGHT,
				 aes_key, AES_KEY_LEN128, ctr, AES_CIPHER_BLOCK,
				 mode);
		if(rc)
			exit(handle_ica_error(rc, "ica_aes_ctr"));

		if(mode == ICA_ENCRYPT)
			input_buffer = output_buffer;
		else if(mode == ICA_DECRYPT)
			input_buffer = plain_data;
	}
	check_icastats(AES_CTR, "AES CTR");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1;mode >= 0;mode--){
		rc = ica_aes_ecb(input_buffer, output_buffer, DATA_LENGHT,
				 aes_key, AES_KEY_LEN128, mode);
		if (rc)
			exit(handle_ica_error(rc, "ica_aes_ecb"));

		if(mode == ICA_ENCRYPT)
			input_buffer = output_buffer;
		else if(mode == ICA_DECRYPT)
			input_buffer = plain_data;
	}
	check_icastats(AES_ECB, "AES ECB");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1;mode >= 0;mode--){
		rc = ica_aes_ofb(input_buffer, output_buffer, DATA_LENGHT,
				 aes_key, AES_KEY_LEN128, iv, mode);

		if(rc)
			exit(handle_ica_error(rc, "ica_aes_ofb"));

		if(mode == ICA_ENCRYPT)
			input_buffer = output_buffer;
		else if(mode == ICA_DECRYPT)
			input_buffer = plain_data;
	}
	check_icastats(AES_OFB, "AES OFB");

	rc = system("icastats -r");
	if (rc == -1)
		exit(handle_ica_error(rc, "system"));

	for(mode = 1;mode >= 0;mode--){
		rc = ica_aes_xts(input_buffer, output_buffer, DATA_LENGHT,
				 aes_key, aes_key2, AES_KEY_LEN128, tweak,
				 mode);

		if(rc)
			exit(handle_ica_error(rc, "ica_aes_xts"));

		if(mode == ICA_ENCRYPT)
			input_buffer = output_buffer;
		else if(mode == ICA_DECRYPT)
			input_buffer = plain_data;
	}
	check_icastats(AES_XTS, "AES XTS");

	free(tag);
	free(output_buffer);
	free(nonce);
}

