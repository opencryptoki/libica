/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2010, 2011 */
#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "ica_api.h"
#include "testcase.h"

#define NR_RANDOM_TESTS 10000

void dump_ofb_data(unsigned char *iv, unsigned int iv_length,
		   unsigned char *key, unsigned int key_length,
		   unsigned char *input_data, unsigned int data_length,
		   unsigned char *output_data)
{
	VV_(printf("IV \n"));
	dump_array(iv, iv_length);
	VV_(printf("Key \n"));
	dump_array(key, key_length);
	VV_(printf("Input Data\n"));
	dump_array(input_data, data_length);
	VV_(printf("Output Data\n"));
	dump_array(output_data, data_length);
}

int load_random_test_data(unsigned char *data, unsigned int data_length,
			   unsigned char *iv, unsigned int iv_length,
			   unsigned char *key, unsigned int key_length)
{
	int rc;

	rc = ica_random_number_generate(data_length, data);
	if (rc) {
		VV_(printf("ica_random_number_generate with rc = %i errnor = %i\n",
		       rc, errno));
		return TEST_FAIL;
	}
	rc = ica_random_number_generate(iv_length, iv);
	if (rc) {
		VV_(printf("ica_random_number_generate with rc = %i errnor = %i\n",
		       rc, errno));
		return TEST_FAIL;
	}
	rc = ica_random_number_generate(key_length, key);
	if (rc) {
		VV_(printf("ica_random_number_generate with rc = %i errnor = %i\n",
		       rc, errno));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

int random_des_ofb(int iteration, unsigned int data_length)
{
	unsigned int iv_length = sizeof(ica_des_vector_t);
	unsigned int key_length = sizeof(ica_des_key_single_t);

	unsigned char iv[iv_length];
	unsigned char tmp_iv[iv_length];
	unsigned char key[key_length];
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];

	int rc = 0;

	memset(encrypt, 0x00, data_length);
	memset(decrypt, 0x00, data_length);

	load_random_test_data(input_data, data_length, iv, iv_length, key,
			      key_length);
	memcpy(tmp_iv, iv, iv_length);

	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i, iv length = %i\n",
		key_length, data_length, iv_length));

	rc = ica_des_ofb(input_data, encrypt, data_length, key, tmp_iv, 1);
	if (rc) {
		VV_(printf("ica_des_ofb encrypt failed with rc = %i\n", rc));
		dump_ofb_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!rc) {
		VV_(printf("Encrypt:\n"));
		dump_ofb_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}

	if (rc) {
		VV_(printf("DES OFB test exited after encryption\n"));
		return TEST_FAIL;
	}

	memcpy(tmp_iv, iv, iv_length);

	rc = ica_des_ofb(encrypt, decrypt, data_length, key, tmp_iv, 0);
	if (rc) {
		VV_(printf("ica_des_ofb decrypt failed with rc = %i\n", rc));
		dump_ofb_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
		return TEST_FAIL;
	}

	if (!rc) {
		VV_(printf("Decrypt:\n"));
		dump_ofb_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
	}

	if (memcmp(decrypt, input_data, data_length)) {
		VV_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(input_data, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(decrypt, data_length);
		rc++;
	}

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}

int main(int argc, char **argv)
{
	int rc = 0;
	int error_count = 0;
	int iteration;
	unsigned int rdata;
	unsigned int data_length = 1;

	set_verbosity(argc, argv);

#ifdef ICA_FIPS
	if (ica_fips_status() & ICA_FIPS_MODE) {
		printf("All DES-OFB tests skipped."
		    " (DES not FIPS approved)\n");
		return TEST_SKIP;
	}
#endif /* ICA_FIPS */

	for(iteration = 1; iteration <= NR_RANDOM_TESTS; iteration++)	{
		rc = random_des_ofb(iteration, data_length);
		if (rc) {
			V_(printf("random_des_ofb failed with rc = %i\n", rc));
			error_count++;
			goto out;
		}
		// add a value between 1 and 8 to data_length
		if (ica_random_number_generate(sizeof(rdata), (unsigned char*) &rdata)) {
			printf("ica_random_number_generate failed with errnor = %i\n",
			       errno);
			goto out;
		}
		data_length += (rdata % 8) + 1;
	}
out:
	if (error_count) {
		printf("%i DES-OFB tests failed.\n", error_count);
		return TEST_FAIL;
	}

	printf("All DES-OFB tests passed.\n");
	return TEST_SUCC;
}

