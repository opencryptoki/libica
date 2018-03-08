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

#define NR_RANDOM_TESTS 1000

void dump_ctr_data(unsigned char *iv, unsigned int iv_length,
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

int random_3des_ctr(int iteration, unsigned int data_length)
{
	unsigned int key_length = sizeof(ica_des_key_triple_t);
	unsigned int iv_length = sizeof(ica_des_vector_t);

	unsigned char iv[iv_length];
	unsigned char tmp_iv[iv_length];
	unsigned char key[key_length];
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];

	int rc = 0;

	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i, iv length = %i\n",
	    key_length, data_length, iv_length));

	rc = ica_random_number_generate(data_length, input_data);
	if (rc) {
		VV_(printf("random number generate returned rc = %i, errno = %i\n", rc, errno));
		return TEST_FAIL;
	}
	rc = ica_random_number_generate(iv_length, iv);
	if (rc) {
		VV_(printf("random number generate returned rc = %i, errno = %i\n", rc, errno));
		return TEST_FAIL;
	}

	rc = ica_random_number_generate(key_length, key);
	if (rc) {
		VV_(printf("random number generate returned rc = %i, errno = %i\n", rc, errno));
		return TEST_FAIL;
	}
	memcpy(tmp_iv, iv, iv_length);

	rc = ica_3des_ctr(input_data, encrypt, data_length, key, tmp_iv,
			  32, 1);
	if (rc) {
		VV_(printf("ica_3des_ctr encrypt failed with rc = %i\n", rc));
		dump_ctr_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
		return TEST_FAIL;
	}
	if (!rc) {
		VV_(printf("Encrypt:\n"));
		dump_ctr_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}

	memcpy(tmp_iv, iv, iv_length);
	rc = ica_3des_ctr(encrypt, decrypt, data_length, key, tmp_iv,
			  32, 0);
	if (rc) {
		VV_(printf("ica_3des_ctr decrypt failed with rc = %i\n", rc));
		dump_ctr_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
		return TEST_FAIL;
	}


	if (!rc) {
		VV_(printf("Decrypt:\n"));
		dump_ctr_data(iv, iv_length, key, key_length, encrypt,
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
	unsigned int endless = 0;
	unsigned int data_length = 1;
	unsigned int rdata;
	int error_count = 0;
	int i = 0;
	int rc = 0;

	set_verbosity(argc, argv);
	if (argc > 1) {
		if (strstr(argv[1], "endless"))
			endless = 1;
	}

	if (endless) {
		while (1) {
			VV_(printf("i = %i\n", i));
			rc = random_3des_ctr(i, 320);
			if (rc) {
				VV_(printf("kat_3des_ctr failed with rc = %i\n",
				    rc));
				return TEST_FAIL;
			} else
				VV_(printf("kat_3des_ctr finished.n"));
			i++;
		}
	} else {
		for (i = 1; i < NR_RANDOM_TESTS; i++) {
			rc = random_3des_ctr(i, data_length);
			if (rc) {
				VV_(printf("random_3des_ctr failed with rc = %i\n", rc));
				error_count++;
			}
			// add a value between 1 and 8 to data_length
			if (ica_random_number_generate(sizeof(rdata), (unsigned char*) &rdata)) {
				printf("ica_random_number_generate failed with errnor = %i\n",
				    errno);
				exit(1);
			}
			data_length += (rdata % 8) + 1;
		}
	}

	if (error_count) {
		printf("%i 3DES-CTR tests failed.\n", error_count);
		return TEST_FAIL;
	}

	printf("All 3DES-CTR tests passed.\n");
	return TEST_SUCC;
}

