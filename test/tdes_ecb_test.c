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

#define NR_TESTS 2
#define NR_RANDOM_TESTS 10000

/* ECB data - 1 for 3DES192 */
unsigned char NIST_KEY_ECB_E1[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
	0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
};

unsigned char NIST_TEST_DATA_ECB_E1[] = {
	0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20,
};

unsigned char NIST_TEST_RESULT_ECB_E1[] = {
	0xCC, 0xE2, 0x1C, 0x81, 0x12, 0x25, 0x6F, 0xE6,
};

/* ECB data - 2 - for 3DES128 */
unsigned char NIST_KEY_ECB_E2[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
	0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,

};

unsigned char NIST_TEST_DATA_ECB_E2[] = {
	0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x66, 0x63,
	0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20,
	0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70,
};

unsigned char NIST_TEST_RESULT_ECB_E2[] = {
	0xA8, 0x26, 0xFD, 0x8C, 0xE5, 0x3B, 0x85, 0x5F,
	0xCC, 0xE2, 0x1C, 0x81, 0x12, 0x25, 0x6F, 0xE6,
	0x68, 0xD5, 0xC0, 0x5D, 0xD9, 0xB6, 0xB9, 0x00,
};

void dump_ecb_data(unsigned char *key, unsigned int key_length,
		   unsigned char *input_data, unsigned int data_length,
		   unsigned char *output_data)
{
	VV_(printf("Key \n"));
	dump_array(key, key_length);
	VV_(printf("Input Data\n"));
	dump_array(input_data, data_length);
	VV_(printf("Output Data\n"));
	dump_array(output_data, data_length);
}

void get_sizes(unsigned int *data_length,
	       unsigned int *key_length, unsigned int iteration)
{
	switch (iteration) {
		case 1:
			*data_length = sizeof(NIST_TEST_DATA_ECB_E1);
			*key_length = sizeof(NIST_KEY_ECB_E1);
			break;
		case 2:
			*data_length = sizeof(NIST_TEST_DATA_ECB_E2);
			*key_length = sizeof(NIST_KEY_ECB_E2);
			break;
		default:
			*data_length = 0;
			*key_length = 0;
			break;
	}

}

void load_test_data(unsigned char *data, unsigned int data_length,
		    unsigned char *result,
		    unsigned char *key, unsigned int key_length,
		    unsigned int iteration)
{
	switch (iteration) {
		case 1:
			memcpy(data, NIST_TEST_DATA_ECB_E1, data_length);
			memcpy(result, NIST_TEST_RESULT_ECB_E1, data_length);
			memcpy(key, NIST_KEY_ECB_E1, key_length);
			break;
		case 2:
			memcpy(data, NIST_TEST_DATA_ECB_E2, data_length);
			memcpy(result, NIST_TEST_RESULT_ECB_E2, data_length);
			memcpy(key, NIST_KEY_ECB_E2, key_length);
			break;
	}

}

int kat_3des_ecb(int iteration)
{
	unsigned int data_length;
	unsigned int key_length;

	get_sizes(&data_length, &key_length, iteration);

	unsigned char key[key_length];
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];
	unsigned char result[data_length];

	int rc = 0;

	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i", key_length, data_length));

	load_test_data(input_data, data_length, result, key, key_length,
		       iteration);

	rc = ica_3des_ecb(input_data, encrypt, data_length, key, 1);
	if (rc) {
		VV_(printf("ica_3des_ecb encrypt failed with rc = %i\n", rc));
		dump_ecb_data(key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!rc) {
		VV_(printf("Encrypt:\n"));
		dump_ecb_data(key, key_length, input_data,
			      data_length, encrypt);
	}

	if (memcmp(result, encrypt, data_length)) {
		VV_(printf("Encryption Result does not match the known ciphertext!\n"));
		VV_(printf("Expected data:\n"));
		dump_array(result, data_length);
		VV_(printf("Encryption Result:\n"));
		dump_array(encrypt, data_length);
		rc++;
	}

	if (rc) {
		VV_(printf("3DES ECB test exited after encryption\n"));
		return TEST_FAIL;
	}

	rc = ica_3des_ecb(encrypt, decrypt, data_length, key, 0);
	if (rc) {
		VV_(printf("ica_3des_ecb decrypt failed with rc = %i\n", rc));
		dump_ecb_data(key, key_length, encrypt,
			      data_length, decrypt);
		return TEST_FAIL;
	}


	if (!rc) {
		VV_(printf("Decrypt:\n"));
		dump_ecb_data(key, key_length, encrypt,
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

int load_random_test_data(unsigned char *data, unsigned int data_length,
			   unsigned char *key, unsigned int key_length)
{
	int rc;

	rc = ica_random_number_generate(data_length, data);
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

int random_3des_ecb(int iteration, unsigned int data_length)
{
	int rc = 0;
	unsigned int key_length = sizeof(ica_des_key_triple_t);
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];
	unsigned char key[key_length];

	memset(encrypt, 0x00, data_length);
	memset(decrypt, 0x00, data_length);

	load_random_test_data(input_data, data_length, key, key_length);
	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i\n", key_length, data_length));

	rc = ica_3des_ecb(input_data, encrypt, data_length, key, 1);
	if (rc) {
		VV_(printf("ica_3des_ecb encrypt failed with rc = %i\n", rc));
		dump_ecb_data(key, key_length, input_data, data_length,
			      encrypt);
	}
	if (!rc) {
		VV_(printf("Encrypt:\n"));
		dump_ecb_data(key, key_length, input_data,
			      data_length, encrypt);
	}

	if (rc) {
		VV_(printf("3DES ECB test exited after encryption\n"));
		return TEST_FAIL;
	}

	rc = ica_3des_ecb(encrypt, decrypt, data_length, key, 0);
	if (rc) {
		VV_(printf("ica_3des_ecb decrypt failed with rc = %i\n", rc));
		dump_ecb_data(key, key_length, encrypt,
			      data_length, decrypt);
		return TEST_FAIL;
	}


	if (!rc) {
		VV_(printf("Decrypt:\n"));
		dump_ecb_data(key, key_length, encrypt,
			      data_length, decrypt);
	}

	if (memcmp(decrypt, input_data, data_length)) {
		VV_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(input_data, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(decrypt, data_length);
		rc++;
		return TEST_FAIL;
	}

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}

/*
 * Performs ECB and CFQ tests.
 */
int main(int argc, char **argv)
{
	int rc = 0;
	int error_count = 0;
	int iteration;
	unsigned int data_length = sizeof(ica_des_vector_t);

	set_verbosity(argc, argv);

	for(iteration = 1; iteration <= NR_TESTS; iteration++)	{
		rc = kat_3des_ecb(iteration);
		if (rc) {
			V_(printf("kat_3des_ecb failed with rc = %i\n", rc));
			error_count++;
		}
	}

	for(iteration = 1; iteration <= NR_RANDOM_TESTS; iteration++)	{
		rc = random_3des_ecb(iteration, data_length);
		if (rc) {
			V_(printf("random_3des_ecb failed with rc = %i\n", rc));
			error_count++;
			goto out;
		}
		data_length += sizeof(ica_des_vector_t);
	}

out:
	if (error_count) {
		printf("%i 3DES-ECB tests failed.\n", error_count);
		return TEST_FAIL;
	}

	printf("All 3DES-ECB tests passed.\n");
	return TEST_SUCC;
}

