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

#define NR_TESTS 1
#define NR_RANDOM_TESTS 10000

/* CBC data - 1 for DES128 */
unsigned char NIST_KEY_CBC_E1[] = {
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
};

unsigned char NIST_IV_CBC_E1[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

unsigned char NIST_EXPECTED_IV_CBC_E1[] = {
	0x95, 0xf8, 0xa5, 0xe5, 0xdd, 0x31, 0xd9, 0x00,
};

unsigned char NIST_TEST_DATA_CBC_E1[] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

unsigned char NIST_TEST_RESULT_CBC_E1[] = {
	0x95, 0xf8, 0xa5, 0xe5, 0xdd, 0x31, 0xd9, 0x00,
};


void dump_array(unsigned char *ptr, unsigned int size)
{
	unsigned char *ptr_end;
	unsigned char *h;
	int i = 1;

	h = ptr;
	ptr_end = ptr + size;
	while (h < (unsigned char *)ptr_end) {
		printf("0x%02x ",(unsigned char ) *h);
		h++;
		if (i == 8) {
			printf("\n");
			i = 1;
		} else {
			++i;
		}
	}
	printf("\n");
}

void dump_cbc_data(unsigned char *iv, unsigned int iv_length,
                   unsigned char *key, unsigned int key_length,
                   unsigned char *input_data, unsigned int data_length,
                   unsigned char *output_data)
{
	printf("IV \n");
	dump_array(iv, iv_length);
	printf("Key \n");
	dump_array(key, key_length);
	printf("Input Data\n");
	dump_array(input_data, data_length);
	printf("Output Data\n");
	dump_array(output_data, data_length);
}

void get_sizes(unsigned int *data_length, unsigned int *iv_length,
	       unsigned int *key_length, unsigned int iteration)
{
	switch (iteration) {
		case 1:
			*data_length = sizeof(NIST_TEST_DATA_CBC_E1);
			*iv_length = sizeof(NIST_IV_CBC_E1);
			*key_length = sizeof(NIST_KEY_CBC_E1);
			break;
	}

}

void load_test_data(unsigned char *data, unsigned int data_length,
		    unsigned char *result,
		    unsigned char *iv, unsigned char *expected_iv,
		    unsigned int iv_length,
		    unsigned char *key, unsigned int key_length,
		    unsigned int iteration)
{
	switch (iteration) {
		case 1:
			memcpy(data, NIST_TEST_DATA_CBC_E1, data_length);
			memcpy(result, NIST_TEST_RESULT_CBC_E1, data_length);
			memcpy(iv, NIST_IV_CBC_E1, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CBC_E1, iv_length);
			memcpy(key, NIST_KEY_CBC_E1, key_length);
			break;
	}

}

int kat_des_cbc(int iteration, int silent)
{
	unsigned int data_length;
	unsigned int iv_length;
	unsigned int key_length;

	get_sizes(&data_length, &iv_length, &key_length, iteration);

	printf("Test Parameters for iteration = %i\n", iteration);
	printf("key length = %i, data length = %i, iv length = %i\n",
	       key_length, data_length, iv_length);

	unsigned char iv[iv_length];
	unsigned char tmp_iv[iv_length];
	unsigned char expected_iv[iv_length];
	unsigned char key[key_length];
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];
	unsigned char result[data_length];

	int rc = 0;

	load_test_data(input_data, data_length, result, iv, expected_iv,
		       iv_length, key, key_length, iteration);
	memcpy(tmp_iv, iv, iv_length);

	rc = ica_des_cbc(input_data, encrypt, data_length, key, tmp_iv, 1);
	if (rc) {
		printf("ica_des_cbc encrypt failed with rc = %i\n", rc);
		dump_cbc_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!silent && !rc) {
		printf("Encrypt:\n");
		dump_cbc_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}

	if (memcmp(result, encrypt, data_length)) {
		printf("Encryption Result does not match the known ciphertext!\n");
		printf("Expected data:\n");
		dump_array(result, data_length);
		printf("Encryption Result:\n");
		dump_array(encrypt, data_length);
		rc++;
	}

	if (memcmp(expected_iv, tmp_iv, iv_length)) {
		printf("Update of IV does not match the expected IV!\n");
		printf("Expected IV:\n");
		dump_array(expected_iv, iv_length);
		printf("Updated IV:\n");
		dump_array(tmp_iv, iv_length);
		printf("Original IV:\n");
		dump_array(iv, iv_length);
		rc++;
	}
	if (rc) {
		printf("DES CBC test exited after encryption\n");
		return rc;
	}

	memcpy(tmp_iv, iv, iv_length);
	rc = ica_des_cbc(encrypt, decrypt, data_length, key, tmp_iv, 0);
	if (rc) {
		printf("ica_des_cbc decrypt failed with rc = %i\n", rc);
		dump_cbc_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
		return rc;
	}


	if (!silent && !rc) {
		printf("Decrypt:\n");
		dump_cbc_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
	}

	if (memcmp(decrypt, input_data, data_length)) {
		printf("Decryption Result does not match the original data!\n");
		printf("Original data:\n");
		dump_array(input_data, data_length);
		printf("Decryption Result:\n");
		dump_array(decrypt, data_length);
		rc++;
	}
	return rc;
}

int load_random_test_data(unsigned char *data, unsigned int data_length,
		    	   unsigned char *iv, unsigned int iv_length,
		    	   unsigned char *key, unsigned int key_length)
{
	int rc;
	rc = ica_random_number_generate(data_length, data);
	if (rc) {
		printf("ica_random_number_generate with rc = %i errnor = %i\n",
		       rc, errno);
		return rc;
	}
	rc = ica_random_number_generate(iv_length, iv);
	if (rc) {
		printf("ica_random_number_generate with rc = %i errnor = %i\n",
		       rc, errno);
		return rc;
	}
	rc = ica_random_number_generate(key_length, key);
	if (rc) {
		printf("ica_random_number_generate with rc = %i errnor = %i\n",
		       rc, errno);
		return rc;
	}
	return rc;
}

int random_des_cbc(int iteration, int silent, unsigned int data_length)
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

	printf("Test Parameters for iteration = %i\n", iteration);
	printf("key length = %i, data length = %i, iv length = %i\n",
	       key_length, data_length, iv_length);

	rc = ica_des_cbc(input_data, encrypt, data_length, key, tmp_iv, 1);
	if (rc) {
		printf("ica_des_cbc encrypt failed with rc = %i\n", rc);
		dump_cbc_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!silent && !rc) {
		printf("Encrypt:\n");
		dump_cbc_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}

	if (rc) {
		printf("DES CBC test exited after encryption\n");
		return rc;
	}

	memcpy(tmp_iv, iv, iv_length);

	rc = ica_des_cbc(encrypt, decrypt, data_length, key, tmp_iv, 0);
	if (rc) {
		printf("ica_des_cbc decrypt failed with rc = %i\n", rc);
		dump_cbc_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
		return rc;
	}


	if (!silent && !rc) {
		printf("Decrypt:\n");
		dump_cbc_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
	}

	if (memcmp(decrypt, input_data, data_length)) {
		printf("Decryption Result does not match the original data!\n");
		printf("Original data:\n");
		dump_array(input_data, data_length);
		printf("Decryption Result:\n");
		dump_array(decrypt, data_length);
		rc++;
	}
	return rc;
}

int main(int argc, char **argv)
{
	// Default mode is 0. ECB,CBC and CFQ tests will be performed.
	unsigned int silent = 0;
	if (argc > 1) {
		if (strstr(argv[1], "silent"))
			silent = 1;
	}
	int rc = 0;
	int error_count = 0;
	int iteration;
	unsigned int data_length = sizeof(ica_des_vector_t);
	for(iteration = 1; iteration <= NR_TESTS; iteration++)	{
		rc = kat_des_cbc(iteration, silent);
		if (rc) {
			printf("kat_des_cbc failed with rc = %i\n", rc);
			error_count++;
		} else
			printf("kat_des_cbc finished successfuly\n");

	}

	for(iteration = 1; iteration <= NR_RANDOM_TESTS; iteration++)	{
		int silent = 1;
		rc = random_des_cbc(iteration, silent, data_length);
		if (rc) {
			printf("random_des_cbc failed with rc = %i\n", rc);
			error_count++;
			goto out;
		} else
			printf("random_des_cbc finished successfuly\n");
		data_length += sizeof(ica_des_vector_t);
	}
out:
	if (error_count)
		printf("%i testcases failed\n", error_count);
	else
		printf("All testcases finished successfully\n");

	return rc;
}

