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

#define NR_TESTS 6
#define NR_RANDOM_TESTS 10000

/* OFB data - 1 for AES128 */
unsigned char NIST_KEY_OFB_E1[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

unsigned char NIST_IV_OFB_E1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_EXPECTED_IV_OFB_E1[] = {
	0x50, 0xfe, 0x67, 0xcc, 0x99, 0x6d, 0x32, 0xb6,
	0xda, 0x09, 0x37, 0xe9, 0x9b, 0xaf, 0xec, 0x60,
};

unsigned char NIST_TEST_DATA_OFB_E1[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

unsigned char NIST_TEST_RESULT_OFB_E1[] = {
	0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
	0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
};

/* OFB data - 2 for AES128 */
unsigned char NIST_KEY_OFB_E2[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

unsigned char NIST_IV_OFB_E2[] = {
	0x50, 0xfe, 0x67, 0xcc, 0x99, 0x6d, 0x32, 0xb6,
	0xda, 0x09, 0x37, 0xe9, 0x9b, 0xaf, 0xec, 0x60,
};

unsigned char NIST_EXPECTED_IV_OFB_E2[] = {
	0xd9, 0xa4, 0xda, 0xda, 0x08, 0x92, 0x23, 0x9f,
	0x6b, 0x8b, 0x3d, 0x76, 0x80, 0xe1, 0x56, 0x74,
};

unsigned char NIST_TEST_DATA_OFB_E2[] = {
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};

unsigned char NIST_TEST_RESULT_OFB_E2[] = {
	0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03,
	0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e, 0xd8, 0x25,
};

/* OFB data - 3 - for AES192 */
unsigned char NIST_KEY_OFB_E3[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
	0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};

unsigned char NIST_IV_OFB_E3[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_EXPECTED_IV_OFB_E3[] = {
	0xa6, 0x09, 0xb3, 0x8d, 0xf3, 0xb1, 0x13, 0x3d,
	0xdd, 0xff, 0x27, 0x18, 0xba, 0x09, 0x56, 0x5e,
};

unsigned char NIST_TEST_DATA_OFB_E3[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

unsigned char NIST_TEST_RESULT_OFB_E3[] = {
	0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab,
	0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
};

/* OFB data - 4 - for AES192 */
unsigned char NIST_KEY_OFB_E4[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
	0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};

unsigned char NIST_IV_OFB_E4[] = {
	0xa6, 0x09, 0xb3, 0x8d, 0xf3, 0xb1, 0x13, 0x3d,
	0xdd, 0xff, 0x27, 0x18, 0xba, 0x09, 0x56, 0x5e,
};

unsigned char NIST_EXPECTED_IV_OFB_E4[] = {
	0x52, 0xef, 0x01, 0xda, 0x52, 0x60, 0x2f, 0xe0,
	0x97, 0x5f, 0x78, 0xac, 0x84, 0xbf, 0x8a, 0x50,
};

unsigned char NIST_TEST_DATA_OFB_E4[] = {
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};

unsigned char NIST_TEST_RESULT_OFB_E4[] = {
	0xfc, 0xc2, 0x8b, 0x8d, 0x4c, 0x63, 0x83, 0x7c,
	0x09, 0xe8, 0x17, 0x00, 0xc1, 0x10, 0x04, 0x01,
};

/* OFB data 5 - for AES 256 */
unsigned char NIST_KEY_OFB_E5[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

unsigned char NIST_IV_OFB_E5[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_EXPECTED_IV_OFB_E5[] = {
	0xb7, 0xbf, 0x3a, 0x5d, 0xf4, 0x39, 0x89, 0xdd,
	0x97, 0xf0, 0xfa, 0x97, 0xeb, 0xce, 0x2f, 0x4a,
};

unsigned char NIST_TEST_DATA_OFB_E5[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

unsigned char NIST_TEST_RESULT_OFB_E5[] = {
	0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b,
	0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
};

/* OFB data 6 - for AES 256 */
unsigned char NIST_KEY_OFB_E6[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

unsigned char NIST_IV_OFB_E6[] = {
	0xb7, 0xbf, 0x3a, 0x5d, 0xf4, 0x39, 0x89, 0xdd,
	0x97, 0xf0, 0xfa, 0x97, 0xeb, 0xce, 0x2f, 0x4a,
};

unsigned char NIST_EXPECTED_IV_OFB_E6[] = {
	0xe1, 0xc6, 0x56, 0x30, 0x5e, 0xd1, 0xa7, 0xa6,
	0x56, 0x38, 0x05, 0x74, 0x6f, 0xe0, 0x3e, 0xdc,
};

unsigned char NIST_TEST_DATA_OFB_E6[] = {
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};

unsigned char NIST_TEST_RESULT_OFB_E6[] = {
	0x4f, 0xeb, 0xdc, 0x67, 0x40, 0xd2, 0x0b, 0x3a,
	0xc8, 0x8f, 0x6a, 0xd8, 0x2a, 0x4f, 0xb0, 0x8d,
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

void dump_ofb_data(unsigned char *iv, unsigned int iv_length,
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
			*data_length = sizeof(NIST_TEST_DATA_OFB_E1);
			*iv_length = sizeof(NIST_IV_OFB_E1);
			*key_length = sizeof(NIST_KEY_OFB_E1);
			break;
		case 2:
			*data_length = sizeof(NIST_TEST_DATA_OFB_E2);
			*iv_length = sizeof(NIST_IV_OFB_E2);
			*key_length = sizeof(NIST_KEY_OFB_E2);
			break;
		case 3:
			*data_length = sizeof(NIST_TEST_DATA_OFB_E3);
			*iv_length = sizeof(NIST_IV_OFB_E3);
			*key_length = sizeof(NIST_KEY_OFB_E3);
			break;
		case 4:
			*data_length = sizeof(NIST_TEST_DATA_OFB_E4);
			*iv_length = sizeof(NIST_IV_OFB_E4);
			*key_length = sizeof(NIST_KEY_OFB_E4);
			break;
		case 5:
			*data_length = sizeof(NIST_TEST_DATA_OFB_E5);
			*iv_length = sizeof(NIST_IV_OFB_E5);
			*key_length = sizeof(NIST_KEY_OFB_E5);
			break;
		case 6:
			*data_length = sizeof(NIST_TEST_DATA_OFB_E6);
			*iv_length = sizeof(NIST_IV_OFB_E6);
			*key_length = sizeof(NIST_KEY_OFB_E6);
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
			memcpy(data, NIST_TEST_DATA_OFB_E1, data_length);
			memcpy(result, NIST_TEST_RESULT_OFB_E1, data_length);
			memcpy(iv, NIST_IV_OFB_E1, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_OFB_E1, iv_length);
			memcpy(key, NIST_KEY_OFB_E1, key_length);
			break;
		case 2:
			memcpy(data, NIST_TEST_DATA_OFB_E2, data_length);
			memcpy(result, NIST_TEST_RESULT_OFB_E2, data_length);
			memcpy(iv, NIST_IV_OFB_E2, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_OFB_E2, iv_length);
			memcpy(key, NIST_KEY_OFB_E2, key_length);
			break;
		case 3:
			memcpy(data, NIST_TEST_DATA_OFB_E3, data_length);
			memcpy(result, NIST_TEST_RESULT_OFB_E3, data_length);
			memcpy(iv, NIST_IV_OFB_E3, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_OFB_E3, iv_length);
			memcpy(key, NIST_KEY_OFB_E3, key_length);
			break;
		case 4:
			memcpy(data, NIST_TEST_DATA_OFB_E4, data_length);
			memcpy(result, NIST_TEST_RESULT_OFB_E4, data_length);
			memcpy(iv, NIST_IV_OFB_E4, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_OFB_E4, iv_length);
			memcpy(key, NIST_KEY_OFB_E4, key_length);
			break;
		case 5:
			memcpy(data, NIST_TEST_DATA_OFB_E5, data_length);
			memcpy(result, NIST_TEST_RESULT_OFB_E5, data_length);
			memcpy(iv, NIST_IV_OFB_E5, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_OFB_E5, iv_length);
			memcpy(key, NIST_KEY_OFB_E5, key_length);
			break;
		case 6:
			memcpy(data, NIST_TEST_DATA_OFB_E6, data_length);
			memcpy(result, NIST_TEST_RESULT_OFB_E6, data_length);
			memcpy(iv, NIST_IV_OFB_E6, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_OFB_E6, iv_length);
			memcpy(key, NIST_KEY_OFB_E6, key_length);
			break;
	}

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

int random_aes_ofb(int iteration, int silent, unsigned int data_length)
{
	int i;
	int rc = 0;
	unsigned int iv_length = sizeof(ica_aes_vector_t);
	unsigned int key_length = AES_KEY_LEN128;
	unsigned char iv[iv_length];
	unsigned char tmp_iv[iv_length];
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];
for (i = 0; i <= 2; i++) {

	unsigned char key[key_length];

	memset(encrypt, 0x00, data_length);
	memset(decrypt, 0x00, data_length);

	load_random_test_data(input_data, data_length, iv, iv_length, key,
			      key_length);
	memcpy(tmp_iv, iv, iv_length);
	printf("Test Parameters for iteration = %i\n", iteration);
	printf("key length = %i, data length = %i, iv length = %i\n",
	       key_length, data_length, iv_length);

	rc = ica_aes_ofb(input_data, encrypt, data_length, key, key_length,
			 tmp_iv, 1);
	if (rc) {
		printf("ica_aes_ofb encrypt failed with rc = %i\n", rc);
		dump_ofb_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!silent && !rc) {
		printf("Encrypt:\n");
		dump_ofb_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}

	if (rc) {
		printf("AES OFB test exited after encryption\n");
		return rc;
	}

	memcpy(tmp_iv, iv, iv_length);

	rc = ica_aes_ofb(encrypt, decrypt, data_length, key, key_length,
			 tmp_iv, 0);
	if (rc) {
		printf("ica_aes_ofb decrypt failed with rc = %i\n", rc);
		dump_ofb_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
		return rc;
	}


	if (!silent && !rc) {
		printf("Decrypt:\n");
		dump_ofb_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
	}

	if (memcmp(decrypt, input_data, data_length)) {
		printf("Decryption Result does not match the original data!\n");
		printf("Original data:\n");
		dump_array(input_data, data_length);
		printf("Decryption Result:\n");
		dump_array(decrypt, data_length);
		rc++;
		return rc;
	}
	key_length += 8;
}
	
	return rc;
}

int kat_aes_ofb(int iteration, int silent)
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

	rc = ica_aes_ofb(input_data, encrypt, data_length, key, key_length,
			 tmp_iv, 1);
	if (rc) {
		printf("ica_aes_ofb encrypt failed with rc = %i\n", rc);
		dump_ofb_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!silent && !rc) {
		printf("Encrypt:\n");
		dump_ofb_data(iv, iv_length, key, key_length, input_data,
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
		printf("AES OFB test exited after encryption\n");
		return rc;
	}

	memcpy(tmp_iv, iv, iv_length);
	rc = ica_aes_ofb(encrypt, decrypt, data_length, key, key_length,
			 tmp_iv, 0);
	if (rc) {
		printf("ica_aes_ofb decrypt failed with rc = %i\n", rc);
		dump_ofb_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
		return rc;
	}


	if (!silent && !rc) {
		printf("Decrypt:\n");
		dump_ofb_data(iv, iv_length, key, key_length, encrypt,
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
	unsigned int silent = 0;
	if (argc > 1) {
		if (strstr(argv[1], "silent"))
			silent = 1;
	}
	int rc = 0;
	int error_count = 0;
	int iteration;
	unsigned int data_length = sizeof(ica_aes_vector_t);
	for(iteration = 1; iteration <= NR_TESTS; iteration++)	{
		rc = kat_aes_ofb(iteration, silent);
		if (rc) {
			printf("kat_aes_ofb failed with rc = %i\n", rc);
			error_count++;
		} else
			printf("kat_aes_ofb finished successfuly\n");

	}
	for(iteration = 1; iteration <= NR_RANDOM_TESTS; iteration++)	{
		int silent = 1;
		rc = random_aes_ofb(iteration, silent, data_length);
		if (rc) {
			printf("random_aes_ofb failed with rc = %i\n", rc);
			error_count++;
			goto out;
		} else
			printf("random_aes_ofb finished successfuly\n");
		data_length += sizeof(ica_aes_vector_t);
	}

out:
	if (error_count)
		printf("%i testcases failed\n", error_count);
	else
		printf("All testcases finished successfully\n");

	return rc;
}

