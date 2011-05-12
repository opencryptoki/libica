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

#define NR_TESTS 7
#define NR_RANDOM_TESTS 10000

/* ECB data - 1 for AES128 */
unsigned char NIST_KEY_ECB_E1[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

unsigned char NIST_TEST_DATA_ECB_E1[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

unsigned char NIST_TEST_RESULT_ECB_E1[] = {
	0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
	0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
};

/* ECB data - 2 for AES128 */
unsigned char NIST_KEY_ECB_E2[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

unsigned char NIST_TEST_DATA_ECB_E2[] = {
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};

unsigned char NIST_TEST_RESULT_ECB_E2[] = {
	0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
	0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
};

/* ECB data - 3 - for AES128 */
unsigned char NIST_KEY_ECB_E3[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	
};

unsigned char NIST_TEST_DATA_ECB_E3[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

unsigned char NIST_TEST_RESULT_ECB_E3[] = {
	0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
	0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
	0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
	0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
	0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
	0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
	0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
	0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,	
};

/* ECB data - 4 - for AES192 */
unsigned char NIST_KEY_ECB_E4[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
	0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};

unsigned char NIST_TEST_DATA_ECB_E4[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

unsigned char NIST_TEST_RESULT_ECB_E4[] = {
	0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
	0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
};

/* ECB data 5 - for AES 192 */
unsigned char NIST_KEY_ECB_E5[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
	0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};

unsigned char NIST_TEST_DATA_ECB_E5[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

unsigned char NIST_TEST_RESULT_ECB_E5[] = {
	0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
	0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
	0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
	0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef,
	0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
	0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e,
	0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
	0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e,
};

/* ECB data 6 - for AES 256 */
unsigned char NIST_KEY_ECB_E6[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

unsigned char NIST_TEST_DATA_ECB_E6[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

unsigned char NIST_TEST_RESULT_ECB_E6[] = {
	0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
	0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
};

/* ECB data 7 - for AES 256 */
unsigned char NIST_KEY_ECB_E7[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

unsigned char NIST_TEST_DATA_ECB_E7[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

unsigned char NIST_TEST_RESULT_ECB_E7[] = {
	0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
	0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
	0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
	0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
	0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
	0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
	0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
	0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7,
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

void dump_ecb_data(unsigned char *key, unsigned int key_length,
                   unsigned char *input_data, unsigned int data_length,
                   unsigned char *output_data)
{
	printf("Key \n");
	dump_array(key, key_length);
	printf("Input Data\n");
	dump_array(input_data, data_length);
	printf("Output Data\n");
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
		case 3:
			*data_length = sizeof(NIST_TEST_DATA_ECB_E3);
			*key_length = sizeof(NIST_KEY_ECB_E3);
			break;
		case 4:
			*data_length = sizeof(NIST_TEST_DATA_ECB_E4);
			*key_length = sizeof(NIST_KEY_ECB_E4);
			break;
		case 5:
			*data_length = sizeof(NIST_TEST_DATA_ECB_E5);
			*key_length = sizeof(NIST_KEY_ECB_E5);
			break;
		case 6:
			*data_length = sizeof(NIST_TEST_DATA_ECB_E6);
			*key_length = sizeof(NIST_KEY_ECB_E6);
			break;
		case 7:
			*data_length = sizeof(NIST_TEST_DATA_ECB_E7);
			*key_length = sizeof(NIST_KEY_ECB_E7);
			break;
		case 8:
			break;
		case 9:
			break;
		case 10:
			break;
		case 11:
			break;
		case 12:
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
		case 3:
			memcpy(data, NIST_TEST_DATA_ECB_E3, data_length);
			memcpy(result, NIST_TEST_RESULT_ECB_E3, data_length);
			memcpy(key, NIST_KEY_ECB_E3, key_length);
			break;
		case 4:
			memcpy(data, NIST_TEST_DATA_ECB_E4, data_length);
			memcpy(result, NIST_TEST_RESULT_ECB_E4, data_length);
			memcpy(key, NIST_KEY_ECB_E4, key_length);
			break;
		case 5:
			memcpy(data, NIST_TEST_DATA_ECB_E5, data_length);
			memcpy(result, NIST_TEST_RESULT_ECB_E5, data_length);
			memcpy(key, NIST_KEY_ECB_E5, key_length);
			break;
		case 6:
			memcpy(data, NIST_TEST_DATA_ECB_E6, data_length);
			memcpy(result, NIST_TEST_RESULT_ECB_E6, data_length);
			memcpy(key, NIST_KEY_ECB_E6, key_length);
			break;
		case 7:
			memcpy(data, NIST_TEST_DATA_ECB_E7, data_length);
			memcpy(result, NIST_TEST_RESULT_ECB_E7, data_length);
			memcpy(key, NIST_KEY_ECB_E7, key_length);
			break;
		case 8:
			break;
		case 9:
			break;
		case 10:
			break;
		case 11:
			break;
		case 12:
			break;
	}

}

int kat_aes_ecb(int iteration, int silent)
{
	unsigned int data_length;
	unsigned int key_length;

	get_sizes(&data_length, &key_length, iteration);

	printf("Test Parameters for iteration = %i\n", iteration);
	printf("key length = %i, data length = %i",
	       key_length, data_length);

	unsigned char key[key_length];
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];
	unsigned char result[data_length];

	int rc = 0;

	load_test_data(input_data, data_length, result, key, key_length,
		       iteration);

	rc = ica_aes_ecb(input_data, encrypt, data_length, key, key_length, 1);
	if (rc) {
		printf("ica_aes_ecb encrypt failed with rc = %i\n", rc);
		dump_ecb_data(key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!silent && !rc) {
		printf("Encrypt:\n");
		dump_ecb_data(key, key_length, input_data,
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

	if (rc) {
		printf("AES ECB test exited after encryption\n");
		return rc;
	}

	rc = ica_aes_ecb(encrypt, decrypt, data_length, key, key_length, 0);
	if (rc) {
		printf("ica_aes_ecb decrypt failed with rc = %i\n", rc);
		dump_ecb_data(key, key_length, encrypt,
			      data_length, decrypt);
		return rc;
	}


	if (!silent && !rc) {
		printf("Decrypt:\n");
		dump_ecb_data(key, key_length, encrypt,
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
		    	   unsigned char *key, unsigned int key_length)
{
	int rc;
	rc = ica_random_number_generate(data_length, data);
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

int random_aes_ecb(int iteration, int silent, unsigned int data_length)
{
	int i;
	int rc = 0;
	unsigned int key_length = AES_KEY_LEN128;
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];
for (i = 1; i <= 2; i++) {

	unsigned char key[key_length];

	memset(encrypt, 0x00, data_length);
	memset(decrypt, 0x00, data_length);

	load_random_test_data(input_data, data_length, key, key_length);
	printf("Test Parameters for iteration = %i\n", iteration);
	printf("key length = %i, data length = %i\n", key_length, data_length);

	rc = ica_aes_ecb(input_data, encrypt, data_length, key, key_length,
			 1);
	if (rc) {
		printf("ica_aes_ecb encrypt failed with rc = %i\n", rc);
		dump_ecb_data(key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!silent && !rc) {
		printf("Encrypt:\n");
		dump_ecb_data(key, key_length, input_data,
			      data_length, encrypt);
	}

	if (rc) {
		printf("AES ECB test exited after encryption\n");
		return rc;
	}

	rc = ica_aes_ecb(encrypt, decrypt, data_length, key, key_length, 0);
	if (rc) {
		printf("ica_aes_ecb decrypt failed with rc = %i\n", rc);
		dump_ecb_data(key, key_length, encrypt,
			      data_length, decrypt);
		return rc;
	}


	if (!silent && !rc) {
		printf("Decrypt:\n");
		dump_ecb_data(key, key_length, encrypt,
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

int main(int argc, char **argv)
{
	// Default mode is 0. ECB,ECB and CFQ tests will be performed.
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
		rc = kat_aes_ecb(iteration, silent);
		if (rc) {
			printf("kat_aes_ecb failed with rc = %i\n", rc);
			error_count++;
		} else
			printf("kat_aes_ecb finished successfuly\n");

	}
	for(iteration = 1; iteration <= NR_RANDOM_TESTS; iteration++)	{
		int silent = 1;
		rc = random_aes_ecb(iteration, silent, data_length);
		if (rc) {
			printf("random_aes_ecb failed with rc = %i\n", rc);
			error_count++;
			goto out;
		} else
			printf("random_aes_ecb finished successfuly\n");
		data_length += sizeof(ica_aes_vector_t);
	}

out:

	if (error_count)
		printf("%i testcases failed\n", error_count);
	else
		printf("All testcases finished successfully\n");

	return rc;
}

