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

#define NR_TESTS 12
#define NR_RANDOM_TESTS 1000

/* CFB128 data -1- AES128 */
unsigned char NIST_KEY_CFB_E1[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

unsigned char NIST_IV_CFB_E1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_EXPECTED_IV_CFB_E1[] = {
	0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
	0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
};

unsigned char NIST_TEST_DATA_CFB_E1[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

unsigned char NIST_TEST_RESULT_CFB_E1[] = {
	0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
	0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
};

unsigned int NIST_LCFB_E1 = 128 / 8;

/* CFB128 data -2- AES128 */
unsigned char NIST_KEY_CFB_E2[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

unsigned char NIST_IV_CFB_E2[] = {
	0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
	0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
};

unsigned char NIST_EXPECTED_IV_CFB_E2[] = {
	0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f,
	0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
};

unsigned char NIST_TEST_DATA_CFB_E2[] = {
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};

unsigned char NIST_TEST_RESULT_CFB_E2[] = {
	0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f,
	0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
};

unsigned int NIST_LCFB_E2 = 128 / 8;

/* CFB8 data -3- AES128 */
unsigned char NIST_KEY_CFB_E3[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

unsigned char NIST_IV_CFB_E3[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_EXPECTED_IV_CFB_E3[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x3b,
};
unsigned char NIST_TEST_DATA_CFB_E3[] = {
	0x6b, 
};

unsigned char NIST_TEST_RESULT_CFB_E3[] = {
	0x3b,
};
unsigned int NIST_LCFB_E3 = 8 / 8;

/* CFB8 data -4- AES128 */
unsigned char NIST_KEY_CFB_E4[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

unsigned char NIST_IV_CFB_E4[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x3b,
};

unsigned char NIST_EXPECTED_IV_CFB_E4[] = {
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x3b, 0x79,
};
unsigned char NIST_TEST_DATA_CFB_E4[] = {
	0xc1, 
};

unsigned char NIST_TEST_RESULT_CFB_E4[] = {
	0x79,
};

unsigned int NIST_LCFB_E4 = 8 / 8;


/* CFB 128 data -5- for AES192 */
unsigned char NIST_KEY_CFB_E5[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
	0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};

unsigned char NIST_IV_CFB_E5[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_EXPECTED_IV_CFB_E5[] = {
	0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab,
	0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
};

unsigned char NIST_TEST_DATA_CFB_E5[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

unsigned char NIST_TEST_RESULT_CFB_E5[] = {
	0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab,
	0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
};

unsigned int NIST_LCFB_E5 = 128 / 8;

/* CFB 128 data -6- for AES192 */
unsigned char NIST_KEY_CFB_E6[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
	0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};

unsigned char NIST_IV_CFB_E6[] = {
	0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab,
	0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
};

unsigned char NIST_EXPECTED_IV_CFB_E6[] = {
	0x67, 0xce, 0x7f, 0x7f, 0x81, 0x17, 0x36, 0x21,
	0x96, 0x1a, 0x2b, 0x70, 0x17, 0x1d, 0x3d, 0x7a,
};

unsigned char NIST_TEST_DATA_CFB_E6[] = {
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};

unsigned char NIST_TEST_RESULT_CFB_E6[] = {
	0x67, 0xce, 0x7f, 0x7f, 0x81, 0x17, 0x36, 0x21,
	0x96, 0x1a, 0x2b, 0x70, 0x17, 0x1d, 0x3d, 0x7a,
};

unsigned int NIST_LCFB_E6 = 128 / 8;

/* CFB 128 data -7- for AES192 */
unsigned char NIST_KEY_CFB_E7[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
	0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};

unsigned char NIST_IV_CFB_E7[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_EXPECTED_IV_CFB_E7[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xcd,
};

unsigned char NIST_TEST_DATA_CFB_E7[] = {
	0x6b,
};

unsigned char NIST_TEST_RESULT_CFB_E7[] = {
	0xcd,
};

unsigned int NIST_LCFB_E7 = 8 / 8;

/* CFB 128 data -8- for AES192 */
unsigned char NIST_KEY_CFB_E8[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
	0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};

unsigned char NIST_IV_CFB_E8[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xcd,
};

unsigned char NIST_EXPECTED_IV_CFB_E8[] = {
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xcd, 0xa2,
};

unsigned char NIST_TEST_DATA_CFB_E8[] = {
	0xc1,
};

unsigned char NIST_TEST_RESULT_CFB_E8[] = {
	0xa2,
};

unsigned int NIST_LCFB_E8 = 8 / 8;



/* CFB128 data -9- for AES256 */
unsigned char NIST_KEY_CFB_E9[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

unsigned char NIST_IV_CFB_E9[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_EXPECTED_IV_CFB_E9[] = {
	0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b,
	0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
};

unsigned char NIST_TEST_DATA_CFB_E9[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

unsigned char NIST_TEST_RESULT_CFB_E9[] = {
	0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b,
	0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
};

unsigned int NIST_LCFB_E9 = 128 / 8;

/* CFB128 data -10- for AES256 */
unsigned char NIST_KEY_CFB_E10[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

unsigned char NIST_IV_CFB_E10[] = {
	0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b,
	0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
};

unsigned char NIST_EXPECTED_IV_CFB_E10[] = {
	0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8,
	0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b,
};

unsigned char NIST_TEST_DATA_CFB_E10[] = {
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};

unsigned char NIST_TEST_RESULT_CFB_E10[] = {
	0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8,
	0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b,
};

unsigned int NIST_LCFB_E10 = 128 / 8;

/* CFB8 data -11- for AES256 */
unsigned char NIST_KEY_CFB_E11[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

unsigned char NIST_IV_CFB_E11[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_EXPECTED_IV_CFB_E11[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xdc,
};

unsigned char NIST_TEST_DATA_CFB_E11[] = {
	0x6b,
};

unsigned char NIST_TEST_RESULT_CFB_E11[] = {
	0xdc,
};

unsigned int NIST_LCFB_E11 = 8 / 8;

/* CFB8 data -12- for AES256 */
unsigned char NIST_KEY_CFB_E12[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

unsigned char NIST_IV_CFB_E12[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xdc,
};

unsigned char NIST_EXPECTED_IV_CFB_E12[] = {
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xdc, 0x1f,
};

unsigned char NIST_TEST_DATA_CFB_E12[] = {
	0xc1,
};

unsigned char NIST_TEST_RESULT_CFB_E12[] = {
	0x1f,
};

unsigned int NIST_LCFB_E12 = 8 / 8;


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

void dump_cfb_data(unsigned char *iv, unsigned int iv_length,
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
			*data_length = sizeof(NIST_TEST_DATA_CFB_E1);
			*iv_length = sizeof(NIST_IV_CFB_E1);
			*key_length = sizeof(NIST_KEY_CFB_E1);
			break;
		case 2:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E2);
			*iv_length = sizeof(NIST_IV_CFB_E2);
			*key_length = sizeof(NIST_KEY_CFB_E2);
			break;
		case 3:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E3);
			*iv_length = sizeof(NIST_IV_CFB_E3);
			*key_length = sizeof(NIST_KEY_CFB_E3);
			break;
		case 4:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E4);
			*iv_length = sizeof(NIST_IV_CFB_E4);
			*key_length = sizeof(NIST_KEY_CFB_E4);
			break;
		case 5:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E5);
			*iv_length = sizeof(NIST_IV_CFB_E5);
			*key_length = sizeof(NIST_KEY_CFB_E5);
			break;
		case 6:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E6);
			*iv_length = sizeof(NIST_IV_CFB_E6);
			*key_length = sizeof(NIST_KEY_CFB_E6);
			break;
		case 7:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E7);
			*iv_length = sizeof(NIST_IV_CFB_E7);
			*key_length = sizeof(NIST_KEY_CFB_E7);
			break;
		case 8:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E8);
			*iv_length = sizeof(NIST_IV_CFB_E8);
			*key_length = sizeof(NIST_KEY_CFB_E8);
			break;
		case 9:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E9);
			*iv_length = sizeof(NIST_IV_CFB_E9);
			*key_length = sizeof(NIST_KEY_CFB_E9);
			break;
		case 10:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E10);
			*iv_length = sizeof(NIST_IV_CFB_E10);
			*key_length = sizeof(NIST_KEY_CFB_E10);
			break;
		case 11:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E11);
			*iv_length = sizeof(NIST_IV_CFB_E11);
			*key_length = sizeof(NIST_KEY_CFB_E11);
			break;
		case 12:
			*data_length = sizeof(NIST_TEST_DATA_CFB_E12);
			*iv_length = sizeof(NIST_IV_CFB_E12);
			*key_length = sizeof(NIST_KEY_CFB_E12);
			break;
	}

}

void load_test_data(unsigned char *data, unsigned int data_length,
		    unsigned char *result,
		    unsigned char *iv, unsigned char *expected_iv,
		    unsigned int iv_length,
		    unsigned char *key, unsigned int key_length,
		    unsigned int *lcfb, unsigned int iteration)
{
	switch (iteration) {
		case 1:
			memcpy(data, NIST_TEST_DATA_CFB_E1, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E1, data_length);
			memcpy(iv, NIST_IV_CFB_E1, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E1, iv_length);
			memcpy(key, NIST_KEY_CFB_E1, key_length);
			*lcfb = NIST_LCFB_E1;
			break;
		case 2:
			memcpy(data, NIST_TEST_DATA_CFB_E2, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E2, data_length);
			memcpy(iv, NIST_IV_CFB_E2, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E2, iv_length);
			memcpy(key, NIST_KEY_CFB_E2, key_length);
			*lcfb = NIST_LCFB_E2;
			break;
		case 3:
			memcpy(data, NIST_TEST_DATA_CFB_E3, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E3, data_length);
			memcpy(iv, NIST_IV_CFB_E3, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E3, iv_length);
			memcpy(key, NIST_KEY_CFB_E3, key_length);
			*lcfb = NIST_LCFB_E3;
			break;
		case 4:
			memcpy(data, NIST_TEST_DATA_CFB_E4, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E4, data_length);
			memcpy(iv, NIST_IV_CFB_E4, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E4, iv_length);
			memcpy(key, NIST_KEY_CFB_E4, key_length);
			*lcfb = NIST_LCFB_E4;
			break;
		case 5:
			memcpy(data, NIST_TEST_DATA_CFB_E5, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E5, data_length);
			memcpy(iv, NIST_IV_CFB_E5, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E5, iv_length);
			memcpy(key, NIST_KEY_CFB_E5, key_length);
			*lcfb = NIST_LCFB_E5;
			break;
		case 6:
			memcpy(data, NIST_TEST_DATA_CFB_E6, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E6, data_length);
			memcpy(iv, NIST_IV_CFB_E6, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E6, iv_length);
			memcpy(key, NIST_KEY_CFB_E6, key_length);
			*lcfb = NIST_LCFB_E6;
			break;
		case 7:
			memcpy(data, NIST_TEST_DATA_CFB_E7, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E7, data_length);
			memcpy(iv, NIST_IV_CFB_E7, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E7, iv_length);
			memcpy(key, NIST_KEY_CFB_E7, key_length);
			*lcfb = NIST_LCFB_E7;
			break;
		case 8:
			memcpy(data, NIST_TEST_DATA_CFB_E8, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E8, data_length);
			memcpy(iv, NIST_IV_CFB_E8, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E8, iv_length);
			memcpy(key, NIST_KEY_CFB_E8, key_length);
			*lcfb = NIST_LCFB_E8;
			break;
		case 9:
			memcpy(data, NIST_TEST_DATA_CFB_E9, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E9, data_length);
			memcpy(iv, NIST_IV_CFB_E9, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E9, iv_length);
			memcpy(key, NIST_KEY_CFB_E9, key_length);
			*lcfb = NIST_LCFB_E9;
			break;
		case 10:
			memcpy(data, NIST_TEST_DATA_CFB_E10, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E10, data_length);
			memcpy(iv, NIST_IV_CFB_E10, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E10, iv_length);
			memcpy(key, NIST_KEY_CFB_E10, key_length);
			*lcfb = NIST_LCFB_E10;
			break;
		case 11:
			memcpy(data, NIST_TEST_DATA_CFB_E11, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E11, data_length);
			memcpy(iv, NIST_IV_CFB_E11, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E11, iv_length);
			memcpy(key, NIST_KEY_CFB_E11, key_length);
			*lcfb = NIST_LCFB_E11;
			break;
		case 12:
			memcpy(data, NIST_TEST_DATA_CFB_E12, data_length);
			memcpy(result, NIST_TEST_RESULT_CFB_E12, data_length);
			memcpy(iv, NIST_IV_CFB_E12, iv_length);
			memcpy(expected_iv, NIST_EXPECTED_IV_CFB_E12, iv_length);
			memcpy(key, NIST_KEY_CFB_E12, key_length);
			*lcfb = NIST_LCFB_E12;
			break;
	}

}

int kat_aes_cfb(int iteration, int silent)
{
	unsigned int data_length;
	unsigned int iv_length;
	unsigned int key_length;

	get_sizes(&data_length, &iv_length, &key_length, iteration);


	unsigned char iv[iv_length];
	unsigned char tmp_iv[iv_length];
	unsigned char expected_iv[iv_length];
	unsigned char key[key_length];
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];
	unsigned char result[data_length];

	int rc = 0;
	unsigned int lcfb;
	memset(encrypt, 0x00, data_length);
	memset(decrypt, 0x00, data_length);

	load_test_data(input_data, data_length, result, iv, expected_iv,
		       iv_length, key, key_length, &lcfb, iteration);
	memcpy(tmp_iv, iv, iv_length);

	printf("Test Parameters for iteration = %i\n", iteration);
	printf("key length = %i, data length = %i, iv length = %i,"
	       " lcfb = %i\n", key_length, data_length, iv_length, lcfb);

	if (iteration == 3)
	rc = ica_aes_cfb(input_data, encrypt, lcfb, key, key_length, tmp_iv,
			 lcfb, 1);
	else
	rc = ica_aes_cfb(input_data, encrypt, data_length, key, key_length,
			 tmp_iv, lcfb, 1);
	if (rc) {
		printf("ica_aes_cfb encrypt failed with rc = %i\n", rc);
		dump_cfb_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!silent && !rc) {
		printf("Encrypt:\n");
		dump_cfb_data(iv, iv_length, key, key_length, input_data,
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
	if (iteration == 3)
	rc = ica_aes_cfb(encrypt, decrypt, lcfb, key, key_length, tmp_iv,
			 lcfb, 0);
	else
	rc = ica_aes_cfb(encrypt, decrypt, data_length, key, key_length,
			 tmp_iv, lcfb, 0);
	if (rc) {
		printf("ica_aes_cfb decrypt failed with rc = %i\n", rc);
		dump_cfb_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
		return rc;
	}


	if (!silent && !rc) {
		printf("Decrypt:\n");
		dump_cfb_data(iv, iv_length, key, key_length, encrypt,
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

int random_aes_cfb(int iteration, int silent, unsigned int data_length,
		   unsigned int lcfb)
{
	unsigned int iv_length = sizeof(ica_aes_vector_t);
	unsigned int key_length = AES_KEY_LEN128;

	unsigned char iv[iv_length];
	unsigned char tmp_iv[iv_length];
	unsigned char key[key_length];
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];

	int rc = 0;
	for (key_length = AES_KEY_LEN128; key_length <= AES_KEY_LEN256; key_length += 8) {
	memset(encrypt, 0x00, data_length);
	memset(decrypt, 0x00, data_length);

	load_random_test_data(input_data, data_length, iv, iv_length, key,
			      key_length);
	memcpy(tmp_iv, iv, iv_length);

	printf("Test Parameters for iteration = %i\n", iteration);
	printf("key length = %i, data length = %i, iv length = %i,"
	       " lcfb = %i\n", key_length, data_length, iv_length, lcfb);

	rc = ica_aes_cfb(input_data, encrypt, data_length, key, key_length,
			 tmp_iv, lcfb, 1);
	if (rc) {
		printf("ica_aes_cfb encrypt failed with rc = %i\n", rc);
		dump_cfb_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}
	if (!silent && !rc) {
		printf("Encrypt:\n");
		dump_cfb_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}

	if (rc) {
		printf("AES OFB test exited after encryption\n");
		return rc;
	}

	memcpy(tmp_iv, iv, iv_length);

	rc = ica_aes_cfb(encrypt, decrypt, data_length, key, key_length,
			 tmp_iv, lcfb, 0);
	if (rc) {
		printf("ica_aes_cfb decrypt failed with rc = %i\n", rc);
		dump_cfb_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
		return rc;
	}


	if (!silent && !rc) {
		printf("Decrypt:\n");
		dump_cfb_data(iv, iv_length, key, key_length, encrypt,
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
	}
	return rc;
}

int main(int argc, char **argv)
{
	unsigned int silent = 0;
	unsigned int endless = 0;
	if (argc > 1) {
		if (strstr(argv[1], "silent"))
			silent = 1;
		if (strstr(argv[1], "endless"))
			endless = 1;
	}
	int rc = 0;
	int error_count = 0;
	int iteration;
	for(iteration = 1; iteration <= NR_TESTS; iteration++)	{
		rc = kat_aes_cfb(iteration, silent);
		if (rc) {
			printf("kat_aes_cfb failed with rc = %i\n", rc);
			error_count++;
		} else
			printf("kat_aes_cfb finished successfuly\n");

	}

	unsigned int data_length = 1;
	unsigned int lcfb = 1;
	unsigned int j;
	for(iteration = 1; iteration <= NR_RANDOM_TESTS; iteration++)	{
		for (j = 1; j <= 3; j++) {
			int silent = 1;
			if (!(data_length % lcfb)) {
			rc = random_aes_cfb(iteration, silent, data_length, lcfb);
			if (rc) {
				printf("random_aes_cfb failed with rc = %i\n", rc);
				error_count++;
			} else
				printf("random_aes_cfb finished successfuly\n");
			}
			switch (j) {
				case 1:
					lcfb = 1;
					break;
				case 2:
					lcfb = 8;
					break;
				case 3:
					lcfb = 16;
					break;
			}
		}
		if (data_length == 1)
			data_length = 8;
		else
			data_length += 8;
	}
	if (error_count)
		printf("%i testcases failed\n", error_count);
	else
		printf("All testcases finished successfully\n");

	return rc;
}

