/* This program is released under the Common Public License V1.0
*
* You should have received a copy of Common Public License V1.0 along with
* with this program.
*/

/* (C) COPYRIGHT International Business Machines Corp. 2010  */
#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include "ica_api.h"
#include <stdlib.h>
#include <openssl/aes.h>
#include "testcase.h"

/* CBC_CS data */
unsigned char NIST_KEY[] = {
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
};
unsigned int key_size[6]  = { 24, 24, 24, 32, 32, 32 };
unsigned char key[6][256] = {
	{
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
	0x64, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20
	},{
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
	0x64, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20
	},{
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
	0x64, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20
	},{
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
	0x64, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
	},{
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
	0x64, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
	},{
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
	0x64, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
	}
};

unsigned char NIST_IV[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned int NIST_TEST_DATA_LENGTH[6] = { 17, 31, 32, 47, 48, 64 };
unsigned char NIST_TEST_DATA[6][100] = {
	{ 0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20
	},{
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20
	},{
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43
	},{
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
	0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
	0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c
	},{
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
	0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
	0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20
	},{
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
	0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
	0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20,
	0x61, 0x6e, 0x64, 0x20, 0x77, 0x6f, 0x6e, 0x74,
	0x6f, 0x6e, 0x20, 0x73, 0x6f, 0x75, 0x70, 0x2e
	}
};

unsigned char NIST_TEST_RESULT[6][100] = {
	{
	0xc6, 0x35, 0x35, 0x68, 0xf2, 0xbf, 0x8c, 0xb4,
	0xd8, 0xa5, 0x80, 0x36, 0x2d, 0xa7, 0xff, 0x7f, 0x97
	},{
	0xfc, 0x00, 0x78, 0x3e, 0x0e, 0xfd, 0xb2, 0xc1,
	0xd4, 0x45, 0xd4, 0xc8, 0xef, 0xf7, 0xed, 0x22,
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5
	},{
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84
	},{
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	0xb3, 0xff, 0xfd, 0x94, 0x0c, 0x16, 0xa1, 0x8c,
	0x1b, 0x55, 0x49, 0xd2, 0xf8, 0x38, 0x02, 0x9e,
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5
	},{
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
	0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8,
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8
	},{
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
	0x48, 0x07, 0xef, 0xe8, 0x36, 0xee, 0x89, 0xa5,
	0x26, 0x73, 0x0d, 0xbc, 0x2f, 0x7b, 0xc8, 0x40,
	0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
	0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8
	}
};

unsigned char NIST_NEXT_IV[6][16] = {
	{
	0xc6, 0x35, 0x35, 0x68, 0xf2, 0xbf, 0x8c, 0xb4,
	0xd8, 0xa5, 0x80, 0x36, 0x2d, 0xa7, 0xff, 0x7f
	},{
	0xfc, 0x00, 0x78, 0x3e, 0x0e, 0xfd, 0xb2, 0xc1,
	0xd4, 0x45, 0xd4, 0xc8, 0xef, 0xf7, 0xed, 0x22
	},{
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8
	},{
	0xb3, 0xff, 0xfd, 0x94, 0x0c, 0x16, 0xa1, 0x8c,
	0x1b, 0x55, 0x49, 0xd2, 0xf8, 0x38, 0x02, 0x9e
	},{
	0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
	0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8
	},{
	0x48, 0x07, 0xef, 0xe8, 0x36, 0xee, 0x89, 0xa5,
	0x26, 0x73, 0x0d, 0xbc, 0x2f, 0x7b, 0xc8, 0x40
	}
};

int compare_decrypt_result_with_expected_result(
			unsigned char *, unsigned char *,
			unsigned int, unsigned char *,
			unsigned int, unsigned char *,
			unsigned int, char *,
			unsigned int);

inline int compare_decrypt_result_with_expected_result(
	unsigned char * decrypt_out,
	unsigned char * expected_result,
	unsigned int compare_length,
	unsigned char * key,
	unsigned int key_length,
	unsigned char * iv,
	unsigned int iv_size,
	char * out_text,
	unsigned int test_case_number)
{
	if (memcmp(decrypt_out, expected_result, compare_length) != 0) {
		VV_(printf("This does NOT match the original data.\n"));
		VV_(printf("Test case number %i for %s with CBC_CS mode failed\n",
		test_case_number, out_text));
		VV_(printf("\nkey \n"));
		dump_array(key, key_length);
		VV_(printf("\nOriginal data:\n"));
		dump_array(expected_result, compare_length);
		VV_(printf("\ntmp iv\n"));
		dump_array(iv, iv_size);
		VV_(printf("\nExpected Result:\n"));
		dump_array(expected_result, compare_length);
		VV_(printf("\nDecrypted data:\n"));
		dump_array(decrypt_out, compare_length);
		return TEST_FAIL;
	}

	return TEST_SUCC;
}


int test_3des_new_api(unsigned int variant)
{
	/* Test 3des */
	unsigned int iv_size = sizeof(ica_des_vector_t);
	unsigned char tmp_iv[iv_size];
	unsigned char enc_text[100] ,dec_text[100] ;
	unsigned int number_of_testcases = 6;
	int rc = 0;
	unsigned int i = 0;

	for (i = 0; i < number_of_testcases ; i++) {
		memcpy(tmp_iv, NIST_IV, iv_size);
		rc = ica_3des_cbc_cs(NIST_TEST_DATA[i], enc_text,
				     NIST_TEST_DATA_LENGTH[i], key[i],
				     tmp_iv, 1, variant);
		if (rc) {
			VV_(printf("key \n"));
			dump_array(key[i], 8);
			VV_(printf("\nOriginal data:\n"));
			dump_array(NIST_TEST_DATA[i],
				   NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\ntest iv\n"));
			dump_array(tmp_iv, iv_size);
			VV_(printf("\nica_3des_cbc_cs encrypt test %i failed with "
				"errno %d (0x%x).\n", i, rc, rc));
			return TEST_FAIL;
		}
		memcpy(tmp_iv, NIST_IV, iv_size);
		memset(dec_text,0,NIST_TEST_DATA_LENGTH[i]);
		rc = ica_3des_cbc_cs(enc_text, dec_text,
				     NIST_TEST_DATA_LENGTH[i], key[i],
				     tmp_iv, 0, variant);
		if (rc) {
			VV_(printf("key \n"));
			dump_array(key[i], 8);
			VV_(printf("\nOriginal data:\n"));
			dump_array(NIST_TEST_DATA[i],
				   NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\ntmp iv\n"));
			dump_array(tmp_iv, iv_size);
			VV_(printf("\nEncrypted data:\n"));
			dump_array(enc_text, NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\nDecrypted data:\n"));
			dump_array(dec_text, NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\nica_3des_cbc_cs decrypt test %i failed with "
				"errno %d (0x%x).\n", i, rc, rc));
			return TEST_FAIL;
		}
		if (compare_decrypt_result_with_expected_result(dec_text,
				NIST_TEST_DATA[i], NIST_TEST_DATA_LENGTH[i],
				key[i], 24, tmp_iv, iv_size,
				(char *) "3DES", i))
			return TEST_FAIL;
		else {
			VV_(printf("Test case number %i for 3DES with CBC_CS mode was "
			"successful!\n", i));
		}
	}

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}
int test_des_new_api(unsigned int variant)
{
	/* Test des */
	unsigned int iv_size = sizeof(ica_des_vector_t);
	unsigned char tmp_iv[iv_size];
	unsigned char enc_text[100] ,dec_text[100] ;
	unsigned int number_of_testcases = 6;
	int rc = 0;
	unsigned int i = 0;

#ifdef ICA_FIPS
	if (ica_fips_status() & ICA_FIPS_MODE) {
		printf("All DES-CBC-CS tests skipped."
		    " (DES not FIPS approved)\n");
		return TEST_SKIP;
	}
#endif /* ICA_FIPS */

	for (i = 0; i < number_of_testcases ; i++) {
		memcpy(tmp_iv, NIST_IV, iv_size);
		rc = ica_des_cbc_cs(NIST_TEST_DATA[i], enc_text,
				    NIST_TEST_DATA_LENGTH[i], key[i],
				    tmp_iv, 1, variant);
		if (rc) {
			VV_(printf("key \n"));
			dump_array(key[i], 8);
			VV_(printf("\nOriginal data:\n"));
			dump_array(NIST_TEST_DATA[i],
				NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\ntest iv\n"));
			dump_array(tmp_iv, iv_size);
			VV_(printf("\nica_des_cbc_cs encrypt test %i failed with "
				"errno %d (0x%x).\n", i, rc, rc));
			return TEST_FAIL;
		}
		memcpy(tmp_iv, NIST_IV, iv_size);
		memset(dec_text,0,NIST_TEST_DATA_LENGTH[i]);
		rc = ica_des_cbc_cs(enc_text, dec_text,
				    NIST_TEST_DATA_LENGTH[i], key[i],
				    tmp_iv, 0, variant);
		if (rc) {
			VV_(printf("key \n"));
			dump_array(key[i], 8);
			VV_(printf("\nOriginal data:\n"));
			dump_array(NIST_TEST_DATA[i],
			NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\ntmp iv\n"));
			dump_array(tmp_iv, iv_size);
			VV_(printf("\nEncrypted data:\n"));
			dump_array(enc_text, NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\nDecrypted data:\n"));
			dump_array(dec_text, NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\nica_des_cbc_cs decrypt test %i failed with "
				"errno %d (0x%x).\n", i, rc, rc));
			return TEST_FAIL;
		}
		if (compare_decrypt_result_with_expected_result(
				dec_text, NIST_TEST_DATA[i],
				NIST_TEST_DATA_LENGTH[i], key[i],
				(sizeof(key[i]) / 8), tmp_iv, iv_size,
				(char *) "DES", i))
			return TEST_FAIL;
		else {
			VV_(printf("Test case number %i for DES with CBC_CS mode was "
			"successful!\n", i));
		}
	}

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}
int test_aes_new_api(unsigned int variant)
{
	/* Test with 192 & 256 byte keys */
	unsigned int iv_size = sizeof(ica_aes_vector_t);
	unsigned char tmp_iv[iv_size];
	char text[2][8] = {
		{ 0x41, 0x45, 0x53, 0x2d, 0x31, 0x39, 0x32, 0x00 },
		{ 0x41, 0x45, 0x53, 0x2d, 0x32, 0x35, 0x36, 0x00 }};
	unsigned char enc_text[100] ,dec_text[100] ;
	unsigned int number_of_testcases = 6;

	int rc = 0;
	unsigned int i = 0;

	for (i = 0; i < number_of_testcases ; i++) {
		memcpy(tmp_iv, NIST_IV, iv_size);
		rc = ica_aes_cbc_cs(NIST_TEST_DATA[i], enc_text,
				    NIST_TEST_DATA_LENGTH[i], key[i],
				    key_size[i], tmp_iv, 1, variant);
		if (rc) {
			VV_(printf("key \n"));
			dump_array(key[i], key_size[i]);
			VV_(printf("\nOriginal data:\n"));
			dump_array(NIST_TEST_DATA[i],
				NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\ntest iv\n"));
			dump_array(tmp_iv, iv_size);
			VV_(printf("\nica_aes_cbc_cs encrypt test %i failed with "
				" errno %d (0x%x).\n", i, rc, rc));
			return TEST_FAIL;
		}
		memcpy(tmp_iv, NIST_IV, iv_size);
		memset(dec_text,0,NIST_TEST_DATA_LENGTH[i]);
		rc = ica_aes_cbc_cs(enc_text, dec_text,
				    NIST_TEST_DATA_LENGTH[i], key[i],
				    key_size[i], tmp_iv, 0, variant);
		if (rc) {
			VV_(printf("key \n"));
			dump_array(key[i], key_size[i]);
			VV_(printf("\nOriginal data:\n"));
			dump_array(NIST_TEST_DATA[i],
				NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\ntmp iv\n"));
			dump_array(tmp_iv, iv_size);
			VV_(printf("\nEncrypted data:\n"));
			dump_array(enc_text, NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\nDecrypted data:\n"));
			dump_array(dec_text, NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\nica_aes_cbc_cs decrypt test %i failed with "
				"errno %d (0x%x).\n", i, rc, rc));
			return TEST_FAIL;
		}
		if (compare_decrypt_result_with_expected_result(dec_text,
				NIST_TEST_DATA[i], NIST_TEST_DATA_LENGTH[i],
				key[i],	key_size[i], tmp_iv, iv_size,
				(i < 3) ? text[0] : text[1], i))
			return TEST_FAIL;
		else {
			VV_(printf("Test case number %i for %s with CBC_CS mode was "
			"successful!\n", i, (i < 3) ? text[0] : text[1]));
		}
	}

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}

int test_aes128_new_api(void)
{
	/* AES128 Known Answer Tests*/
	unsigned int iv_size = sizeof(ica_aes_vector_t);
	unsigned int key_size = AES_KEY_LEN128;
	unsigned char tmp_iv[iv_size];
	unsigned char key[key_size];
	unsigned char enc_text[100] ,dec_text[100] ;
	unsigned int number_of_testcases = 6;
	int rc = 0;
	unsigned int i = 0;

	memcpy(key, NIST_KEY, sizeof(key));
	for (i = 0; i < number_of_testcases ; i++) {
		memcpy(tmp_iv, NIST_IV, iv_size);
		rc = ica_aes_cbc_cs(NIST_TEST_DATA[i], enc_text,
				    NIST_TEST_DATA_LENGTH[i], key,
				    sizeof(key), tmp_iv, 1, ICA_CBCCS_VARIANT3);
		if (rc) {
			VV_(printf("key \n"));
			dump_array(key, sizeof(key));
			VV_(printf("\nOriginal data:\n"));
			dump_array(NIST_TEST_DATA[i],
				NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\ntest iv\n"));
			dump_array(tmp_iv, iv_size);
			VV_(printf("\nica_aes_cbc_cs encrypt test %i failed with "
				"errno %d (0x%x).\n", i, rc, rc));
			return TEST_FAIL;
		}

		if (compare_decrypt_result_with_expected_result(enc_text,
				NIST_TEST_RESULT[i], NIST_TEST_DATA_LENGTH[i],
				key, sizeof(key), tmp_iv, iv_size,
				(char *) "AES-128", i))
			return TEST_FAIL;

		if (compare_decrypt_result_with_expected_result(tmp_iv,
				NIST_NEXT_IV[i], iv_size,
				key, sizeof(key), tmp_iv, iv_size,
				(char *) "AES-128", i))
			return TEST_FAIL;

		memcpy(tmp_iv, NIST_IV, iv_size);
		memset(dec_text,0,NIST_TEST_DATA_LENGTH[i]);
		rc = ica_aes_cbc_cs(enc_text, dec_text,
				    NIST_TEST_DATA_LENGTH[i], key, sizeof(key),
				    tmp_iv, 0, ICA_CBCCS_VARIANT3);
		if (rc) {
			VV_(printf("key \n"));
			dump_array(key, sizeof(key));
			VV_(printf("\nOriginal data:\n"));
			dump_array(NIST_TEST_DATA[i],
				NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\ntmp iv\n"));
			dump_array(tmp_iv, iv_size);
			VV_(printf("\nkey\n"));
			dump_array(key, sizeof(key));
			VV_(printf("\nEncrypted data:\n"));
			dump_array(enc_text, NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\nDecrypted data:\n"));
			dump_array(dec_text, NIST_TEST_DATA_LENGTH[i]);
			VV_(printf("\nica_aes_cbc_cs decrypt test %i failed"
				"with errno %d (0x%x).\n", i, rc, rc));
			return TEST_FAIL;
		}

		if (compare_decrypt_result_with_expected_result(dec_text,
				NIST_TEST_DATA[i], NIST_TEST_DATA_LENGTH[i],
				key, sizeof(key), tmp_iv, iv_size,
				(char *) "AES-128", i))
			return TEST_FAIL;
		else {
			VV_(printf("Test case number %i for AES-128 with CBC_CS "
			"mode was successful!\n", i));
		}
	}

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}

int main(int argc, char **argv)
{
	unsigned int variant;
	int rc, error_count;

	set_verbosity(argc, argv);

	rc = 0;
	error_count = 0;

	/* known answer tests for AES128 */
	rc = test_aes128_new_api();
	if (rc) {
		error_count++;
		printf("test_aes128_new_api for CBC_CS mode with AES-128 "
		"failed.\n");
		return TEST_FAIL;
	}

	for (variant =  ICA_CBCCS_VARIANT1;
	     variant <= ICA_CBCCS_VARIANT3;
	     variant++) {
		VV_(printf("\n--- Test cycle with CBCCS variant %d ---\n", variant));
		/* AES 192 & 256 test */
		rc = test_aes_new_api(variant);
		if (rc) {
			error_count++;
			printf("test_aes_new_api for CBC_CS mode with AES (192|256) "
			       "failed.\n");
			return TEST_FAIL;
		}

		/* DES tests */
		rc = test_des_new_api(variant);
		if (rc) {
			error_count++;
			printf("test_des_new_api for CBC_CS mode with DES "
			       "failed.\n");
			return TEST_FAIL;
		}

		/* 3DES tests */
		rc = test_3des_new_api(variant);
		if (rc) {
			error_count++;
			printf("test_des_new_api for CBC_CS mode with 3DES "
			       "failed.\n");
			return TEST_FAIL;
		}
	}

	printf("All CBC-CS tests passed.\n");
	return TEST_SUCC;
}

