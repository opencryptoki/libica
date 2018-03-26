/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2001, 2009, 2011 */
#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "ica_api.h"
#include "testcase.h"

unsigned char KEY1[] =
		  { 0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57 };

unsigned char KEY2[] =
		  { 0x8c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57 };

unsigned char KEY3[] =
		  { 0x9c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57 };

unsigned char TEST_DATA[] =
		  { 0x01, 0xa1, 0xd6, 0xd0, 0x39, 0x77, 0x67, 0x42 };

unsigned char TEST_RESULT[] =
		  { 0x90, 0x9c, 0xbc, 0x01, 0xc5, 0x1f, 0x09, 0x60 };

int test_3des_new_api(int mode)
{
	ica_des_vector_t iv;
	ica_des_key_triple_t key;
	int rc = 0;
	unsigned char dec_text[sizeof(TEST_DATA)],
		      enc_text[sizeof(TEST_DATA)];

	bzero(dec_text, sizeof(dec_text));
	bzero(enc_text, sizeof(enc_text));
	bzero(iv, sizeof(iv));
	bcopy(KEY1, key.key1, sizeof(KEY1));
	bcopy(KEY2, key.key2, sizeof(KEY2));
	bcopy(KEY3, key.key3, sizeof(KEY3));

	VV_(printf("\nOriginal data:\n"));
	dump_array(TEST_DATA, sizeof(TEST_DATA));

	rc = ica_3des_encrypt(mode, sizeof(TEST_DATA), TEST_DATA,
			      &iv, &key, enc_text);
	if (rc != 0) {
		VV_(printf("ica_3des_encrypt failed with errno %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	VV_(printf("\nEncrypted data:\n"));
	dump_array(enc_text, sizeof(enc_text));
	if (memcmp(enc_text, TEST_RESULT, sizeof TEST_RESULT) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		return TEST_FAIL;
	} else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	bzero(iv, sizeof(iv));
	rc = ica_3des_decrypt(mode, sizeof(enc_text), enc_text,
			    &iv, &key, dec_text);
	if (rc != 0) {
		VV_(printf("ica_3des_decrypt failed with errno %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	VV_(printf("\nDecrypted data:\n"));
	dump_array(dec_text, sizeof(dec_text));
	if (memcmp(dec_text, TEST_DATA, sizeof(TEST_DATA)) != 0) {
		VV_(printf("This does NOT match the original data.\n"));
		return TEST_FAIL;
	} else {
		VV_(printf("Successful!\n"));
	}

	return TEST_SUCC;
}

/*
 * Performs ECB and CBC tests.
 */
int main(int argc, char **argv)
{
	unsigned int mode = 0;
	int rc = 0;
	int error_count = 0;

	if (argc > 1) {
		if (strstr(argv[1], "ecb"))
			mode = MODE_ECB;
		if (strstr(argv[1], "cbc"))
			mode = MODE_CBC;
		V_(printf("mode = %i \n", mode));
	}
	if (mode != 0 && mode != MODE_ECB && mode != MODE_CBC) {
		printf("Usage: %s [ ecb | cbc ]\n", argv[0]);
		return TEST_ERR;
	}

	set_verbosity(argc, argv);

	if (!mode) {
	/* This is the standard loop that will perform all testcases */
		mode = 2;
		while (mode) {
			rc = test_3des_new_api(mode);
			if (rc) {
				error_count++;
				V_(printf ("test_des_new_api mode = %i failed \n", mode));
			}
			else {
				V_(printf ("test_des_new_api mode = %i finished.\n", mode));
			}

			mode--;
		}
		if (error_count)
			printf("%i tests failed.\n", error_count);
		else
			printf("All tests passed.\n");
	} else {
	/* Perform only either in ECB or CBC mode */
		rc = test_3des_new_api(mode);
		if (rc)
			printf ("test_des_new_api mode = %i failed \n", mode);
		else
			printf ("test_des_new_api mode = %i finished.\n", mode);
	}

	if (rc || error_count)
		return TEST_FAIL;

	return TEST_SUCC;
}

