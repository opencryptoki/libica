/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2005, 2009, 2011 */
#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "ica_api.h"
#include "testcase.h"

unsigned char NIST_KEY3[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

unsigned char NIST_TEST_DATA[] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

unsigned char NIST_TEST_RESULT[] = {
	0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
	0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
};

int test_aes256_new_api(int mode)
{
	ica_aes_vector_t iv;
	unsigned char key[AES_KEY_LEN256];
	int rc = 0;
	unsigned char dec_text[sizeof(NIST_TEST_DATA)],
		      enc_text[sizeof(NIST_TEST_DATA)];

	bzero(dec_text, sizeof(dec_text));
	bzero(enc_text, sizeof(enc_text));
	bzero(iv, sizeof(iv));
	bcopy(NIST_KEY3, key, sizeof(NIST_KEY3));

	rc = ica_aes_encrypt(mode, sizeof(NIST_TEST_DATA), NIST_TEST_DATA, &iv,
			     AES_KEY_LEN256, key, enc_text);
	if (rc) {
		VV_(printf("ica_aes_encrypt failed with errno %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	if (memcmp(enc_text, NIST_TEST_RESULT, sizeof(NIST_TEST_RESULT)) != 0) {
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		VV_(printf("\nEncrypted data:\n"));
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		VV_(printf("This does NOT match the known result.\n"));
		return TEST_FAIL;
	} else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	bzero(iv, sizeof(iv));
	rc = ica_aes_decrypt(mode, sizeof(enc_text), enc_text, &iv,
			     AES_KEY_LEN256, key, dec_text);
	if (rc) {
		VV_(printf("ica_aes_decrypt failed with errno %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	if (memcmp(dec_text, NIST_TEST_DATA, sizeof(NIST_TEST_DATA)) != 0) {
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		VV_(printf("\nEncrypted data:\n"));
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		VV_(printf("\nDecrypted data:\n"));
		dump_array((unsigned char *) dec_text, sizeof(dec_text));
		VV_(printf("This does NOT match the original data.\n"));
		return TEST_FAIL;
	} else {
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		VV_(printf("\nEncrypted data:\n"));
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		VV_(printf("\nDecrypted data:\n"));
		dump_array((unsigned char *) dec_text, sizeof(dec_text));
		VV_(printf("Successful!\n"));
	}

	return TEST_SUCC;
}

/*
 * Performs ECB and CBC tests.
 */
int main(int argc, char **argv)
{
#ifdef NO_CPACF
	UNUSED(argc);
	UNUSED(argv);
	printf("Skipping AES-256 test, because CPACF support disabled via config option.\n");
	return TEST_SKIP;
#else
	unsigned int mode = 0;
	int rc = 0;
	int error_count = 0;

	if (argc > 1) {
		if (strstr(argv[1], "ecb"))
			mode = MODE_ECB;
		if (strstr(argv[1], "cbc"))
			mode = MODE_CBC;
	}
	if (argc > 2) {
		if (strstr(argv[2], "ecb"))
			mode = MODE_ECB;
		if (strstr(argv[2], "cbc"))
			mode = MODE_CBC;
	}

	set_verbosity(argc, argv);

	if (mode != 0 && mode != MODE_ECB && mode != MODE_CBC) {
		printf("Usage: %s [ ecb | cbc ]\n", argv[0]);
		return TEST_ERR;
	}

	if (!mode) {
	/* This is the standard loop that will perform all testcases */
		mode = 2;
		while (mode) {
			rc = test_aes256_new_api(mode);
			if (rc) {
				error_count++;
				V_(printf ("test_aes_new_api mode = %i failed \n", mode));
			}
			else {
				V_(printf ("test_aes_new_api mode = %i finished.\n", mode));
			}
			mode--;
		}
		if (error_count)
			printf("%i AES-256-ECB/CBC tests failed.\n", error_count);
		else
			printf("All AES-256-ECB/CBC tests passed.\n");
	} else {
	/* Perform only either in ECB or CBC mode */
		rc = test_aes256_new_api(mode);
		if (rc)
			printf("test_aes_new_api mode = %i failed \n", mode);
		else
			printf("test_aes_new_api mode = %i finished.\n", mode);
	}

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
#endif /* NO_CPACF */
}
