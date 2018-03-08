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
#include <stdlib.h>
#include "ica_api.h"
#include "testcase.h"

const int cipher_buf_length = 8;

unsigned char NIST_KEY1[] =
		  { 0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57 };

unsigned char NIST_TEST_DATA[] =
		  { 0x01, 0xa1, 0xd6, 0xd0, 0x39, 0x77, 0x67, 0x42 };

unsigned char NIST_TEST_RESULT[] =
		  { 0x69, 0x0f, 0x5b, 0x0d, 0x9a, 0x26, 0x93, 0x9b };

int test_des_new_api(int mode)
{
	ica_des_vector_t iv;
	ica_des_key_single_t key;
	int rc = 0;
	unsigned char dec_text[sizeof NIST_TEST_DATA],
		      enc_text[sizeof NIST_TEST_DATA];

	bzero(dec_text, sizeof dec_text);
	bzero(enc_text, sizeof enc_text);
	bzero(iv, sizeof iv);
	bcopy(NIST_KEY1, key, sizeof NIST_KEY1);

	rc = ica_des_encrypt(mode, sizeof NIST_TEST_DATA, NIST_TEST_DATA, &iv,
			     &key, enc_text);
	if (rc) {
		VV_(printf("\nOriginal data:\n");
		dump_array(NIST_TEST_DATA, sizeof NIST_TEST_DATA));
		VV_(printf("ica_des_encrypt failed with errno %d (0x%x).\n", rc, rc));
		VV_(printf("\nEncrypted data:\n"));
		dump_array(enc_text, sizeof enc_text);
		return TEST_FAIL;
	}

	if (memcmp(enc_text, NIST_TEST_RESULT, sizeof NIST_TEST_RESULT) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		return TEST_FAIL;
	} else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	bzero(iv, sizeof iv);
	rc = ica_des_decrypt(mode, sizeof enc_text, enc_text, &iv, &key,
			     dec_text);
	if (rc) {
		VV_(printf("\nOriginal data:\n"));
		dump_array(NIST_TEST_DATA, sizeof NIST_TEST_DATA);
		VV_(printf("ica_des_encrypt failed with errno %d (0x%x).\n", rc, rc));
		VV_(printf("\nEncrypted data:\n"));
		dump_array(enc_text, sizeof enc_text);
		VV_(printf("\nDecrypted data:\n"));
		dump_array(dec_text, sizeof dec_text);
		VV_(printf("ica_des_decrypt failed with errno %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	if (memcmp(dec_text, NIST_TEST_DATA, sizeof NIST_TEST_DATA) != 0) {
		VV_(printf("\nOriginal data:\n"));
		dump_array(NIST_TEST_DATA, sizeof NIST_TEST_DATA);
		VV_(printf("ica_des_encrypt failed with errno %d (0x%x).\n", rc, rc));
		VV_(printf("\nEncrypted data:\n"));
		dump_array(enc_text, sizeof enc_text);
		VV_(printf("\nDecrypted data:\n"));
		dump_array(dec_text, sizeof dec_text);
		VV_(printf("This does NOT match the original data.\n"));
		return TEST_FAIL;
	} else {
		VV_(printf("Successful!\n"));
	}

	return TEST_SUCC;
}

int main(int argc, char **argv)
{
	unsigned int mode = 0;
	int rc = 0;
	int error_count = 0;

	set_verbosity(argc, argv);

#ifdef ICA_FIPS
	if (ica_fips_status() & ICA_FIPS_MODE) {
		printf("All DES new api tests skipped."
		    " (DES not FIPS approved)\n");
		return TEST_SKIP;
	}
#endif /* ICA_FIPS */

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
	if (!mode) {
	/* This is the standard loop that will perform all testcases */
		mode = 2;
		while (mode) {
			rc = test_des_new_api(mode);
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
		rc = test_des_new_api(mode);
		if (rc)
			printf ("test_des_new_api mode = %i failed \n", mode);
		else
			printf ("test_des_new_api mode = %i finished.\n", mode);
	}

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}
