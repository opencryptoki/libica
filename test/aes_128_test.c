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
#include <unistd.h>
#include "ica_api.h"
#include <stdlib.h>
#include <openssl/aes.h>
#include "testcase.h"

unsigned char NIST_KEY1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

unsigned char NIST_TEST_DATA[] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

unsigned char NIST_TEST_RESULT[] = {
	0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
	0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};

int test_aes128_new_api(int mode)
{
	ica_aes_vector_t iv;
	unsigned char key[AES_KEY_LEN128];
	int rc = 0;
	unsigned char dec_text[sizeof(NIST_TEST_DATA)],
		      enc_text[sizeof(NIST_TEST_DATA)];

	bzero(dec_text, sizeof(dec_text));
	bzero(enc_text, sizeof(enc_text));
	bzero(iv, sizeof(iv));
	bcopy(NIST_KEY1, key, sizeof(NIST_KEY1));

	rc = ica_aes_encrypt(mode, sizeof(NIST_TEST_DATA), NIST_TEST_DATA, &iv,
			     AES_KEY_LEN128, key, enc_text);
	if (rc) {
		VV_(printf("key \n"));
		dump_array((unsigned char *) key, sizeof(NIST_KEY1));
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		VV_(printf("test iv\n"));
		dump_array((unsigned char *) &iv, sizeof(ica_aes_vector_t));
		VV_(printf("key\n"));
		dump_array((unsigned char *) key, AES_KEY_LEN128);
		VV_(printf("ica_aes_encrypt failed with errno %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	if (memcmp(enc_text, NIST_TEST_RESULT, sizeof(NIST_TEST_RESULT)) != 0) {
		VV_(printf("key \n"));
		dump_array((unsigned char *) key, sizeof(NIST_KEY1));
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		VV_(printf("test iv\n"));
		dump_array((unsigned char *) &iv, sizeof(ica_aes_vector_t));
		VV_(printf("key\n"));
		dump_array((unsigned char *) key, AES_KEY_LEN128);
		VV_(printf("\nEncrypted data:\n"));
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		VV_(printf("This does NOT match the known result.\n"));
		return TEST_FAIL;
	} else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	bzero(iv, sizeof(iv));
	rc = ica_aes_decrypt(mode, sizeof(enc_text), enc_text, &iv,
			     AES_KEY_LEN128, key, dec_text);
	if (rc) {
		VV_(printf("key \n"));
		dump_array((unsigned char *) key, sizeof(NIST_KEY1));
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		VV_(printf("test iv\n"));
		dump_array((unsigned char *) &iv, sizeof(ica_aes_vector_t));
		VV_(printf("key\n"));
		dump_array((unsigned char *) key, AES_KEY_LEN128);
		VV_(printf("\nEncrypted data:\n"));
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		VV_(printf("\nDecrypted data:\n"));
		dump_array((unsigned char *) dec_text, sizeof(dec_text));
		VV_(printf("ica_aes_decrypt failed with errno %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	if (memcmp(dec_text, NIST_TEST_DATA, sizeof(NIST_TEST_DATA)) != 0) {
		VV_(printf("This does NOT match the original data.\n"));
		return TEST_FAIL;
	} else {
		VV_(printf("Successful!\n"));
		VV_(printf("key \n"));
		dump_array((unsigned char *) key, sizeof(NIST_KEY1));
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		VV_(printf("test iv\n"));
		dump_array((unsigned char *) &iv, sizeof(ica_aes_vector_t));
		VV_(printf("key\n"));
		dump_array((unsigned char *) key, AES_KEY_LEN128);
		VV_(printf("\nEncrypted data:\n"));
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		VV_(printf("\nDecrypted data:\n"));
		dump_array((unsigned char *) dec_text, sizeof(dec_text));
	}

// Test 2

	rc = 0;
	bzero(dec_text, sizeof(dec_text));
	bzero(enc_text, sizeof(enc_text));
	bzero(iv, sizeof(iv));
	bzero(key, sizeof(key));

	unsigned int length = 64;
	unsigned char *decrypt = malloc(length);
	unsigned char *encrypt = malloc(length);
	unsigned char *original = malloc(length);
	ica_aes_key_len_128_t key2;

	rc = ica_random_number_generate(length, original);
	if (rc) {
		VV_(printf("ica_random_number_generate returned rc = %i\n", rc));
		return TEST_FAIL;
	}

	rc = ica_random_number_generate(AES_KEY_LEN128, (unsigned char *) &key2);
	if (rc) {
		VV_(printf("ica_random_number_generate returned rc = %i\n", rc));
		return TEST_FAIL;
	}

	rc = ica_aes_encrypt(mode, length, original, &iv, AES_KEY_LEN128, (unsigned char *) &key2,
			     (unsigned char *) encrypt);
	if (rc) {
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) original, length);
		VV_(printf("KEY: \n"));
		dump_array((unsigned char *) &key2, AES_KEY_LEN128);
		VV_(printf("ica_aes_encrypt failed with errno %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	if (memcmp(encrypt, original, length) == 0) {
		VV_(printf("Encrypt and original are the same.\n"));
		return TEST_FAIL;
	}

	bzero(iv, sizeof(iv));
	rc = ica_aes_decrypt(mode, length, encrypt, &iv, AES_KEY_LEN128,
			     (unsigned char *) &key2, decrypt);
	if (rc) {
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) original, length);
		VV_(printf("KEY: \n"));
		dump_array((unsigned char *) &key2, AES_KEY_LEN128);
		VV_(printf("\nEncrypted data:\n"));
		dump_array((unsigned char *) encrypt, length);
		VV_(printf("ica_aes_decrypt failed with errno %d (0x%x).\n", rc, rc));
		goto free;
	}

	if (memcmp(decrypt, original, length) != 0) {
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) original, length);
		VV_(printf("KEY: \n"));
		dump_array((unsigned char *) &key2, AES_KEY_LEN128);
		VV_(printf("\nEncrypted data:\n"));
		dump_array((unsigned char *) encrypt, length);
		VV_(printf("\nDecrypted data:\n"));
		dump_array((unsigned char *) decrypt, length);
		VV_(printf("This does NOT match the original data.\n"));
		rc = -1;
		goto free;
	}

	if(memcmp(decrypt, encrypt, length) == 0) {
		VV_(printf("\nOriginal data:\n"));
		dump_array((unsigned char *) original, length);
		VV_(printf("KEY: \n"));
		dump_array((unsigned char *) &key2, AES_KEY_LEN128);
		VV_(printf("\nEncrypted data:\n"));
		dump_array((unsigned char *) encrypt, length);
		VV_(printf("\nDecrypted data:\n"));
		dump_array((unsigned char *) decrypt, length);
		VV_(printf("decrypt and encrypt are the same\n"));
		rc = -1;
		goto free;

	} else {
		VV_(printf("Successful!\n"));
	}
free:
	free(original);
	free(encrypt);
	free(decrypt);

	if (rc)
		return TEST_FAIL;

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
			rc = test_aes128_new_api(mode);
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
			printf("%i AES-128-ECB/CBC tests failed.\n", error_count);
		else
			printf("All AES-128-ECB/CBC tests passed.\n");
	} else {
	/* Perform only either in ECB or CBC mode */
		rc = test_aes128_new_api(mode);
		if (rc)
			printf ("test_aes_new_api mode = %i failed \n", mode);
		else {
			printf ("test_aes_new_api mode = %i finished.\n", mode);
		}
	}

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}
