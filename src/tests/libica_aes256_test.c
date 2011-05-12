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

int silent = 1;

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

int test_aes256_old_api(int mode)
{
	ICA_ADAPTER_HANDLE adapter_handle;
	ICA_AES_VECTOR iv;
	ICA_KEY_AES_LEN256 key;
	int rc = 0;
	unsigned char dec_text[sizeof(NIST_TEST_DATA)],
		      enc_text[sizeof(NIST_TEST_DATA)];
	unsigned int i;

	bzero(dec_text, sizeof(dec_text));
	bzero(enc_text, sizeof(enc_text));
	bzero(iv, sizeof(iv));
	bcopy(NIST_KEY3, key, sizeof(NIST_KEY3));

	i = sizeof(enc_text);
	rc = icaAesEncrypt(adapter_handle, mode, sizeof(NIST_TEST_DATA),
			   NIST_TEST_DATA, &iv, AES_KEY_LEN256,
			   (unsigned char *)&key, &i, enc_text);
	if (rc) {
		printf("icaAesEncrypt failed with errno %d (0x%x).\n", rc, rc);
		return 1;
	}
	if (i != sizeof(enc_text)) {
		printf("\nOriginal data:\n");
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		printf("\nEncrypted data:\n");
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		printf("icaAesEncrypt returned an incorrect output data length, %u (0x%x).\n", i, i);
		return 1;
	}

	if (memcmp(enc_text, NIST_TEST_RESULT, sizeof(NIST_TEST_RESULT)) != 0) {
		printf("\nOriginal data:\n");
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		printf("\nEncrypted data:\n");
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		printf("This does NOT match the known result.\n");
		return 1;
	} else {
		printf("Yep, it's what it should be.\n");
	}

	bzero(iv, sizeof(iv));
	i = sizeof(dec_text);
	rc = icaAesDecrypt(adapter_handle, mode, sizeof(enc_text),
			   enc_text, &iv, AES_KEY_LEN256,
			   (unsigned char *)&key, &i, dec_text);
	if (rc) {
		printf("icaAesDecrypt failed with errno %d (0x%x).\n", rc, rc);
		return 1;
	}
	if (i != sizeof(dec_text)) {
		printf("\nOriginal data:\n");
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		printf("\nEncrypted data:\n");
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		printf("\nDecrypted data:\n");
		dump_array((unsigned char *) dec_text, sizeof(dec_text));
		printf("icaAesDecrypt returned an incorrect output data length, %u (0x%x).\n", i, i);
		return 1;
	}

	if (memcmp(dec_text, NIST_TEST_DATA, sizeof(NIST_TEST_DATA)) != 0) {
		printf("\nOriginal data:\n");
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		printf("\nEncrypted data:\n");
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		printf("\nDecrypted data:\n");
		dump_array((unsigned char *) dec_text, sizeof(dec_text));
		printf("This does NOT match the original data.\n");
		return 1;
	} else {
		if (!silent) {
			printf("\nOriginal data:\n");
			dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
			printf("\nEncrypted data:\n");
			dump_array((unsigned char *) enc_text, sizeof(enc_text));
			printf("\nDecrypted data:\n");
			dump_array((unsigned char *) dec_text, sizeof(dec_text));
		}
		printf("Successful!\n");
	}

	return 0;
}

int test_aes256_new_api(int mode)
{
	ica_aes_vector_t iv;
	unsigned char key[AES_KEY_LEN256];
	int rc = 0;
	unsigned char dec_text[sizeof(NIST_TEST_DATA)],
		      enc_text[sizeof(NIST_TEST_DATA)];
	unsigned int i;

	bzero(dec_text, sizeof(dec_text));
	bzero(enc_text, sizeof(enc_text));
	bzero(iv, sizeof(iv));
	bcopy(NIST_KEY3, key, sizeof(NIST_KEY3));

	i = sizeof(enc_text);
	rc = ica_aes_encrypt(mode, sizeof(NIST_TEST_DATA), NIST_TEST_DATA, &iv,
			     AES_KEY_LEN256, key, enc_text);
	if (rc) {
		printf("ica_aes_encrypt failed with errno %d (0x%x).\n", rc, rc);
		return 1;
	}

	if (memcmp(enc_text, NIST_TEST_RESULT, sizeof(NIST_TEST_RESULT)) != 0) {
		printf("\nOriginal data:\n");
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		printf("\nEncrypted data:\n");
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		printf("This does NOT match the known result.\n");
		return 1;
	} else {
		printf("Yep, it's what it should be.\n");
	}

	bzero(iv, sizeof(iv));
	rc = ica_aes_decrypt(mode, sizeof(enc_text), enc_text, &iv,
			     AES_KEY_LEN256, key, dec_text);
	if (rc) {
		printf("ica_aes_decrypt failed with errno %d (0x%x).\n", rc, rc);
		return 1;
	}

	if (memcmp(dec_text, NIST_TEST_DATA, sizeof(NIST_TEST_DATA)) != 0) {
		printf("\nOriginal data:\n");
		dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
		printf("\nEncrypted data:\n");
		dump_array((unsigned char *) enc_text, sizeof(enc_text));
		printf("\nDecrypted data:\n");
		dump_array((unsigned char *) dec_text, sizeof(dec_text));
		printf("This does NOT match the original data.\n");
		return 1;
	} else {
		if (!silent) {
			printf("\nOriginal data:\n");
			dump_array((unsigned char *) NIST_TEST_DATA, sizeof(NIST_TEST_DATA));
			printf("\nEncrypted data:\n");
			dump_array((unsigned char *) enc_text, sizeof(enc_text));
			printf("\nDecrypted data:\n");
			dump_array((unsigned char *) dec_text, sizeof(dec_text));
		}
		printf("Successful!\n");
	}

	return 0;
}

int main(int argc, char **argv)
{
	// Default mode is 0. ECB and CBC tests will be performed.
	unsigned int mode = 0;
	if (argc > 1) {
		if (strstr(argv[1], "ecb"))
			mode = MODE_ECB;
		if (strstr(argv[1], "cbc"))
			mode = MODE_CBC;
		printf("mode = %i \n", mode);
		}
	if (mode != 0 && mode != MODE_ECB && mode != MODE_CBC) {
		printf("Usage: %s [ ecb | cbc ]\n", argv[0]);
		return -1;
	}
	int rc = 0;
	int error_count = 0;
	if (!mode) {
	/* This is the standard loop that will perform all testcases */
		mode = 2;
		while (mode) {
			rc = test_aes256_old_api(mode);
			if (rc) {
				error_count++;
				printf ("test_aes_old_api mode = %i failed \n", mode);
			}
			else
				printf ("test_aes_old_api mode = %i finished successfuly \n", mode);

			rc = test_aes256_new_api(mode);
			if (rc) {
				error_count++;
				printf ("test_aes_new_api mode = %i failed \n", mode);
			}
			else
				printf ("test_aes_new_api mode = %i finished successfuly \n", mode);

			mode--;
		}
		if (error_count)
			printf("%i testcases failed\n", error_count);
		else
			printf("All testcases finished successfuly\n");
	} else {
	/* Perform only the old test either ein ECB or CBC mode */
		silent = 0;
		rc = test_aes256_old_api(mode);
		if (rc)
			printf("test_aes_old_api mode = %i failed \n", mode);
		else
			printf("test_aes_old_api mode = %i finished successfuly \n", mode);

		rc = test_aes256_new_api(mode);
		if (rc)
			printf("test_aes_new_api mode = %i failed \n", mode);
		else
			printf("test_aes_new_api mode = %i finished successfuly \n", mode);
	}

	return rc;
}

