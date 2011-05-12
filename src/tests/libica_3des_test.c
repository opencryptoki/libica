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


unsigned char NIST_KEY1[] =
                  { 0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57 };

unsigned char NIST_KEY2[] =
                  { 0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57 };

unsigned char NIST_KEY3[] =
                  { 0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57 };

unsigned char NIST_TEST_DATA[] =
                  { 0x01, 0xa1, 0xd6, 0xd0, 0x39, 0x77, 0x67, 0x42 };

unsigned char NIST_TEST_RESULT[] =
                  { 0x69, 0x0f, 0x5b, 0x0d, 0x9a, 0x26, 0x93, 0x9b };

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

int test_3des_old_api(int mode)
{
	ica_adapter_handle_t adapter_handle;
	ica_des_vector_t iv;
	ica_des_key_triple_t key;
	int rc = 0;
	unsigned char dec_text[sizeof(NIST_TEST_DATA)],
		      enc_text[sizeof(NIST_TEST_DATA)];
	unsigned int i;

	bzero(dec_text, sizeof(dec_text));
	bzero(enc_text, sizeof(enc_text));
	bzero(iv, sizeof(iv));
	bcopy(NIST_KEY1, key.key1, sizeof(NIST_KEY1));
	bcopy(NIST_KEY2, key.key2, sizeof(NIST_KEY2));
	bcopy(NIST_KEY3, key.key3, sizeof(NIST_KEY3));

	printf("\nOriginal data:\n");
	dump_array(NIST_TEST_DATA, sizeof(NIST_TEST_DATA));

	i = sizeof(enc_text);
	rc = icaTDesEncrypt(adapter_handle, mode, sizeof(NIST_TEST_DATA),
			    NIST_TEST_DATA, &iv, &key, &i, enc_text);
	if (rc != 0) {
		printf("icaTDesEncrypt failed with errno %d (0x%x).\n", rc, rc);
		return rc;
	}
	if (i != sizeof(enc_text)) {
		printf("icaTDesEncrypt returned an incorrect output data"
		       "length, %u (0x%x).\n", i, i);
		return -1;
	}

	printf("\nEncrypted data:\n");
	dump_array(enc_text, sizeof(enc_text));
	if (memcmp(enc_text, NIST_TEST_RESULT, sizeof NIST_TEST_RESULT) != 0) {
		printf("This does NOT match the known result.\n");
		return -1;
	} else {
		printf("Yep, it's what it should be.\n");
	}

	i = sizeof dec_text;
	bzero(iv, sizeof(iv));
	rc = icaTDesDecrypt(adapter_handle, mode, sizeof(enc_text), enc_text,
			    &iv, &key, &i, dec_text);
	if (rc != 0) {
		printf("icaTDesDecrypt failed with errno %d (0x%x).\n", rc, rc);
		return rc;
	}
	if (i != sizeof(dec_text)) {
		printf("icaTDesDecrypt returned an incorrect output data"
		       "length, %u (0x%x).\n", i, i);
		return rc;
	}

	printf("\nDecrypted data:\n");
	dump_array(dec_text, sizeof(dec_text));
	if (memcmp(dec_text, NIST_TEST_DATA, sizeof(NIST_TEST_DATA)) != 0) {
		printf("This does NOT match the original data.\n");
		return -1;
	} else {
		printf("Successful!\n");
	}

	return 0;
}

int test_3des_new_api(int mode)
{
	ica_des_vector_t iv;
	ica_des_key_triple_t key;
	int rc = 0;
	unsigned char dec_text[sizeof(NIST_TEST_DATA)],
		      enc_text[sizeof(NIST_TEST_DATA)];

	bzero(dec_text, sizeof(dec_text));
	bzero(enc_text, sizeof(enc_text));
	bzero(iv, sizeof(iv));
	bcopy(NIST_KEY1, key.key1, sizeof(NIST_KEY1));
	bcopy(NIST_KEY2, key.key2, sizeof(NIST_KEY2));
	bcopy(NIST_KEY3, key.key3, sizeof(NIST_KEY3));

	printf("\nOriginal data:\n");
	dump_array(NIST_TEST_DATA, sizeof(NIST_TEST_DATA));

	rc = ica_3des_encrypt(mode, sizeof(NIST_TEST_DATA), NIST_TEST_DATA,
			      &iv, &key, enc_text);
	if (rc != 0) {
		printf("ica_3des_encrypt failed with errno %d (0x%x).\n", rc, rc);
		return rc;
	}

	printf("\nEncrypted data:\n");
	dump_array(enc_text, sizeof(enc_text));
	if (memcmp(enc_text, NIST_TEST_RESULT, sizeof NIST_TEST_RESULT) != 0) {
		printf("This does NOT match the known result.\n");
		return -1;
	} else {
		printf("Yep, it's what it should be.\n");
	}

	bzero(iv, sizeof(iv));
	rc = ica_3des_decrypt(mode, sizeof(enc_text), enc_text,
			    &iv, &key, dec_text);
	if (rc != 0) {
		printf("ica_3des_decrypt failed with errno %d (0x%x).\n", rc, rc);
		return rc;
	}

	printf("\nDecrypted data:\n");
	dump_array(dec_text, sizeof(dec_text));
	if (memcmp(dec_text, NIST_TEST_DATA, sizeof(NIST_TEST_DATA)) != 0) {
		printf("This does NOT match the original data.\n");
		return -1;
	} else {
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
			rc = test_3des_old_api(mode);
			if (rc) {
				error_count++;
				printf ("test_des_old_api mode = %i failed \n", mode);
			}
			else
				printf ("test_des_old_api mode = %i finished successfuly \n", mode);

			rc = test_3des_new_api(mode);
			if (rc) {
				error_count++;
				printf ("test_des_new_api mode = %i failed \n", mode);
			}
			else
				printf ("test_des_new_api mode = %i finished successfuly \n", mode);

			mode--;
		}
		if (error_count)
			printf("%i testcases failed\n", error_count);
		else
			printf("All testcases finished successfuly\n");
	} else {
	/* Perform only the old test either ein ECB or CBC mode */
		silent = 0;
		rc = test_3des_old_api(mode);
		if (rc)
			printf("test_des_old_api mode = %i failed \n", mode);
		else
			printf("test_des_old_api mode = %i finished successfuly \n", mode);

		rc = test_3des_new_api(mode);
		if (rc)
			printf ("test_des_new_api mode = %i failed \n", mode);
		else
			printf ("test_des_new_api mode = %i finished successfuly \n", mode);
	}

	return rc;
}

