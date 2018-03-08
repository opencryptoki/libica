/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2016 */
/* (C) COPYRIGHT International Business Machines Corp. 2016          */
#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include <string.h>
#include "ica_api.h"
#include "testcase.h"

#define NUM_FIPS_TESTS 3

unsigned char FIPS_TEST_DATA[NUM_FIPS_TESTS][64] = {
  // Test 0: "abc"
  { 0x61,0x62,0x63 },
  // Test 1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x61,0x62,0x63,0x64,0x62,0x63,0x64,0x65,0x63,0x64,0x65,0x66,0x64,0x65,0x66,0x67,
0x65,0x66,0x67,0x68,0x66,0x67,0x68,0x69,0x67,0x68,0x69,0x6a,0x68,0x69,0x6a,0x6b,
0x69,0x6a,0x6b,0x6c,0x6a,0x6b,0x6c,0x6d,0x6b,0x6c,0x6d,0x6e,0x6c,0x6d,0x6e,0x6f,
0x6d,0x6e,0x6f,0x70,0x6e,0x6f,0x70,0x71,
  },
  // Test 2: 1,000,000 'a' -- don't actually use this... see the special case
  // in the loop below.
  {
0x61,
  },
};

unsigned int FIPS_TEST_DATA_SIZE[NUM_FIPS_TESTS] = {
  // Test 0: "abc"
  3,
  // Test 1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  56,
  // Test 2: 1,000,000 'a'
  1000000,
};

unsigned char FIPS_TEST_RESULT[NUM_FIPS_TESTS][SHA3_224_HASH_LENGTH] =
{
  // SHA3_224 Hash for test 0: "abc"
  {
0xe6,0x42,0x82,0x4c,0x3f,0x8c,0xf2,0x4a,0xd0,0x92,0x34,0xee,0x7d,0x3c,0x76,0x6f,
0xc9,0xa3,0xa5,0x16,0x8d,0x0c,0x94,0xad,0x73,0xb4,0x6f,0xdf,
  },
  // SHA3_224 Hash for test 1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x8a,0x24,0x10,0x8b,0x15,0x4a,0xda,0x21,0xc9,0xfd,0x55,0x74,0x49,0x44,0x79,0xba,
0x5c,0x7e,0x7a,0xb7,0x6e,0xf2,0x64,0xea,0xd0,0xfc,0xce,0x33,
  },
  // SHA3_224 Hash for test 2: 1,000,000 'a'
  {
0xd6,0x93,0x35,0xb9,0x33,0x25,0x19,0x2e,0x51,0x6a,0x91,0x2e,0x6d,0x19,0xa1,0x5c,
0xb5,0x1c,0x6e,0xd5,0xc1,0x52,0x43,0xe7,0xa7,0xfd,0x65,0x3c
  },
};

int new_api_sha3_224_test(void)
{
	sha3_224_context_t sha3_224_context;
	int rc = 0;
	int i = 0;
	unsigned char input_data[1000000];
	unsigned int  output_hash_length = SHA3_224_HASH_LENGTH;
	unsigned char output_hash[SHA3_224_HASH_LENGTH];
	unsigned int errors = 0;

	for (i = 0; i < NUM_FIPS_TESTS; i++) {
		// Test 2 is a special one, because we want to keep the size of the
		// executable down, so we build it special, instead of using a static
		if (i != 2)
			memcpy(input_data, FIPS_TEST_DATA[i], FIPS_TEST_DATA_SIZE[i]);
		else
			memset(input_data, 'a', FIPS_TEST_DATA_SIZE[i]);

		VV_(printf("\nOriginal data for test %d:\n", i));
		if (i != 2)
			dump_array(input_data, FIPS_TEST_DATA_SIZE[i]);
		else
			VV_(printf("Data suppressed (1.000.000 'a'), too much output.\n"));

		rc = ica_sha3_224(SHA_MSG_PART_ONLY, FIPS_TEST_DATA_SIZE[i], input_data,
				&sha3_224_context, output_hash);

		if (rc != 0) {
			V_(printf("icaSha3_224 failed with errno %d (0x%x).\n", rc, rc));
			return TEST_FAIL;
		}

		VV_(printf("\nOutput hash for test %d:\n", i));
		dump_array(output_hash, output_hash_length);
		if (memcmp(output_hash, FIPS_TEST_RESULT[i], SHA3_224_HASH_LENGTH) != 0) {
			VV_(printf("This does NOT match the known result.\n"));
			errors++;
		}
		else {
			VV_(printf("Yep, it's what it should be.\n"));
		}
	}

	// This test is the same as test 2, except that we use the SHA3_224_CONTEXT and
	// break it into calls of 1152 bytes each (which is 8 * 144, where 144 is the
	// SHA3_224 input block size).
	V_(printf("\nOriginal data for test 2 (chunks = 1152) is calls of 1152 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 1152);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 1152)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha3_224(sha_message_part, (i < 1152) ? i : 1152,
				input_data, &sha3_224_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha3_224 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i -= 1152;
	}

	VV_(printf("\nOutput hash for test 2 (chunks = 1152):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA3_224_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	// This test is the same as test 2, except that we use the
	// SHA3_224_CONTEXT and break it into calls of 144 bytes each.
	V_(printf("\nOriginal data for test 2 (chunks = 144) is calls of 144 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 144);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 144)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha3_224(sha_message_part, (i < 144) ? i : 144,
				input_data, &sha3_224_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha3_224 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i -= 144;
	}

	VV_(printf("\nOutput hash for test 2 (chunks = 144):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA3_224_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	} else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	if (errors) {
		printf("%d out of %d SHA3_224 tests did not return the expected result.\n",
				errors, (NUM_FIPS_TESTS+2));
		return TEST_FAIL;
	}

	printf("All SHA3_224 tests passed.\n");
	return TEST_SUCC;
}

int main(int argc, char **argv)
{
	int rc = 0;

	set_verbosity(argc, argv);

	if (!sha3_available()) {
		printf("Skipping SHA3-224 test, because SHA3 not available on this machine.\n");
		return TEST_SKIP;
	}

	rc = new_api_sha3_224_test();
	if (rc) {
		printf("new_api_sha3_224_test: returned rc = %i\n", rc);
		return TEST_FAIL;
	}

	return TEST_SUCC;
}
