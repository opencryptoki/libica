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

unsigned char FIPS_TEST_RESULT[NUM_FIPS_TESTS][SHA3_384_HASH_LENGTH] =
{
  // SHA3_384 Hash for test 0: "abc"
  {
0xEC,0x01,0x49,0x82,0x88,0x51,0x6F,0xC9,0x26,0x45,0x9F,0x58,0xE2,0xC6,0xAD,0x8D,
0xF9,0xB4,0x73,0xCB,0x0F,0xC0,0x8C,0x25,0x96,0xDA,0x7C,0xF0,0xE4,0x9B,0xE4,0xB2,
0x98,0xD8,0x8C,0xEA,0x92,0x7A,0xC7,0xF5,0x39,0xF1,0xED,0xF2,0x28,0x37,0x6D,0x25,
  },
  // SHA3_384 Hash for test 1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x99,0x1C,0x66,0x57,0x55,0xEB,0x3A,0x4B,0x6B,0xBD,0xFB,0x75,0xC7,0x8A,0x49,0x2E,
0x8C,0x56,0xA2,0x2C,0x5C,0x4D,0x7E,0x42,0x9B,0xFD,0xBC,0x32,0xB9,0xD4,0xAD,0x5A,
0xA0,0x4A,0x1F,0x07,0x6E,0x62,0xFE,0xA1,0x9E,0xEF,0x51,0xAC,0xD0,0x65,0x7C,0x22,

  },
  // SHA3_384 Hash for test 2: 1,000,000 'a'
  {
0xEE,0xE9,0xE2,0x4D,0x78,0xC1,0x85,0x53,0x37,0x98,0x34,0x51,0xDF,0x97,0xC8,0xAD,
0x9E,0xED,0xF2,0x56,0xC6,0x33,0x4F,0x8E,0x94,0x8D,0x25,0x2D,0x5E,0x0E,0x76,0x84,
0x7A,0xA0,0x77,0x4D,0xDB,0x90,0xA8,0x42,0x19,0x0D,0x2C,0x55,0x8B,0x4B,0x83,0x40,
  },
};

int new_api_sha3_384_test(void)
{
	sha3_384_context_t sha3_384_context;
	int rc = 0;
	int i = 0;
	unsigned char input_data[1000000];
	unsigned int  output_hash_length = SHA3_384_HASH_LENGTH;
	unsigned char output_hash[SHA3_384_HASH_LENGTH];
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

		rc = ica_sha3_384(SHA_MSG_PART_ONLY, FIPS_TEST_DATA_SIZE[i], input_data,
				&sha3_384_context, output_hash);

		if (rc != 0) {
			V_(printf("icaSha3_384 failed with errno %d (0x%x).\n", rc, rc));
			return TEST_FAIL;
		}

		VV_(printf("\nOutput hash for test %d:\n", i));
		dump_array(output_hash, output_hash_length);
		if (memcmp(output_hash, FIPS_TEST_RESULT[i], SHA3_384_HASH_LENGTH) != 0) {
			VV_(printf("This does NOT match the known result.\n"));
			errors++;
		} else {
			VV_(printf("Yep, it's what it should be.\n"));
		}
	}

	// This test is the same as test 2, except that we use the SHA3_384_CONTEXT and
	// break it into calls of 1040 bytes each (which is 10 * 104, where 104 is the
	// SHA3_384 input block size).
	V_(printf("\nOriginal data for test 2 (chunks = 1040) is calls of 1040 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 1040);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 1040)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha3_384(sha_message_part, (i < 1040) ? i : 1040,
				input_data, &sha3_384_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha3_384 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i -= 1040;
	}

	VV_(printf("\nOutput hash for test 2 (chunks = 1040):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA3_384_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	// This test is the same as test 2, except that we use the
	// SHA3_512_CONTEXT and break it into calls of 104 bytes each.
	V_(printf("\nOriginal data for test 2 (chunks = 104) is calls of 104 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 104);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 104)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha3_384(sha_message_part, (i < 104) ? i : 104,
				input_data, &sha3_384_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha3_384 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i -= 104;
	}

	VV_(printf("\nOutput hash for test 2 (chunks = 104):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA3_384_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	if (errors) {
		printf("%d out of %d SHA3_384 tests did not return the expected result.\n",
				errors, (NUM_FIPS_TESTS+2));
		return TEST_FAIL;
	}

	printf("All SHA3_384 tests passed.\n");
	return TEST_SUCC;
}

int main(int argc, char **argv)
{
	int rc = 0;

	set_verbosity(argc, argv);

	if (!sha3_available()) {
		printf("Skipping SHA3-384 test, because SHA3 not available on this machine.\n");
		return TEST_SKIP;
	}

	rc = new_api_sha3_384_test();
	if (rc) {
		printf("new_api_sha3_384_test: returned rc = %i\n", rc);
		return TEST_FAIL;
	}

	return TEST_SUCC;
}
