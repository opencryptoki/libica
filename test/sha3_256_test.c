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

unsigned char FIPS_TEST_RESULT[NUM_FIPS_TESTS][SHA3_256_HASH_LENGTH] =
{
  // SHA3_256 Hash for test 0: "abc"
  {
0x3A,0x98,0x5D,0xA7,0x4F,0xE2,0x25,0xB2,0x04,0x5C,0x17,0x2D,0x6B,0xD3,0x90,0xBD,
0x85,0x5F,0x08,0x6E,0x3E,0x9D,0x52,0x5B,0x46,0xBF,0xE2,0x45,0x11,0x43,0x15,0x32,

  },
  // SHA3_256 Hash for test 1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x41,0xC0,0xDB,0xA2,0xA9,0xD6,0x24,0x08,0x49,0x10,0x03,0x76,0xA8,0x23,0x5E,0x2C,
0x82,0xE1,0xB9,0x99,0x8A,0x99,0x9E,0x21,0xDB,0x32,0xDD,0x97,0x49,0x6D,0x33,0x76,

  },
  // SHA3_256 Hash for test 2: 1,000,000 'a'
  {
0x5C,0x88,0x75,0xAE,0x47,0x4A,0x36,0x34,0xBA,0x4F,0xD5,0x5E,0xC8,0x5B,0xFF,0xD6,
0x61,0xF3,0x2A,0xCA,0x75,0xC6,0xD6,0x99,0xD0,0xCD,0xCB,0x6C,0x11,0x58,0x91,0xC1,
  },
};

int new_api_sha3_256_test(void)
{
	sha3_256_context_t sha3_256_context;
	int rc = 0;
	int i = 0;
	unsigned char input_data[1000000];
	unsigned int  output_hash_length = SHA3_256_HASH_LENGTH;
	unsigned char output_hash[SHA3_256_HASH_LENGTH];
	unsigned int errors = 0;
	int input_length = 0;

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

		rc = ica_sha3_256(SHA_MSG_PART_ONLY, FIPS_TEST_DATA_SIZE[i], input_data,
				&sha3_256_context, output_hash);

		if (rc != 0) {
			V_(printf("icaSha3_256 failed with errno %d (0x%x).\n", rc, rc));
			return TEST_FAIL;
		}

		VV_(printf("\nOutput hash for test %d:\n", i));
		dump_array(output_hash, output_hash_length);
		if (memcmp(output_hash, FIPS_TEST_RESULT[i], SHA3_256_HASH_LENGTH) != 0) {
			VV_(printf("This does NOT match the known result.\n"));
			errors++;
		} else {
			VV_(printf("Yep, it's what it should be.\n"));
		}
	}

	// This test is the same as test 2, except that we use the SHA3_256_CONTEXT and
	// break it into calls of 1088 bytes each (which is 8 * 136, where 136 is the
	// SHA3_256 block length).

	V_(printf("\nOriginal data for test 2 (chunks = 1088) is calls of 1088 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {

		unsigned int sha_message_part;
		memset(input_data, 'a', 1088);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 1088)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		input_length = (i < 1088) ? i : 1088;

		rc = ica_sha3_256(sha_message_part, input_length,
				input_data, &sha3_256_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha3_256 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i-= 1088;
	}


	VV_(printf("\nOutput hash for test 2 (chunks = 1088):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA3_256_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	// This test is the same as test 2, except that we use the
	// SHA3_256_CONTEXT and break it into calls of 136 bytes each.
	V_(printf("\nOriginal data for test 2 (chunks = 136) is calls of 136 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 136);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 136)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha3_256(sha_message_part, (i < 136) ? i : 136,
				input_data, &sha3_256_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha3_256 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i -= 136;
	}

	VV_(printf("\nOutput hash for test 2 (chunks = 136):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA3_256_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	if (errors) {
		printf("%d out of %d SHA3_256 tests did not return the expected result.\n",
				errors, (NUM_FIPS_TESTS+2));
		return TEST_FAIL;
	}

	printf("All SHA3_256 tests passed.\n");
	return TEST_SUCC;
}

int main(int argc, char **argv)
{
	int rc = 0;

	set_verbosity(argc, argv);

	if (!sha3_available()) {
		printf("Skipping SHA3-256 test, because SHA3 not available on this machine.\n");
		return TEST_SKIP;
	}

	rc = new_api_sha3_256_test();
	if (rc) {
		printf("new_api_sha3_256_test: returned rc = %i\n", rc);
		return TEST_FAIL;
	}

	return TEST_SUCC;
}
