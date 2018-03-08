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

unsigned char FIPS_TEST_RESULT[NUM_FIPS_TESTS][SHA3_512_HASH_LENGTH] =
{
  // SHA3_512 Hash for test 0: "abc"
  {
0xB7,0x51,0x85,0x0B,0x1A,0x57,0x16,0x8A,0x56,0x93,0xCD,0x92,0x4B,0x6B,0x09,0x6E,
0x08,0xF6,0x21,0x82,0x74,0x44,0xF7,0x0D,0x88,0x4F,0x5D,0x02,0x40,0xD2,0x71,0x2E,
0x10,0xE1,0x16,0xE9,0x19,0x2A,0xF3,0xC9,0x1A,0x7E,0xC5,0x76,0x47,0xE3,0x93,0x40,
0x57,0x34,0x0B,0x4C,0xF4,0x08,0xD5,0xA5,0x65,0x92,0xF8,0x27,0x4E,0xEC,0x53,0xF0,
  },
  // SHA3_512 Hash for test 1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x04,0xA3,0x71,0xE8,0x4E,0xCF,0xB5,0xB8,0xB7,0x7C,0xB4,0x86,0x10,0xFC,0xA8,0x18,
0x2D,0xD4,0x57,0xCE,0x6F,0x32,0x6A,0x0F,0xD3,0xD7,0xEC,0x2F,0x1E,0x91,0x63,0x6D,
0xEE,0x69,0x1F,0xBE,0x0C,0x98,0x53,0x02,0xBA,0x1B,0x0D,0x8D,0xC7,0x8C,0x08,0x63,
0x46,0xB5,0x33,0xB4,0x9C,0x03,0x0D,0x99,0xA2,0x7D,0xAF,0x11,0x39,0xD6,0xE7,0x5E,

  },
  // SHA3_512 Hash for test 2: 1,000,000 'a'
  {
0x3C,0x3A,0x87,0x6D,0xA1,0x40,0x34,0xAB,0x60,0x62,0x7C,0x07,0x7B,0xB9,0x8F,0x7E,
0x12,0x0A,0x2A,0x53,0x70,0x21,0x2D,0xFF,0xB3,0x38,0x5A,0x18,0xD4,0xF3,0x88,0x59,
0xED,0x31,0x1D,0x0A,0x9D,0x51,0x41,0xCE,0x9C,0xC5,0xC6,0x6E,0xE6,0x89,0xB2,0x66,
0xA8,0xAA,0x18,0xAC,0xE8,0x28,0x2A,0x0E,0x0D,0xB5,0x96,0xC9,0x0B,0x0A,0x7B,0x87,
  },
};

int new_api_sha3_512_test(void)
{
	sha3_512_context_t sha3_512_context;
	int rc = 0;
	int i = 0;
	unsigned char input_data[1000000];
	unsigned int  output_hash_length = SHA3_512_HASH_LENGTH;
	unsigned char output_hash[SHA3_512_HASH_LENGTH];
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

		rc = ica_sha3_512(SHA_MSG_PART_ONLY, FIPS_TEST_DATA_SIZE[i], input_data,
				&sha3_512_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha3_512 failed with errno %d (0x%x).\n", rc, rc));
			return TEST_FAIL;
		}

		VV_(printf("\nOutput hash for test %d:\n", i));
		dump_array(output_hash, output_hash_length);
		if (memcmp(output_hash, FIPS_TEST_RESULT[i], SHA3_512_HASH_LENGTH) != 0) {
			VV_(printf("This does NOT match the known result.\n"));
			errors++;
		} else {
			VV_(printf("Yep, it's what it should be.\n"));
		}
	}

	// This test is the same as test 2, except that we use the SHA512_CONTEXT and
	// break it into calls of 1152 bytes each (which is 16 * 72, where 72 is the
	// SHA3-512 input block size).
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

		rc = ica_sha3_512(sha_message_part, (i < 1152) ? i : 1152,
				input_data, &sha3_512_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha3_512 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i -= 1152;
	}

	VV_(printf("\nOutput hash for test 2 (chunks = 1152):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA3_512_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	} else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	// This test is the same as test 2, except that we use the
	// SHA3_512_CONTEXT and break it into calls of 72 bytes each.
	V_(printf("\nOriginal data for test 2 (chunks = 72) is calls of 72 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 72);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 72)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha3_512(sha_message_part, (i < 72) ? i : 72,
				input_data, &sha3_512_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha3_512 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i -= 72;
	}

	VV_(printf("\nOutput hash for test 2 (chunks = 72):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA3_512_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	if (errors) {
		printf("%d out of %d SHA3_512 tests did not return the expected result.\n",
				errors, (NUM_FIPS_TESTS+2));
		return TEST_FAIL;
	}

	printf("All SHA3_512 tests passed.\n");
	return TEST_SUCC;
}

int main(int argc, char **argv)
{
	int rc = 0;

	set_verbosity(argc, argv);

	if (!sha3_available()) {
		printf("Skipping SHA3-512 test, because SHA3 not available on this machine.\n");
		return TEST_SKIP;
	}

	rc = new_api_sha3_512_test();
	if (rc) {
		printf("new_api_sha3_512_test: returned rc = %i\n", rc);
		return TEST_FAIL;
	}

	return TEST_SUCC;
}
