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
#include <stdlib.h>
#include "ica_api.h"
#include "testcase.h"

#define NUM_FIPS_TESTS 3

/**
 * The SHAKE algo has a variable output length, so we cannot use a static
 * value as for the other SHA algos. However, a known answer test requires
 * having pre-calculated results, so let's use a fixed output length of
 * 512 bits (64 bytes) for this test.
 */
#define SHAKE128_64_HASH_LENGTH  64

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

unsigned char FIPS_TEST_RESULT[NUM_FIPS_TESTS][SHAKE128_64_HASH_LENGTH] =
{
  // SHAKE_128(512) Hash for test 0: "abc"
  {
0x58,0x81,0x09,0x2D,0xD8,0x18,0xBF,0x5C,0xF8,0xA3,0xDD,0xB7,0x93,0xFB,0xCB,0xA7,
0x40,0x97,0xD5,0xC5,0x26,0xA6,0xD3,0x5F,0x97,0xB8,0x33,0x51,0x94,0x0F,0x2C,0xC8,
0x44,0xC5,0x0A,0xF3,0x2A,0xCD,0x3F,0x2C,0xDD,0x06,0x65,0x68,0x70,0x6F,0x50,0x9B,
0xC1,0xBD,0xDE,0x58,0x29,0x5D,0xAE,0x3F,0x89,0x1A,0x9A,0x0F,0xCA,0x57,0x83,0x78,
  },
  // SHAKE_128(512) Hash for test 1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x1A,0x96,0x18,0x2B,0x50,0xFB,0x8C,0x7E,0x74,0xE0,0xA7,0x07,0x78,0x8F,0x55,0xE9,
0x82,0x09,0xB8,0xD9,0x1F,0xAD,0xE8,0xF3,0x2F,0x8D,0xD5,0xCF,0xF7,0xBF,0x21,0xF5,
0x4E,0xE5,0xF1,0x95,0x50,0x82,0x5A,0x6E,0x07,0x00,0x30,0x51,0x9E,0x94,0x42,0x63,
0xAC,0x1C,0x67,0x65,0x28,0x70,0x65,0x62,0x1F,0x9F,0xCB,0x32,0x01,0x72,0x3E,0x32,
  },
  // SHAKE_128(512) Hash for test 2: 1,000,000 'a'
  {
0x9D,0x22,0x2C,0x79,0xC4,0xFF,0x9D,0x09,0x2C,0xF6,0xCA,0x86,0x14,0x3A,0xA4,0x11,
0xE3,0x69,0x97,0x38,0x08,0xEF,0x97,0x09,0x32,0x55,0x82,0x6C,0x55,0x72,0xEF,0x58,
0x42,0x4C,0x4B,0x5C,0x28,0x47,0x5F,0xFD,0xCF,0x98,0x16,0x63,0x86,0x7F,0xEC,0x63,
0x21,0xC1,0x26,0x2E,0x38,0x7B,0xCC,0xF8,0xCA,0x67,0x68,0x84,0xC4,0xA9,0xD0,0xC1,
  },
};

int new_api_shake_128_test(void)
{
	shake_128_context_t shake_128_context;
	int rc = 0;
	int i = 0;
	unsigned char input_data[1000000];
	unsigned int  output_hash_length = SHAKE128_64_HASH_LENGTH;
	unsigned char output_hash[SHAKE128_64_HASH_LENGTH];
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

		rc = ica_shake_128(SHA_MSG_PART_ONLY, FIPS_TEST_DATA_SIZE[i], input_data,
				&shake_128_context, output_hash, SHAKE128_64_HASH_LENGTH);

		if (rc != 0) {
			V_(printf("icaShake_128 failed with errno %d (0x%x).\n", rc, rc));
			return TEST_FAIL;
		}

		VV_(printf("\nOutput hash for test %d:\n", i));
		dump_array(output_hash, output_hash_length);
		if (memcmp(output_hash, FIPS_TEST_RESULT[i], SHAKE128_64_HASH_LENGTH) != 0) {
			VV_(printf("This does NOT match the known result.\n"));
			errors++;
		} else {
			VV_(printf("Yep, it's what it should be.\n"));
		}
	}

	// This test is the same as test 2, except that we use the SHAKE128_CONTEXT and
	// break it into calls of 1008 bytes each (which is 6 * 168, where 168 is the
	// SHAKE128 data block size.
	V_(printf("\nOriginal data for test 2 (chunks = 1008) is calls of 1008 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 1008);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 1008)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_shake_128(sha_message_part, (i < 1008) ? i : 1008,
				input_data, &shake_128_context, output_hash,
				SHAKE128_64_HASH_LENGTH);

		if (rc != 0) {
			V_(printf("ica_shake_128 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i -= 1008;
	}

	VV_(printf("\nOutput hash for test 2 (chunks = 1008):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHAKE128_64_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	// This test is the same as test 2, except that we use the
	// SHAKE_128_CONTEXT and break it into calls of 168 bytes each.
	V_(printf("\nOriginal data for test 2 (chunks = 168) is calls of 168 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 168);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 168)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_shake_128(sha_message_part, (i < 168) ? i : 168,
				input_data, &shake_128_context, output_hash,
				SHAKE128_64_HASH_LENGTH);

		if (rc != 0) {
			V_(printf("ica_shake_128 failed with errno %d (0x%x) on iteration %d.\n",
					rc, rc, i));
			return TEST_FAIL;
		}
		i -= 168;
	}

	VV_(printf("\nOutput hash for test 2 (chunks = 168):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHAKE128_64_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
		errors++;
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	if (errors) {
		printf("%d out of %d SHAKE_128 tests did not return the expected result.\n",
				errors, (NUM_FIPS_TESTS+2));
		return TEST_FAIL;
	} else {
		printf("All SHAKE_128 tests passed.\n");
		return TEST_SUCC;
	}
}

int main(int argc, char **argv)
{
	int rc = 0;

	set_verbosity(argc, argv);

	if (!sha3_available()) {
		printf("Skipping SHAKE-128 test, because SHA3/SHAKE not available on this machine.\n");
		return TEST_SKIP;
	}

	rc = new_api_shake_128_test();
	if (rc) {
		printf("new_api_shake_128_test: returned rc = %i\n", rc);
		return TEST_FAIL;
	}

	return TEST_SUCC;
}
