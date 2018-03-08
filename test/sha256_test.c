/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2005, 2009, 2011 */
/* (C) COPYRIGHT International Business Machines Corp. 2005, 2009          */
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

unsigned char FIPS_TEST_RESULT[NUM_FIPS_TESTS][SHA256_HASH_LENGTH] =
{
  // Hash for test 0: "abc"
  {
0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD,
  },
  // Hash for test 1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x24,0x8D,0x6A,0x61,0xD2,0x06,0x38,0xB8,0xE5,0xC0,0x26,0x93,0x0C,0x3E,0x60,0x39,
0xA3,0x3C,0xE4,0x59,0x64,0xFF,0x21,0x67,0xF6,0xEC,0xED,0xD4,0x19,0xDB,0x06,0xC1,
  },
  // Hash for test 2: 1,000,000 'a'
  {
0xCD,0xC7,0x6E,0x5C,0x99,0x14,0xFB,0x92,0x81,0xA1,0xC7,0xE2,0x84,0xD7,0x3E,0x67,
0xF1,0x80,0x9A,0x48,0xA4,0x97,0x20,0x0E,0x04,0x6D,0x39,0xCC,0xC7,0x11,0x2C,0xD0,
  },
};

int new_api_sha256_test(void)
{
	sha256_context_t sha256_context;
	int rc = 0;
	int i = 0;
	unsigned char input_data[1000000];
	unsigned int  output_hash_length = SHA256_HASH_LENGTH;
	unsigned char output_hash[SHA256_HASH_LENGTH];

	for (i = 0; i < NUM_FIPS_TESTS; i++) {
		// Test 2 is a special one, because we want to keep the size of the
		// executable down, so we build it special, instead of using a static
		if (i != 2)
			memcpy(input_data, FIPS_TEST_DATA[i], FIPS_TEST_DATA_SIZE[i]);
		else
			memset(input_data, 'a', FIPS_TEST_DATA_SIZE[i]);

		VV_(printf("\nOriginal data for test %d:\n", i));
		dump_array(input_data, FIPS_TEST_DATA_SIZE[i]);

		rc = ica_sha256(SHA_MSG_PART_ONLY, FIPS_TEST_DATA_SIZE[i], input_data,
				&sha256_context, output_hash);

		if (rc != 0) {
			V_(printf("icaSha256 failed with errno %d (0x%x).\n", rc, rc));
			return TEST_FAIL;
		}

		VV_(printf("\nOutput hash for test %d:\n", i));
		dump_array(output_hash, output_hash_length);
		if (memcmp(output_hash, FIPS_TEST_RESULT[i], SHA256_HASH_LENGTH) != 0) {
			VV_(printf("This does NOT match the known result.\n"));
		}
		else {
			VV_(printf("Yep, it's what it should be.\n"));
		}
	}

	// This test is the same as test 2, except that we use the SHA256_CONTEXT and
	// break it into calls of 1024 bytes each.
	V_(printf("\nOriginal data for test 2(chunks = 1024) is calls of 1024"
	       " 'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 1024);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 1024)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha256(sha_message_part, (i < 1024) ? i : 1024,
				input_data, &sha256_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha256 failed with errno %d (0x%x) on"
			       " iteration %d.\n", rc, rc, i));
			return TEST_FAIL;
		}
		i -= 1024;
	}

	VV_(printf("\nOutput hash for test 2(chunks = 1024):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA256_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	// This test is the same as test 2, except that we use the
	// SHA256_CONTEXT and break it into calls of 64 bytes each.
	V_(printf("\nOriginal data for test 2(chunks = 64) is calls of 64 'a's at"
	       " a time\n"));
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 64);

		if (i == (int)FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 64)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha256(sha_message_part, (i < 64) ? i : 64,
				input_data, &sha256_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha256 failed with errno %d (0x%x) on iteration"
			       " %d.\n", rc, rc, i));
			return TEST_FAIL;
		}
		i -= 64;
	}

	VV_(printf("\nOutput hash for test 2(chunks = 64):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], SHA256_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	printf("All SHA256 tests passed.\n");
	return TEST_SUCC;
}

int main(int argc, char **argv)
{
	int rc = 0;

	set_verbosity(argc, argv);

	rc = new_api_sha256_test();
	if (rc) {
		printf("new_api_sha256_test: returned rc = %i\n", rc);
		return TEST_FAIL;
	}

	return TEST_SUCC;
}
