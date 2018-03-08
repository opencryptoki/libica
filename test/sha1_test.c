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
#include "ica_api.h"
#include "testcase.h"

#define NUM_FIPS_TESTS 4

unsigned char FIPS_TEST_DATA[NUM_FIPS_TESTS][64] = {
  // Test 0: NULL
  { 0x00 },
  // Test 1: "abc"
  { 0x61,0x62,0x63 },
  // Test 2: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x61,0x62,0x63,0x64,0x62,0x63,0x64,0x65,0x63,0x64,0x65,0x66,0x64,0x65,0x66,0x67,
0x65,0x66,0x67,0x68,0x66,0x67,0x68,0x69,0x67,0x68,0x69,0x6a,0x68,0x69,0x6a,0x6b,
0x69,0x6a,0x6b,0x6c,0x6a,0x6b,0x6c,0x6d,0x6b,0x6c,0x6d,0x6e,0x6c,0x6d,0x6e,0x6f,
0x6d,0x6e,0x6f,0x70,0x6e,0x6f,0x70,0x71,
  },
  // Test 3: 1,000,000 'a' -- don't actually use this... see the special case
  // in the loop below.
  {
0x61,
  },
};

unsigned int FIPS_TEST_DATA_SIZE[NUM_FIPS_TESTS] = {
  // Test 0: NULL
  0,
  // Test 1: "abc"
  3,
  // Test 2: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  56,
  // Test 3: 1,000,000 'a'
  1000000,
};

unsigned char FIPS_TEST_RESULT[NUM_FIPS_TESTS][SHA_HASH_LENGTH] =
{
  // Hash for test 0: NULL
  {
0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,
0xaf,0xd8,0x07,0x09,
  },
  // Hash for test 1: "abc"
  {
0xA9,0x99,0x3E,0x36,0x47,0x06,0x81,0x6A,0xBA,0x3E,0x25,0x71,0x78,0x50,0xC2,0x6C,
0x9C,0xD0,0xD8,0x9D,
  },
  // Hash for test 2: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x84,0x98,0x3E,0x44,0x1C,0x3B,0xD2,0x6E,0xBA,0xAE,0x4A,0xA1,0xF9,0x51,0x29,0xE5,
0xE5,0x46,0x70,0xF1,
  },
  // Hash for test 3: 1,000,000 'a'
  {
0x34,0xAA,0x97,0x3C,0xD4,0xC4,0xDA,0xA4,0xF6,0x1E,0xEB,0x2B,0xDB,0xAD,0x27,0x31,
0x65,0x34,0x01,0x6F,
  },
};

int new_api_sha_test(void)
{
	V_(printf("Test of new sha api\n"));
	sha_context_t sha_context;
	int rc = 0;
	int i = 0;
	unsigned char input_data[1000000];
	unsigned int  output_hash_length = SHA_HASH_LENGTH;
	unsigned char output_hash[SHA_HASH_LENGTH];

	for (i = 0; i < NUM_FIPS_TESTS; i++) {
	// Test 3 is a special one, because we want to keep the size of the
	// executable down, so we build it special, instead of using a static
	if (i != 3)
		memcpy(input_data, FIPS_TEST_DATA[i], FIPS_TEST_DATA_SIZE[i]);
	else
		memset(input_data, 'a', FIPS_TEST_DATA_SIZE[i]);

	VV_(printf("\nOriginal data for test %d:\n", i));
	dump_array(input_data, FIPS_TEST_DATA_SIZE[i]);

	rc = ica_sha1(SHA_MSG_PART_ONLY, FIPS_TEST_DATA_SIZE[i], input_data,
		      &sha_context, output_hash);

	if (rc != 0) {
		V_(printf("icaSha1 failed with errno %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	VV_(printf("\nOutput hash for test %d:\n", i));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[i], SHA_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
	}
	else
		VV_(printf("Yep, it's what it should be.\n"));
	}

	// This test is the same as test 3, except that we use the SHA_CONTEXT
	// and break it into calls of 1024 bytes each.
	V_(printf("\nOriginal data for test 3(chunks = 1024) is calls of 1024"
	       "'a's at a time\n"));
	i = FIPS_TEST_DATA_SIZE[3];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 1024);

		if (i == (int)FIPS_TEST_DATA_SIZE[3])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 1024)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha1(sha_message_part, (i < 1024) ? i : 1024,
			      input_data, &sha_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha1 failed with errno %d (0x%x) on"
			       " iteration %d.\n", rc, rc, i));
			return TEST_FAIL;
		}
		i -= 1024;
	}

	VV_(printf("\nOutput hash for test 3(chunks = 1024):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[3], SHA_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	// This test is the same as test 3, except that we use the SHA_CONTEXT
	// and break it into calls of 64 bytes each.
	V_(printf("\nOriginal data for test 3(chunks = 64) is calls of 64 'a's at"
	       "a time\n"));
	i = FIPS_TEST_DATA_SIZE[3];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 64);

		if (i == (int)FIPS_TEST_DATA_SIZE[3])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 64)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha1(sha_message_part, (i < 64) ? i : 64, input_data,
			      &sha_context, output_hash);

		if (rc != 0) {
			V_(printf("ica_sha1 failed with errno %d (0x%x) on"
			       " iteration %d.\n", rc, rc, i));
			return TEST_FAIL;
		}
		i -= 64;
	}

	VV_(printf("\nOutput hash for test 3(chunks = 64):\n"));
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[3], SHA_HASH_LENGTH) != 0) {
		VV_(printf("This does NOT match the known result.\n"));
	}
	else {
		VV_(printf("Yep, it's what it should be.\n"));
	}

	printf("All SHA1 tests passed.\n");

	return TEST_SUCC;
}

int main(int argc, char **argv)
{
	int rc = 0;

	set_verbosity(argc, argv);

	rc = new_api_sha_test();
	if (rc) {
		printf("new_api_sha_test failed with rc = %i\n", rc);
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

