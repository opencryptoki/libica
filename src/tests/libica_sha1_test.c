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

unsigned char FIPS_TEST_RESULT[NUM_FIPS_TESTS][LENGTH_SHA_HASH] =
{
  // Hash for test 0: "abc"
  {
0xA9,0x99,0x3E,0x36,0x47,0x06,0x81,0x6A,0xBA,0x3E,0x25,0x71,0x78,0x50,0xC2,0x6C,
0x9C,0xD0,0xD8,0x9D,
  },
  // Hash for test 1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
0x84,0x98,0x3E,0x44,0x1C,0x3B,0xD2,0x6E,0xBA,0xAE,0x4A,0xA1,0xF9,0x51,0x29,0xE5,
0xE5,0x46,0x70,0xF1,
  },
  // Hash for test 2: 1,000,000 'a'
  {
0x34,0xAA,0x97,0x3C,0xD4,0xC4,0xDA,0xA4,0xF6,0x1E,0xEB,0x2B,0xDB,0xAD,0x27,0x31,
0x65,0x34,0x01,0x6F,
  },
};

void dump_array(unsigned char *ptr, unsigned int size)
{
  unsigned char *ptr_end;
  unsigned char *h;
  int i = 1, trunc = 0;

  if (size > 64) {
    trunc = size - 64;
    size = 64;
  }
  h = ptr;
  ptr_end = ptr + size;
  while (h < ptr_end) {
    printf("0x%02x ", *h);
    h++;
    if (i == 8) {
      if (h != ptr_end)
        printf("\n");
      i = 1;
    } else {
     ++i;
    }
  }
  printf("\n");
  if (trunc > 0)
    printf("... %d bytes not printed\n", trunc);
}

int old_api_sha_test(void)
{
	printf("Test of old sha api\n");
  ICA_ADAPTER_HANDLE adapter_handle;
  SHA_CONTEXT ShaContext;
  int rc = 0, i = 0;
  unsigned char input_data[1000000];
  unsigned int  output_hash_length = LENGTH_SHA_HASH;
  unsigned char output_hash[LENGTH_SHA_HASH];

  rc = icaOpenAdapter(0, &adapter_handle);
  if (rc != 0) {
    printf("icaOpenAdapter failed and returned %d (0x%x).\n", rc, rc);
    return 2;
  }

  for (i = 0; i < NUM_FIPS_TESTS; i++) {
    // Test 2 is a special one, because we want to keep the size of the
    // executable down, so we build it special, instead of using a static
    if (i != 2)
      memcpy(input_data, FIPS_TEST_DATA[i], FIPS_TEST_DATA_SIZE[i]);
    else
      memset(input_data, 'a', FIPS_TEST_DATA_SIZE[i]);

    printf("\nOriginal data for test %d:\n", i);
    dump_array(input_data, FIPS_TEST_DATA_SIZE[i]);

    rc = icaSha1(adapter_handle,
                 SHA_MSG_PART_ONLY,
                 FIPS_TEST_DATA_SIZE[i],
                 input_data,
                 LENGTH_SHA_CONTEXT,
                 &ShaContext,
                 &output_hash_length,
                 output_hash);

    if (rc != 0) {
      printf("icaSha1 failed with errno %d (0x%x).\n", rc, rc);
#ifdef __s390__
      if (rc == ENODEV)
        printf("The usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif
      return 2;
    }

    if (output_hash_length != LENGTH_SHA_HASH) {
      printf("icaSha1 returned an incorrect output data length, %u (0x%x).\n",
             output_hash_length, output_hash_length);
      return 2;
    }

    printf("\nOutput hash for test %d:\n", i);
    dump_array(output_hash, output_hash_length);
    if (memcmp(output_hash, FIPS_TEST_RESULT[i], LENGTH_SHA_HASH) != 0) {
       printf("This does NOT match the known result.\n");
    } else {
       printf("Yep, it's what it should be.\n");
    }
  }

  // This test is the same as test 2, except that we use the SHA_CONTEXT and
  // break it into calls of 1024 bytes each.
  printf("\nOriginal data for test 2(chunks = 1024) is calls of 1024 'a's at a time\n");
  i = FIPS_TEST_DATA_SIZE[2];
  while (i > 0) {
    unsigned int shaMessagePart;
    memset(input_data, 'a', 1024);

    if (i == FIPS_TEST_DATA_SIZE[2])
      shaMessagePart = SHA_MSG_PART_FIRST;
    else if (i <= 1024)
      shaMessagePart = SHA_MSG_PART_FINAL;
    else
      shaMessagePart = SHA_MSG_PART_MIDDLE;

    rc = icaSha1(adapter_handle,
                 shaMessagePart,
                 (i < 1024) ? i : 1024,
                 input_data,
                 LENGTH_SHA_CONTEXT,
                 &ShaContext,
                 &output_hash_length,
                 output_hash);

    if (rc != 0) {
      printf("icaSha1 failed with errno %d (0x%x) on iteration %d.\n", rc, rc, i);
      return 2;
    }

    i -= 1024;
  }

  if (output_hash_length != LENGTH_SHA_HASH) {
    printf("icaSha1 returned an incorrect output data length, %u (0x%x).\n",
           output_hash_length, output_hash_length);
    return 2;
  }

  printf("\nOutput hash for test 2(chunks = 1024):\n");
  dump_array(output_hash, output_hash_length);
  if (memcmp(output_hash, FIPS_TEST_RESULT[2], LENGTH_SHA_HASH) != 0) {
     printf("This does NOT match the known result.\n");
  } else {
     printf("Yep, it's what it should be.\n");
  }

  // This test is the same as test 2, except that we use the SHA_CONTEXT and
  // break it into calls of 64 bytes each.
  printf("\nOriginal data for test 2(chunks = 64) is calls of 64 'a's at a time\n");
  i = FIPS_TEST_DATA_SIZE[2];
  while (i > 0) {
    unsigned int shaMessagePart;
    memset(input_data, 'a', 64);

    if (i == FIPS_TEST_DATA_SIZE[2])
      shaMessagePart = SHA_MSG_PART_FIRST;
    else if (i <= 64)
      shaMessagePart = SHA_MSG_PART_FINAL;
    else
      shaMessagePart = SHA_MSG_PART_MIDDLE;

    rc = icaSha1(adapter_handle,
                 shaMessagePart,
                 (i < 64) ? i : 64,
                 input_data,
                 LENGTH_SHA_CONTEXT,
                 &ShaContext,
                 &output_hash_length,
                 output_hash);

    if (rc != 0) {
      printf("icaSha1 failed with errno %d (0x%x) on iteration %d.\n", rc, rc, i);
      return 2;
    }

    i -= 64;
  }

  if (output_hash_length != LENGTH_SHA_HASH) {
    printf("icaSha1 returned an incorrect output data length, %u (0x%x).\n",
           output_hash_length, output_hash_length);
    return 2;
  }

  printf("\nOutput hash for test 2(chunks = 64):\n");
  dump_array(output_hash, output_hash_length);
  if (memcmp(output_hash, FIPS_TEST_RESULT[2], LENGTH_SHA_HASH) != 0) {
     printf("This does NOT match the known result.\n");
  } else {
     printf("Yep, it's what it should be.\n");
  }

  printf("\nAll SHA1 tests completed successfully\n");

  icaCloseAdapter(adapter_handle);

	return rc;
}

int new_api_sha_test(void)
{
	printf("Test of new sha api\n");
	sha_context_t sha_context;
	int rc = 0, i = 0;
	unsigned char input_data[1000000];
	unsigned int  output_hash_length = LENGTH_SHA_HASH;
	unsigned char output_hash[LENGTH_SHA_HASH];

	for (i = 0; i < NUM_FIPS_TESTS; i++) {
	// Test 2 is a special one, because we want to keep the size of the
	// executable down, so we build it special, instead of using a static
	if (i != 2)
		memcpy(input_data, FIPS_TEST_DATA[i], FIPS_TEST_DATA_SIZE[i]);
	else
		memset(input_data, 'a', FIPS_TEST_DATA_SIZE[i]);

	printf("\nOriginal data for test %d:\n", i);
	dump_array(input_data, FIPS_TEST_DATA_SIZE[i]);

	rc = ica_sha1(SHA_MSG_PART_ONLY, FIPS_TEST_DATA_SIZE[i], input_data,
		      &sha_context, output_hash);

	if (rc != 0) {
		printf("icaSha1 failed with errno %d (0x%x).\n", rc, rc);
		return rc;
	}

	printf("\nOutput hash for test %d:\n", i);
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[i], LENGTH_SHA_HASH) != 0)
		printf("This does NOT match the known result.\n");
	else
		printf("Yep, it's what it should be.\n");
	}

	// This test is the same as test 2, except that we use the SHA_CONTEXT
	// and break it into calls of 1024 bytes each.
	printf("\nOriginal data for test 2(chunks = 1024) is calls of 1024"
	       "'a's at a time\n");
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 1024);

		if (i == FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 1024)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha1(sha_message_part, (i < 1024) ? i : 1024,
			      input_data, &sha_context, output_hash);

		if (rc != 0) {
			printf("ica_sha1 failed with errno %d (0x%x) on"
			       " iteration %d.\n", rc, rc, i);
			return rc;
		}
		i -= 1024;
	}

	printf("\nOutput hash for test 2(chunks = 1024):\n");
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], LENGTH_SHA_HASH) != 0)
		printf("This does NOT match the known result.\n");
	else
		printf("Yep, it's what it should be.\n");

	// This test is the same as test 2, except that we use the SHA_CONTEXT
	// and break it into calls of 64 bytes each.
	printf("\nOriginal data for test 2(chunks = 64) is calls of 64 'a's at"
	       "a time\n");
	i = FIPS_TEST_DATA_SIZE[2];
	while (i > 0) {
		unsigned int sha_message_part;
		memset(input_data, 'a', 64);

		if (i == FIPS_TEST_DATA_SIZE[2])
			sha_message_part = SHA_MSG_PART_FIRST;
		else if (i <= 64)
			sha_message_part = SHA_MSG_PART_FINAL;
		else
			sha_message_part = SHA_MSG_PART_MIDDLE;

		rc = ica_sha1(sha_message_part, (i < 64) ? i : 64, input_data,
			      &sha_context, output_hash);

		if (rc != 0) {
			printf("ica_sha1 failed with errno %d (0x%x) on"
			       " iteration %d.\n", rc, rc, i);
			return rc;
		}
		i -= 64;
	}

	printf("\nOutput hash for test 2(chunks = 64):\n");
	dump_array(output_hash, output_hash_length);
	if (memcmp(output_hash, FIPS_TEST_RESULT[2], LENGTH_SHA_HASH) != 0)
		printf("This does NOT match the known result.\n");
	else
	printf("Yep, it's what it should be.\n");

	printf("\nAll SHA1 tests completed successfully\n");

	return 0;
}

int main(int argc, char **argv)
{
	int rc = 0;

	rc = old_api_sha_test();
	if (rc) {
		printf("old_api_sha_test failed with rc = %i\n", rc);
		return rc;
	}
	rc = new_api_sha_test();
	if (rc) {
		printf("new_api_sha_test failed with rc = %i\n", rc);
		return rc;
	}

	return 0;
}

