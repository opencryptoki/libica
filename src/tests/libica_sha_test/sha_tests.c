#include <stdio.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <string.h>
#include "ica_api.h"
#include "queue_t.h"
#include "sha_tests.h"
#include "critical_error.h"

static void dump_array(unsigned char *ptr, unsigned int size);

int sha1_new_api_test(test_t * test)
{

	sha_context_t sha_context;
	int rc = 0;
	unsigned char output[SHA_HASH_LENGTH];

	if (test->msg_digest_length != SHA_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha1(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			   &sha_context, output);

	if (rc != 0) {
		printf("ica_sha1 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
		return rc;
	}

	if (!silent) {
		printf("message digest (new api)\n");
		dump_array(output, SHA_HASH_LENGTH);
	}

	if (memcmp(output, test->msg_digest, SHA_HASH_LENGTH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}
	return 0;
}

int sha224_new_api_test(test_t * test)
{
	sha256_context_t sha256_context;
	int rc = 0;
	unsigned char output[SHA224_HASH_LENGTH];

	if (test->msg_digest_length != SHA224_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha224(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			     &sha256_context, output);

	if (rc != 0) {
		printf("ica_sha224 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
		return rc;
	}

	if (!silent) {
		printf("message digest (new api)\n");
		dump_array(output, SHA224_HASH_LENGTH);
	}
	if (memcmp(output, test->msg_digest, SHA224_HASH_LENGTH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha256_new_api_test(test_t * test)
{
	sha256_context_t sha256_context;
	int rc = 0;
	unsigned char output[SHA256_HASH_LENGTH];

	if (test->msg_digest_length != SHA256_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha256(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			     &sha256_context, output);

	if (rc != 0) {
		printf("ica_sha256 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
		return rc;
	}

	if (!silent) {
		printf("message digest (new api)\n");
		dump_array(output, SHA256_HASH_LENGTH);
	}
	if (memcmp(output, test->msg_digest, SHA256_HASH_LENGTH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha384_new_api_test(test_t * test)
{
	sha512_context_t sha512_context;
	int rc = 0;
	unsigned char output[SHA384_HASH_LENGTH];

	if (test->msg_digest_length != SHA384_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha384(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			     &sha512_context, output);

	if (rc != 0) {
		printf("ica_sha384 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
		return rc;
	}

	if (!silent) {
		printf("message digest (new api)\n");
		dump_array(output, SHA384_HASH_LENGTH);
	}
	if (memcmp(output, test->msg_digest, SHA384_HASH_LENGTH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha512_new_api_test(test_t * test)
{
	sha512_context_t sha512_context;
	int rc = 0;
	unsigned char output[SHA512_HASH_LENGTH];

	if (test->msg_digest_length != SHA512_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha512(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			     &sha512_context, output);

	if (rc != 0) {
		printf("ica_sha512 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
		return rc;
	}

	if (!silent) {
		printf("message digest (new api)\n");
		dump_array(output, SHA512_HASH_LENGTH);
	}
	if (memcmp(output, test->msg_digest, SHA512_HASH_LENGTH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}
	return 0;
}

static void dump_array(unsigned char *ptr, unsigned int size)
{
	unsigned char *ptr_end;
	unsigned char *h;
	int i = 1, trunc = 0;

	if (size > 64) {
		trunc = (int)size - 64;
		size = 64;
	}
	h = ptr;
	ptr_end = ptr + size;
	while (h < ptr_end) {
		printf("0x%02x ", (unsigned int)*h);
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
