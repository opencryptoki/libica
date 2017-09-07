#include <stdio.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include "ica_api.h"
#include "queue_t.h"
#include "sha_tests.h"
#include "critical_error.h"
#define VERBOSE_EXTERN
#include "../testcase.h"
#undef VERBOSE_EXTERN

#define SHA1_BLOCK_SIZE		(512 / 8)
#define SHA224_BLOCK_SIZE	(512 / 8)
#define SHA256_BLOCK_SIZE	(512 / 8)
#define SHA384_BLOCK_SIZE	(1024 / 8)
#define SHA512_BLOCK_SIZE	(1024 / 8)
#define SHA3_224_BLOCK_SIZE	(1152 / 8)
#define SHA3_256_BLOCK_SIZE	(1088 / 8)
#define SHA3_384_BLOCK_SIZE	(832 / 8)
#define SHA3_512_BLOCK_SIZE	(576 / 8)

int sha1_new_api_test(test_t * test)
{
	sha_context_t sha_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha1(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			   &sha_context, output);

	if (rc != 0) {
		V_(printf("ica_sha1 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	if (test->msg_length <= SHA1_BLOCK_SIZE)
		return 0;

	rc = (int)ica_sha1(SHA_MSG_PART_FIRST, SHA1_BLOCK_SIZE,
			       test->msg, &sha_context, output);
	if (rc != 0) {
		V_(printf("ica_sha1 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return rc;
	}

	for (off = SHA1_BLOCK_SIZE;
	     off < test->msg_length - SHA1_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA1_BLOCK_SIZE + 1);
		rc = (int)ica_sha1(SHA_MSG_PART_MIDDLE,
				       i * SHA1_BLOCK_SIZE,
				       test->msg + off,
				       &sha_context, output);
		if (rc != 0) {
			V_(printf("ica_sha1 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return rc;
		}
		off += i * SHA1_BLOCK_SIZE;
	}

	rc = (int)ica_sha1(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha_context, output);
	if (rc != 0) {
		V_(printf("ica_sha1 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA1_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA1_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	return 0;
}

int sha224_new_api_test(test_t * test)
{
	sha256_context_t sha256_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA224_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA224_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha224(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			     &sha256_context, output);

	if (rc != 0) {
		V_(printf("ica_sha224 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	if (test->msg_length <= SHA224_BLOCK_SIZE)
		return 0;

	rc = (int)ica_sha224(SHA_MSG_PART_FIRST, SHA224_BLOCK_SIZE,
			       test->msg, &sha256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return rc;
	}

	for (off = SHA224_BLOCK_SIZE;
	     off < test->msg_length - SHA224_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA224_BLOCK_SIZE + 1);
		rc = (int)ica_sha224(SHA_MSG_PART_MIDDLE,
				       i * SHA224_BLOCK_SIZE,
				       test->msg + off,
				       &sha256_context, output);
		if (rc != 0) {
			V_(printf("ica_sha224 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return rc;
		}
		off += i * SHA224_BLOCK_SIZE;
	}

	rc = (int)ica_sha224(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	return 0;
}

int sha256_new_api_test(test_t * test)
{
	sha256_context_t sha256_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA256_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA256_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha256(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			     &sha256_context, output);

	if (rc != 0) {
		V_(printf("ica_sha256 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	if (test->msg_length <= SHA256_BLOCK_SIZE)
		return 0;

	rc = (int)ica_sha256(SHA_MSG_PART_FIRST, SHA256_BLOCK_SIZE,
			       test->msg, &sha256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return rc;
	}

	for (off = SHA256_BLOCK_SIZE;
	     off < test->msg_length - SHA256_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA256_BLOCK_SIZE + 1);
		rc = (int)ica_sha256(SHA_MSG_PART_MIDDLE,
				       i * SHA256_BLOCK_SIZE,
				       test->msg + off,
				       &sha256_context, output);
		if (rc != 0) {
			V_(printf("ica_sha256 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return rc;
		}
		off += i * SHA256_BLOCK_SIZE;
	}

	rc = (int)ica_sha256(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	return 0;
}

int sha384_new_api_test(test_t * test)
{
	sha512_context_t sha512_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA384_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA384_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha384(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			     &sha512_context, output);

	if (rc != 0) {
		V_(printf("ica_sha384 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA384_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA384_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	if (test->msg_length <= SHA384_BLOCK_SIZE)
		return 0;

	rc = (int)ica_sha384(SHA_MSG_PART_FIRST, SHA384_BLOCK_SIZE,
			       test->msg, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha384 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return rc;
	}

	for (off = SHA384_BLOCK_SIZE;
	     off < test->msg_length - SHA384_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA384_BLOCK_SIZE + 1);
		rc = (int)ica_sha384(SHA_MSG_PART_MIDDLE,
				       i * SHA384_BLOCK_SIZE,
				       test->msg + off,
				       &sha512_context, output);
		if (rc != 0) {
			V_(printf("ica_sha384 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return rc;
		}
		off += i * SHA384_BLOCK_SIZE;
	}

	rc = (int)ica_sha384(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha384 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA384_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA384_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	return 0;
}

int sha512_new_api_test(test_t * test)
{
	sha512_context_t sha512_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA512_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA512_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha512(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			     &sha512_context, output);

	if (rc != 0) {
		V_(printf("ica_sha512 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA512_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA512_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	if (test->msg_length <= SHA512_BLOCK_SIZE)
		return 0;

	rc = (int)ica_sha512(SHA_MSG_PART_FIRST, SHA512_BLOCK_SIZE,
			       test->msg, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha512 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return rc;
	}

	for (off = SHA512_BLOCK_SIZE;
	     off < test->msg_length - SHA512_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA512_BLOCK_SIZE + 1);
		rc = (int)ica_sha512(SHA_MSG_PART_MIDDLE,
				       i * SHA512_BLOCK_SIZE,
				       test->msg + off,
				       &sha512_context, output);
		if (rc != 0) {
			V_(printf("ica_sha512 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return rc;
		}
		off += i * SHA512_BLOCK_SIZE;
	}

	rc = (int)ica_sha512(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha512 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA512_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA512_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	return 0;
}

int sha3_224_api_test(test_t * test)
{
	sha3_224_context_t sha3_224_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA3_224_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA3_224_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha3_224(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			       &sha3_224_context, output);

	if (rc != 0) {
		V_(printf("ica_sha3_224 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	if (test->msg_length <= SHA3_224_BLOCK_SIZE)
		return 0;

	rc = (int)ica_sha3_224(SHA_MSG_PART_FIRST, SHA3_224_BLOCK_SIZE,
			       test->msg, &sha3_224_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return rc;
	}

	for (off = SHA3_224_BLOCK_SIZE;
	     off < test->msg_length - SHA3_224_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA3_224_BLOCK_SIZE + 1);
		rc = (int)ica_sha3_224(SHA_MSG_PART_MIDDLE,
				       i * SHA3_224_BLOCK_SIZE,
				       test->msg + off,
				       &sha3_224_context, output);
		if (rc != 0) {
			V_(printf("ica_sha3_224 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return rc;
		}
		off += i * SHA3_224_BLOCK_SIZE;
	}

	rc = (int)ica_sha3_224(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha3_224_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	return 0;
}

int sha3_256_api_test(test_t * test)
{
	sha3_256_context_t sha3_256_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA3_256_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA3_256_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha3_256(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			       &sha3_256_context, output);

	if (rc != 0) {
		V_(printf("ica_sha3_256 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	if (test->msg_length <= SHA3_256_BLOCK_SIZE)
		return 0;

	rc = (int)ica_sha3_256(SHA_MSG_PART_FIRST, SHA3_256_BLOCK_SIZE,
			       test->msg, &sha3_256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return rc;
	}

	for (off = SHA3_256_BLOCK_SIZE;
	     off < test->msg_length - SHA3_256_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA3_256_BLOCK_SIZE + 1);
		rc = (int)ica_sha3_256(SHA_MSG_PART_MIDDLE,
				       i * SHA3_256_BLOCK_SIZE,
				       test->msg + off,
				       &sha3_256_context, output);
		if (rc != 0) {
			V_(printf("ica_sha3_256 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return rc;
		}
		off += i * SHA3_256_BLOCK_SIZE;
	}

	rc = (int)ica_sha3_256(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha3_256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	return 0;
}

int sha3_384_api_test(test_t * test)
{
	sha3_384_context_t sha3_384_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA3_384_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA3_384_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha3_384(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			       &sha3_384_context, output);

	if (rc != 0) {
		V_(printf("ica_sha3_384 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_384_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_384_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	if (test->msg_length <= SHA3_384_BLOCK_SIZE)
		return 0;

	rc = (int)ica_sha3_384(SHA_MSG_PART_FIRST, SHA3_384_BLOCK_SIZE,
			       test->msg, &sha3_384_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_384 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return rc;
	}

	for (off = SHA3_384_BLOCK_SIZE;
	     off < test->msg_length - SHA3_384_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA3_384_BLOCK_SIZE + 1);
		rc = (int)ica_sha3_384(SHA_MSG_PART_MIDDLE,
				       i * SHA3_384_BLOCK_SIZE,
				       test->msg + off,
				       &sha3_384_context, output);
		if (rc != 0) {
			V_(printf("ica_sha3_384 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return rc;
		}
		off += i * SHA3_384_BLOCK_SIZE;
	}

	rc = (int)ica_sha3_384(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha3_384_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_384 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_384_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_384_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	return 0;
}

int sha3_512_api_test(test_t * test)
{
	sha3_512_context_t sha3_512_context;
	size_t off;
	int rc = 0;
	unsigned char output[SHA3_512_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA3_512_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha3_512(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
			       &sha3_512_context, output);

	if (rc != 0) {
		V_(printf("ica_sha3_512 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_512_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_512_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	if (test->msg_length <= SHA3_512_BLOCK_SIZE)
		return 0;

	rc = (int)ica_sha3_512(SHA_MSG_PART_FIRST, SHA3_512_BLOCK_SIZE,
			       test->msg, &sha3_512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_512 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return rc;
	}

	for (off = SHA3_512_BLOCK_SIZE;
	     off < test->msg_length - SHA3_512_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA3_512_BLOCK_SIZE + 1);
		rc = (int)ica_sha3_512(SHA_MSG_PART_MIDDLE,
				       i * SHA3_512_BLOCK_SIZE,
				       test->msg + off,
				       &sha3_512_context, output);
		if (rc != 0) {
			V_(printf("ica_sha3_512 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return rc;
		}
		off += i * SHA3_512_BLOCK_SIZE;
	}

	rc = (int)ica_sha3_512(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha3_512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_512 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return rc;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_512_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_512_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return 2;
	}

	return 0;
}
