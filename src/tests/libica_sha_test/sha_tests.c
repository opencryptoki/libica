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

int sha1_old_api_test(test_t * test)
{
	ICA_ADAPTER_HANDLE adapter_handle;
	SHA_CONTEXT ShaContext;
	int rc = 0;
	unsigned int output_length = LENGTH_SHA_HASH;
	unsigned char output[LENGTH_SHA_HASH];

	if (test->msg_digest_length != LENGTH_SHA_HASH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)icaOpenAdapter(0, &adapter_handle);
	if (rc != 0) {
		printf("icaOpenAdapter failed and returned %d (0x%x).\n", rc,
		       (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif

		return 2;
	}

	rc = (int)icaSha1(adapter_handle, SHA_MSG_PART_ONLY, test->msg_length,
			  test->msg, (unsigned int)LENGTH_SHA_CONTEXT,
			  &ShaContext, &output_length, output);
	if (rc != 0) {
		printf("icaSha1 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif
		return 2;
	}

	if (output_length != LENGTH_SHA_HASH) {
		printf
		    ("icaSha1 returned an incorrect output data length, %u (0x%x).\n",
		     output_length, (unsigned int)output_length);
		return 2;
	}

	if (!silent) {
		printf("message digest (old api)\n");
		dump_array(output, LENGTH_SHA_HASH);
	}
	if (memcmp(output, test->msg_digest, LENGTH_SHA_HASH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha1_new_api_test(test_t * test)
{

	sha_context_t sha_context;
	int rc = 0;
	unsigned char output[LENGTH_SHA_HASH];

	if (test->msg_digest_length != LENGTH_SHA_HASH)
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
		dump_array(output, LENGTH_SHA_HASH);
	}

	if (memcmp(output, test->msg_digest, LENGTH_SHA_HASH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}
	return 0;
}

int sha224_old_api_test(test_t * test)
{
	ICA_ADAPTER_HANDLE adapter_handle;
	SHA256_CONTEXT Sha256Context;
	int rc = 0;
	unsigned int output_length = LENGTH_SHA224_HASH;
	unsigned char output[LENGTH_SHA224_HASH];

	if (test->msg_digest_length != LENGTH_SHA224_HASH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)icaOpenAdapter(0, &adapter_handle);
	if (rc != 0) {
		printf("icaOpenAdapter failed and returned %d (0x%x).\n",
		       rc, (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif
		return 2;
	}

	rc = (int)icaSha224(adapter_handle, SHA_MSG_PART_ONLY,
			    test->msg_length, test->msg,
			    (unsigned int)LENGTH_SHA256_CONTEXT,
			    &Sha256Context, &output_length, output);

	if (rc != 0) {
		printf("icaSha224 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif
		return 2;
	}

	if (output_length != LENGTH_SHA224_HASH) {
		printf
		    ("icaSha224 returned an incorrect output data length, %u (0x%x).\n",
		     output_length, output_length);
		return 2;
	}

	if (!silent) {
		printf("message digest (old api)\n");
		dump_array(output, LENGTH_SHA224_HASH);
	}
	if (memcmp(output, test->msg_digest, LENGTH_SHA224_HASH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha224_new_api_test(test_t * test)
{
	sha256_context_t sha256_context;
	int rc = 0;
	unsigned char output[LENGTH_SHA224_HASH];

	if (test->msg_digest_length != LENGTH_SHA224_HASH)
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
		dump_array(output, LENGTH_SHA224_HASH);
	}
	if (memcmp(output, test->msg_digest, LENGTH_SHA224_HASH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha256_old_api_test(test_t * test)
{
	ICA_ADAPTER_HANDLE adapter_handle;
	SHA256_CONTEXT Sha256Context;
	int rc = 0;
	unsigned int output_length = LENGTH_SHA256_HASH;
	unsigned char output[LENGTH_SHA256_HASH];

	if (test->msg_digest_length != LENGTH_SHA256_HASH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)icaOpenAdapter(0, &adapter_handle);
	if (rc != 0) {
		printf("icaOpenAdapter failed and returned %d (0x%x).\n",
		       rc, (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif
		return 2;
	}

	rc = (int)icaSha256(adapter_handle, SHA_MSG_PART_ONLY,
			    test->msg_length, test->msg,
			    (unsigned int)LENGTH_SHA256_CONTEXT,
			    &Sha256Context, &output_length, output);

	if (rc != 0) {
		printf("icaSha256 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif

		return 2;
	}

	if (output_length != LENGTH_SHA256_HASH) {
		printf
		    ("icaSha256 returned an incorrect output data length, %u (0x%x).\n",
		     output_length, output_length);
		return 2;
	}

	if (!silent) {
		printf("message digest (old api)\n");
		dump_array(output, LENGTH_SHA256_HASH);
	}
	if (memcmp(output, test->msg_digest, LENGTH_SHA256_HASH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha256_new_api_test(test_t * test)
{
	sha256_context_t sha256_context;
	int rc = 0;
	unsigned char output[LENGTH_SHA256_HASH];

	if (test->msg_digest_length != LENGTH_SHA256_HASH)
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
		dump_array(output, LENGTH_SHA256_HASH);
	}
	if (memcmp(output, test->msg_digest, LENGTH_SHA256_HASH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha384_old_api_test(test_t * test)
{
	ICA_ADAPTER_HANDLE adapter_handle;
	SHA512_CONTEXT Sha512Context;
	int rc = 0;
	unsigned int output_length = LENGTH_SHA384_HASH;
	unsigned char output[LENGTH_SHA384_HASH];

	if (test->msg_digest_length != LENGTH_SHA384_HASH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)icaOpenAdapter(0, &adapter_handle);
	if (rc != 0) {
		printf("icaOpenAdapter failed and returned %d (0x%x).\n",
		       rc, (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif
		return 2;
	}

	rc = (int)icaSha384(adapter_handle, SHA_MSG_PART_ONLY,
			    test->msg_length, test->msg,
			    (unsigned int)LENGTH_SHA512_CONTEXT,
			    &Sha512Context, &output_length, output);

	if (rc != 0) {
		printf("icaSha384 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif

		return 2;
	}

	if (output_length != LENGTH_SHA384_HASH) {
		printf
		    ("icaSha384 returned an incorrect output data length, %u (0x%x).\n",
		     output_length, output_length);
		return 2;
	}

	if (!silent) {
		printf("message digest (old api)\n");
		dump_array(output, LENGTH_SHA384_HASH);
	}
	if (memcmp(output, test->msg_digest, LENGTH_SHA384_HASH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha384_new_api_test(test_t * test)
{
	sha512_context_t sha512_context;
	int rc = 0;
	unsigned char output[LENGTH_SHA384_HASH];

	if (test->msg_digest_length != LENGTH_SHA384_HASH)
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
		dump_array(output, LENGTH_SHA384_HASH);
	}
	if (memcmp(output, test->msg_digest, LENGTH_SHA384_HASH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha512_old_api_test(test_t * test)
{
	ICA_ADAPTER_HANDLE adapter_handle;
	SHA512_CONTEXT Sha512Context;
	int rc = 0;
	unsigned int output_length = LENGTH_SHA512_HASH;
	unsigned char output[LENGTH_SHA512_HASH];

	if (test->msg_digest_length != LENGTH_SHA512_HASH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)icaOpenAdapter(0, &adapter_handle);
	if (rc != 0) {
		printf("icaOpenAdapter failed and returned %d (0x%x).\n",
		       rc, (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif
		return 2;
	}

	rc = (int)icaSha512(adapter_handle, SHA_MSG_PART_ONLY,
			    test->msg_length, test->msg,
			    (unsigned int)LENGTH_SHA512_CONTEXT,
			    &Sha512Context, &output_length, output);

	if (rc != 0) {
		printf("icaSha512 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc);
#ifdef __s390__
		if (rc == ENODEV)
			printf
			    ("the usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif

		return 2;
	}

	if (output_length != LENGTH_SHA512_HASH) {
		printf
		    ("icaSha512 returned an incorrect output data length, %u (0x%x).\n",
		     output_length, output_length);
		return 2;
	}

	if (!silent) {
		printf("message digest (old api)\n");
		dump_array(output, LENGTH_SHA512_HASH);
	}
	if (memcmp(output, test->msg_digest, LENGTH_SHA512_HASH) != 0) {
		printf("output is not what it should be.\n");
		return 2;
	}

	return 0;
}

int sha512_new_api_test(test_t * test)
{
	sha512_context_t sha512_context;
	int rc = 0;
	unsigned char output[LENGTH_SHA512_HASH];

	if (test->msg_digest_length != LENGTH_SHA512_HASH)
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
		dump_array(output, LENGTH_SHA512_HASH);
	}
	if (memcmp(output, test->msg_digest, LENGTH_SHA512_HASH) != 0) {
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
