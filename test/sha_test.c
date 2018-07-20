/*
 * usage: sha_test [-sha3] <filelist>
 * test for sha2 and sha3
 * test vectors are read from .rsp files and put in the queue
 * the included .rsp files are obtained from nist:
 * http://csrc.nist.gov/groups/STM/cavp/index.html#03
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ica_api.h"
#include "testcase.h"

/* terminate on critical error */
#define CRITICAL_ERROR(msg) \
do { \
        fprintf(stderr, "critical error in %s: " msg "\n",__func__); \
        exit(TEST_ERR); \
} while(0)

#define BUFFER_SIZE 32768

#define SHA1_BLOCK_SIZE		(512 / 8)
#define SHA224_BLOCK_SIZE	(512 / 8)
#define SHA256_BLOCK_SIZE	(512 / 8)
#define SHA384_BLOCK_SIZE	(1024 / 8)
#define SHA512_BLOCK_SIZE	(1024 / 8)
#define SHA3_224_BLOCK_SIZE	(1152 / 8)
#define SHA3_256_BLOCK_SIZE	(1088 / 8)
#define SHA3_384_BLOCK_SIZE	(832 / 8)
#define SHA3_512_BLOCK_SIZE	(576 / 8)

#define NO_TYPE_SET 0
#define NO_LENGTH_SET 0

/*
 * type: NO_TYPE_SET, SHA1, SHA224, SHA256, SHA384, SHA512
 * msg_digest_length: SHA1_HASH_LENGTH, SHA224_HASH_LENGHT, SHA256_HASH_LENGTH,
 * SHA384_HASH_LENGTH, SHA512_HASH_LENGTH
 */
typedef struct test_t {
	unsigned int type;
	unsigned char *msg;
	unsigned int msg_length;
	unsigned char *msg_digest;
	unsigned int msg_digest_length;
	struct test_t *next;
} test_t;

typedef struct queue_t {
	unsigned int size;
	unsigned int passed;
	unsigned int failed;
	test_t *head;
	test_t *tail;
} queue_t;

static test_t new_test_t(void);
static queue_t new_queue_t(void);
static void push(queue_t * queue, test_t test);

static int read_test_data(FILE * test_data, int sha3_flag);
static int line_to_bytes(char *line, int length);

static int sha1_new_api_test(test_t * test);
static int sha224_new_api_test(test_t * test);
static int sha256_new_api_test(test_t * test);
static int sha384_new_api_test(test_t * test);
static int sha512_new_api_test(test_t * test);
static int sha512_224_new_api_test(test_t * test);
static int sha512_256_new_api_test(test_t * test);

static int sha3_224_api_test(test_t * test);
static int sha3_256_api_test(test_t * test);
static int sha3_384_api_test(test_t * test);
static int sha3_512_api_test(test_t * test);

static queue_t queue;

int main(int argc, char *argv[])
{
	test_t *curr_test;
	FILE *test_data;
	int i, j, rc, sha3_flag, sha3;

	sha3 = sha3_available();
	sha3_flag = 0;
	j = 1;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if ((argv[i][1] == 'v') || (argv[i][1] == 'V'))
				set_verbosity(2, argv);
			if (!strcasecmp(argv[i],"-sha3"))
				sha3_flag = 1;
			j++;
		}
	}

	if (!sha3 && sha3_flag) {
		printf("Skipping SHA3: not available...\n");
		return TEST_SKIP;
	}

	if (argc - j == 0) {
		printf("error: no input files.\n");
		return TEST_SKIP;
	}

	queue = new_queue_t();

	/* read test vectors from .rsp file(s) and put on queue */
	for (i = j; i < argc; i++) {
		if ((test_data = fopen(argv[i], "r")) != NULL) {
			VV_(printf("reading test data from %s ... ", argv[i]));
			if (read_test_data(test_data, sha3_flag) == TEST_SUCC) {
				VV_(printf("done.\n"));
			}
			if ((fclose(test_data)) == EOF) {
				V_(printf("error: couldn't close file %s.\n",
				       argv[i]));
			}
		} else {
			V_(printf("error: couldn't open file %s.\n", argv[i]));
		}
	}

	VV_(printf("%u test vectors found.\n", queue.size));

	if (queue.size > 0) {
		V_(printf("starting tests ...\n\n"));
	} else {
		printf("error: no SHA test vectors found.\n");
		return TEST_SKIP;
	}

	for (curr_test = queue.head, i = 1; curr_test != NULL;
	     curr_test = curr_test->next, i++) {
		V_(printf("test #%d : %u byte input message, ", i,
		       curr_test->msg_length));
		switch (curr_test->type) {
		case SHA1:
			V_(printf("SHA1 ...\n"));
			rc = sha1_new_api_test(curr_test);
			break;
		case SHA224:
			V_(printf("SHA224 ...\n"));
			rc = sha224_new_api_test(curr_test);
			break;
		case SHA256:
			V_(printf("SHA256 ...\n"));
			rc = sha256_new_api_test(curr_test);
			break;
		case SHA384:
			V_(printf("SHA384 ...\n"));
			rc = sha384_new_api_test(curr_test);
			break;
		case SHA512:
			V_(printf("SHA512 ...\n"));
			rc = sha512_new_api_test(curr_test);
			break;
		case SHA512_224:
			V_(printf("SHA512/224 ...\n"));
			rc = sha512_224_new_api_test(curr_test);
			break;
		case SHA512_256:
			V_(printf("SHA512/256 ...\n"));
			rc = sha512_256_new_api_test(curr_test);
			break;
		case SHA3_224:
			V_(printf("SHA3-224 ...\n"));
			rc = sha3_224_api_test(curr_test);
			break;
		case SHA3_256:
			V_(printf("SHA3-256 ...\n"));
			rc = sha3_256_api_test(curr_test);
			break;
		case SHA3_384:
			V_(printf("SHA3-384 ...\n"));
			rc = sha3_384_api_test(curr_test);
			break;
		case SHA3_512:
			V_(printf("SHA3-512 ...\n"));
			rc = sha3_512_api_test(curr_test);
			break;
		default:
			CRITICAL_ERROR("Unknown algorithm.\n");
			rc = -1;
			break;
		}
		if (!rc) {
			V_(printf("... Passed.\n"));
			queue.passed++;
		}
		else {
			V_(printf("error: (%x).\n", rc));
			queue.failed++;
		}

	}
	V_(printf("[SHA test case results: tests: %u,  passed: %u, failed: %u]\n",
			queue.passed + queue.failed, queue.passed, queue.failed));

	if (queue.failed != 0) {
		printf("SHA%s tests failed.\n", sha3_flag ? "3" : "");
		return TEST_FAIL;
	}

	printf("All SHA%s tests passed.\n", sha3_flag ? "3" : "");
	return TEST_SUCC;
}

static test_t new_test_t(void)
{
	test_t test;

	test.type = NO_TYPE_SET;
	test.msg = NULL;
	test.msg_length = 0;
	test.msg_digest = NULL;
	test.msg_digest_length = 0;
	test.next = NULL;

	return test;
}

static queue_t new_queue_t(void)
{
	queue_t queue;

	queue.size = 0;
	queue.passed = 0;
	queue.failed = 0;
	queue.head = NULL;
	queue.tail = NULL;

	return queue;
}

static void push(queue_t * queue, test_t test)
{
	test_t *new_test;

	if ((new_test = (test_t *) malloc(sizeof(test_t))) == NULL)
		CRITICAL_ERROR("out of memory.");

	new_test->type = test.type;
	new_test->msg_length = test.msg_length;
	new_test->msg_digest_length = test.msg_digest_length;

	new_test->msg = (unsigned char *)malloc((size_t) test.msg_length);
	memcpy(new_test->msg, test.msg, (size_t) test.msg_length);

	new_test->msg_digest =
	    (unsigned char *)malloc((size_t) test.msg_digest_length);
	memcpy(new_test->msg_digest, test.msg_digest,
	       (size_t) test.msg_digest_length);

	new_test->next = NULL;

	if (queue->head == NULL)
		queue->head = new_test;
	else
		queue->tail->next = new_test;
	queue->tail = new_test;
	queue->size++;
}

static int read_test_data(FILE * test_data, int sha3_flag)
{
	char buffer[BUFFER_SIZE];
	enum { MSG_LENGTH, MSG, MSG_DIGEST } search_term;

	test_t tmp_test = new_test_t();
	unsigned int current_type = NO_TYPE_SET;
	unsigned int current_msg_digest_length = NO_LENGTH_SET;
	char parsed_type[20];

	unsigned int line_number = 0;

	char *tmp = NULL;
	char *tmp2 = NULL;
	search_term = MSG_LENGTH;
	memset(parsed_type, 0, sizeof(parsed_type));

	while (fgets(buffer, (int)sizeof buffer, test_data) != NULL) {

		line_number++;

		/* remove comments */
		if ((tmp = memchr(buffer, (int)'#', strlen(buffer))) != NULL) {
			if ((tmp2 = strstr(buffer, "SHA-512/")) != NULL)
				strncpy(parsed_type, tmp2, strlen("SHA-512/XXX"));
			memset(tmp, 0, strlen(tmp));
		}

		/* scan for: type/msg_digest_length */
		if (((sscanf(buffer, "[L = %u]", &current_msg_digest_length))
		     == 1)
		    || (current_type == NO_TYPE_SET)) {
			if (tmp_test.type != NO_TYPE_SET) {
				printf
				    ("error:\nincorrect file format [line %u]: test type mustn't change during test definition. closing file.\n",
				     line_number);
				return TEST_FAIL;
			}

			/* SHA3 test vector's length is specified in bits. */
			if (sha3_flag)
				current_msg_digest_length /= 8;

			switch (current_msg_digest_length) {
			case NO_LENGTH_SET:
				continue;
			case SHA1_HASH_LENGTH:
				current_type = SHA1;
				break;
			case SHA224_HASH_LENGTH:
				current_type = sha3_flag ? SHA3_224 :
					strcmp(parsed_type, "SHA-512/224") == 0
						? SHA512_224 : SHA224;
				break;
			case SHA256_HASH_LENGTH:
				current_type = sha3_flag ? SHA3_256 :
					strcmp(parsed_type, "SHA-512/256") == 0
						? SHA512_256 : SHA256;
				break;
			case SHA384_HASH_LENGTH:
				current_type = sha3_flag ? SHA3_384 : SHA384;
				break;
			case SHA512_HASH_LENGTH:
				current_type = sha3_flag ? SHA3_512 : SHA512;
				break;
			default:
				CRITICAL_ERROR("this shouldn't happen.");
				break;
			}
		}

		/* scan for: 1st msg_length, 2nd msg, 3rd msg_digest. repeat */
		switch (search_term) {
		case MSG_LENGTH:
			if (sscanf(buffer, "Len = %u", &tmp_test.msg_length) ==
			    1) {
				if ((tmp_test.msg_length % 8) != 0) {
					printf
					    ("error:\nincorrect file format [line %u]: message bit-length must be a multiple of 8. closing file.",
					     line_number);
					return TEST_FAIL;
				}
				tmp_test.msg_length /= 8;
				search_term = MSG;
			}
			break;
		case MSG:
			if (sscanf(buffer, "Msg = %s", buffer) == 1) {
				if ((int)strlen(buffer) % 2 != 0) {
					printf
					    ("error:\nincorrect file format [line %u]: message should be bytes. closing file.\n",
					     line_number);
					return TEST_FAIL;
				}
				if (line_to_bytes
				    (buffer,
				     (int)strlen(buffer)) == TEST_FAIL) {
					printf
					    ("error:\nincorrect file format [line %u]: message contains characters different from hex values. closing file.\n",
					     line_number);
					return TEST_FAIL;
				}
				if ((tmp_test.msg = (unsigned char *)
				     malloc((size_t) tmp_test.msg_length))
				    == NULL)
					CRITICAL_ERROR("out of memory.");
				memcpy(tmp_test.msg, buffer,
				       (size_t) tmp_test.msg_length);
				search_term = MSG_DIGEST;
			}
			break;
		case MSG_DIGEST:
			if (sscanf(buffer, "MD = %s", buffer)
			    == 1) {
				if (((int)strlen(buffer) % 2 != 0)
				    || (((unsigned int)strlen(buffer) / 2)
					!= current_msg_digest_length)) {
					printf
					    ("error:\nincorrect file format [line %u]: message digest length doesn't match test type. closing file.\n",
					     line_number);
					free(tmp_test.msg);
					return TEST_FAIL;
				}
				if (line_to_bytes
				    (buffer,
				     (int)strlen(buffer)) == TEST_FAIL) {
					printf
					    ("error:\nincorrect file format [line %u]: message digest contains characters different from hex values. closing file.\n",
					     line_number);
					free(tmp_test.msg);
					return TEST_FAIL;
				}
				if ((tmp_test.msg_digest = (unsigned char *)
				     malloc((size_t)
					    current_msg_digest_length))
				    == NULL)
					CRITICAL_ERROR("out of memory.");
				memcpy(tmp_test.msg_digest, buffer,
				       (size_t) current_msg_digest_length);
				tmp_test.type = current_type;
				tmp_test.msg_digest_length =
				    current_msg_digest_length;
				push(&queue, tmp_test);
				free(tmp_test.msg);
				free(tmp_test.msg_digest);
				tmp_test = new_test_t();
				search_term = MSG_LENGTH;
			}
			break;
		default:
			CRITICAL_ERROR("this shouldn't happen.");
			break;
		}
		if (feof(test_data) != 0) {
			CRITICAL_ERROR("read error.");
		}
	}
	free(tmp_test.msg);
	free(tmp_test.msg_digest);

	if (feof(test_data) == 0) {
		printf("error:\ndidn't reach end of file. closing file.\n");
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int line_to_bytes(char *line, int length)
{
	int i;
	unsigned char *bytes;
	if ((bytes = (unsigned char *)
	     malloc((size_t) (length / 2))) == NULL)
		CRITICAL_ERROR("out of memory.");
	for (i = 0; i <= ((length / 2) - 1); i++) {
		if (line[2 * i] >= 'a' && line[2 * i] <= 'f')
			line[2 * i] = line[2 * i] - 'a' + (char)10;
		else if (line[2 * i] >= '0' && line[2 * i] <= '9')
			line[2 * i] = line[2 * i] - '0';
		else if (line[2 * i] >= 'A' && line[2 * i] <= 'F')
			line[2 * i] = line[2 * i] - 'A' + (char)10;
		else {
			free(bytes);
			return TEST_FAIL;
		}
		bytes[i] = (unsigned char)(line[2 * i] * (char)16);
		if (line[2 * i + 1] >= 'a' && line[2 * i + 1] <= 'f')
			line[2 * i + 1] = line[2 * i + 1] - (char)87;
		else if (line[2 * i + 1] >= '0' && line[2 * i + 1] <= '9')
			line[2 * i + 1] = line[2 * i + 1] - (char)48;
		else if (line[2 * i + 1] >= 'A' && line[2 * i + 1] <= 'F')
			line[2 * i + 1] = line[2 * i + 1] - 'A' + (char)10;
		else {
			free(bytes);
			return TEST_FAIL;
		}
		bytes[i] += (unsigned char)line[2 * i + 1];
	}
	memcpy(line, bytes, (size_t) (length / 2));
	memset(line + length / 2, 0, (size_t) (length / 2 + 1));
	free(bytes);

	return TEST_SUCC;
}

static int sha1_new_api_test(test_t * test)
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
		return TEST_FAIL;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA1_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha1(SHA_MSG_PART_FIRST, SHA1_BLOCK_SIZE,
			       test->msg, &sha_context, output);
	if (rc != 0) {
		V_(printf("ica_sha1 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
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
			return TEST_FAIL;
		}
		off += i * SHA1_BLOCK_SIZE;
	}

	rc = (int)ica_sha1(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha_context, output);
	if (rc != 0) {
		V_(printf("ica_sha1 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA1_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA1_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha224_new_api_test(test_t * test)
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
		return TEST_FAIL;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA224_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha224(SHA_MSG_PART_FIRST, SHA224_BLOCK_SIZE,
			       test->msg, &sha256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
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
			return TEST_FAIL;
		}
		off += i * SHA224_BLOCK_SIZE;
	}

	rc = (int)ica_sha224(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha256_new_api_test(test_t * test)
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
		return TEST_FAIL;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA256_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha256(SHA_MSG_PART_FIRST, SHA256_BLOCK_SIZE,
			       test->msg, &sha256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
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
			return TEST_FAIL;
		}
		off += i * SHA256_BLOCK_SIZE;
	}

	rc = (int)ica_sha256(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha384_new_api_test(test_t * test)
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
		return TEST_FAIL;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA384_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA384_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA384_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha384(SHA_MSG_PART_FIRST, SHA384_BLOCK_SIZE,
			       test->msg, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha384 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
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
			return TEST_FAIL;
		}
		off += i * SHA384_BLOCK_SIZE;
	}

	rc = (int)ica_sha384(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha384 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA384_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA384_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha512_new_api_test(test_t * test)
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
		return TEST_FAIL;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA512_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA512_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA512_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha512(SHA_MSG_PART_FIRST, SHA512_BLOCK_SIZE,
			       test->msg, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha512 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
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
			return TEST_FAIL;
		}
		off += i * SHA512_BLOCK_SIZE;
	}

	rc = (int)ica_sha512(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha512 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA512_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA512_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha512_224_new_api_test(test_t * test)
{
	sha512_context_t sha512_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA512_224_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA512_224_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha512_224(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
				 &sha512_context, output);

	if (rc != 0) {
		V_(printf("ica_sha512_224 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA512_224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA512_224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA512_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha512_224(SHA_MSG_PART_FIRST, SHA512_BLOCK_SIZE,
				 test->msg, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha512_224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	for (off = SHA512_BLOCK_SIZE;
	     off < test->msg_length - SHA512_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA512_BLOCK_SIZE + 1);
		rc = (int)ica_sha512_224(SHA_MSG_PART_MIDDLE,
					 i * SHA512_BLOCK_SIZE,
					 test->msg + off,
					 &sha512_context, output);
		if (rc != 0) {
			V_(printf("ica_sha512_224 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return TEST_FAIL;
		}
		off += i * SHA512_BLOCK_SIZE;
	}

	rc = (int)ica_sha512_224(SHA_MSG_PART_FINAL, test->msg_length - off,
				 test->msg + off, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha512_224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA512_224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA512_224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha512_256_new_api_test(test_t * test)
{
	sha512_context_t sha512_context;
	int rc = 0;
	size_t off;
	unsigned char output[SHA512_256_HASH_LENGTH];
	time_t seed;
	int i;

	srand(time(&seed));

	if (test->msg_digest_length != SHA512_256_HASH_LENGTH)
		CRITICAL_ERROR("this shouldn't happen.");

	rc = (int)ica_sha512_256(SHA_MSG_PART_ONLY, test->msg_length, test->msg,
				 &sha512_context, output);

	if (rc != 0) {
		V_(printf("ica_sha512_256 failed with errno %d (0x%x).\n", rc,
		       (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest (new api)\n"));
	dump_array(output, SHA512_256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA512_256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA512_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha512_256(SHA_MSG_PART_FIRST, SHA512_BLOCK_SIZE,
				 test->msg, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha512_256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	for (off = SHA512_BLOCK_SIZE;
	     off < test->msg_length - SHA512_BLOCK_SIZE;) {
		i = rand()
		  % ((test->msg_length - off) / SHA512_BLOCK_SIZE + 1);
		rc = (int)ica_sha512_256(SHA_MSG_PART_MIDDLE,
					 i * SHA512_BLOCK_SIZE,
					 test->msg + off,
					 &sha512_context, output);
		if (rc != 0) {
			V_(printf("ica_sha512_256 %s failed"
				  " with errno %d (0x%x).\n",
				  "SHA_MSG_PART_MIDDLE", rc,
				  (unsigned int)rc));
			return TEST_FAIL;
		}
		off += i * SHA512_BLOCK_SIZE;
	}

	rc = (int)ica_sha512_256(SHA_MSG_PART_FINAL, test->msg_length - off,
				 test->msg + off, &sha512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha512_256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA512_256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA512_256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha3_224_api_test(test_t * test)
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
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA3_224_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha3_224(SHA_MSG_PART_FIRST, SHA3_224_BLOCK_SIZE,
			       test->msg, &sha3_224_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
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
			return TEST_FAIL;
		}
		off += i * SHA3_224_BLOCK_SIZE;
	}

	rc = (int)ica_sha3_224(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha3_224_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_224 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_224_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_224_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha3_256_api_test(test_t * test)
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
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA3_256_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha3_256(SHA_MSG_PART_FIRST, SHA3_256_BLOCK_SIZE,
			       test->msg, &sha3_256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
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
			return TEST_FAIL;
		}
		off += i * SHA3_256_BLOCK_SIZE;
	}

	rc = (int)ica_sha3_256(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha3_256_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_256 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_256_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_256_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha3_384_api_test(test_t * test)
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
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_384_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_384_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA3_384_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha3_384(SHA_MSG_PART_FIRST, SHA3_384_BLOCK_SIZE,
			       test->msg, &sha3_384_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_384 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
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
			return TEST_FAIL;
		}
		off += i * SHA3_384_BLOCK_SIZE;
	}

	rc = (int)ica_sha3_384(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha3_384_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_384 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_384_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_384_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}

static int sha3_512_api_test(test_t * test)
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
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_512_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_512_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	if (test->msg_length <= SHA3_512_BLOCK_SIZE)
		return TEST_SUCC;

	rc = (int)ica_sha3_512(SHA_MSG_PART_FIRST, SHA3_512_BLOCK_SIZE,
			       test->msg, &sha3_512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_512 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FIRST", rc, (unsigned int)rc));
		return TEST_FAIL;
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
			return TEST_FAIL;
		}
		off += i * SHA3_512_BLOCK_SIZE;
	}

	rc = (int)ica_sha3_512(SHA_MSG_PART_FINAL, test->msg_length - off,
			       test->msg + off, &sha3_512_context, output);
	if (rc != 0) {
		V_(printf("ica_sha3_512 %s failed with errno %d (0x%x).\n",
			  "SHA_MSG_PART_FINAL", rc, (unsigned int)rc));
		return TEST_FAIL;
	}

	VV_(printf("message digest\n"));
	dump_array(output, SHA3_512_HASH_LENGTH);

	if (memcmp(output, test->msg_digest, SHA3_512_HASH_LENGTH) != 0) {
		V_(printf("output is not what it should be.\n"));
		return TEST_FAIL;
	}

	return TEST_SUCC;
}
