#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ica_api.h"
#include "queue_t.h"
#include "critical_error.h"
#include "read_rsp.h"

static int line_to_bytes(char *line, int length);

int read_test_data(FILE * test_data, int sha3_flag)
{
	char buffer[BUFFER_SIZE];
	enum { MSG_LENGTH, MSG, MSG_DIGEST } search_term;

	test_t tmp_test = new_test_t();
	unsigned int current_type = NO_TYPE_SET;
	unsigned int current_msg_digest_length = NO_LENGTH_SET;

	unsigned int line_number = 0;

	char *tmp = NULL;
	search_term = MSG_LENGTH;

	while (fgets(buffer, (int)sizeof buffer, test_data) != NULL) {

		line_number++;

		/* remove comments */
		if ((tmp = memchr(buffer, (int)'#', strlen(buffer))) != NULL)
			memset(tmp, 0, strlen(tmp));

		/* scan for: type/msg_digest_length */
		if (((sscanf(buffer, "[L = %u]", &current_msg_digest_length))
		     == 1)
		    || (current_type == NO_TYPE_SET)) {
			if (tmp_test.type != NO_TYPE_SET) {
				printf
				    ("error:\nincorrect file format [line %u]: test type mustn't change during test definition. closing file.\n",
				     line_number);
				return EXIT_FAILURE;
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
				current_type = sha3_flag ? SHA3_224 : SHA224;
				break;
			case SHA256_HASH_LENGTH:
				current_type = sha3_flag ? SHA3_256 : SHA256;
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
					return EXIT_FAILURE;
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
					return EXIT_FAILURE;
				}
				if (line_to_bytes
				    (buffer,
				     (int)strlen(buffer)) == EXIT_FAILURE) {
					printf
					    ("error:\nincorrect file format [line %u]: message contains characters different from hex values. closing file.\n",
					     line_number);
					return EXIT_FAILURE;
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
					return EXIT_FAILURE;
				}
				if (line_to_bytes
				    (buffer,
				     (int)strlen(buffer)) == EXIT_FAILURE) {
					printf
					    ("error:\nincorrect file format [line %u]: message digest contains characters different from hex values. closing file.\n",
					     line_number);
					free(tmp_test.msg);
					return EXIT_FAILURE;
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
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
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
			return EXIT_FAILURE;
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
			return EXIT_FAILURE;
		}
		bytes[i] += (unsigned char)line[2 * i + 1];
	}
	memcpy(line, bytes, (size_t) (length / 2));
	memset(line + length / 2, 0, (size_t) (length / 2 + 1));
	free(bytes);

	return EXIT_SUCCESS;
}
