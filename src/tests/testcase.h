/*
 * Testcase infrastructure.
 */
#ifndef TESTCASE_H
#define TESTCASE_H

#include <errno.h>
#include <stddef.h>
#include <string.h>

#define V_(print)	if (verbosity_ >= 1) print
#define VV_(print)	if (verbosity_ >= 2) print

#ifdef VERBOSITY_EXTERN
extern
#endif
int verbosity_;	/* default verbosity level: 0 */

static inline void
set_verbosity(int argc, char *argv[])
{
	int i;

	for (i = 1; i < argc; i++) {
		if (strcasestr(argv[i], "-vv")) {
			verbosity_ = 2;
			break;
		}
		if (strcasestr(argv[i], "-v")) {
			verbosity_ = 1;
			break;
		}
	}
}

static inline void
dump_array(unsigned char array[], size_t len)
{
	size_t i;

	for (i = 1; i <= len; i++) {
		VV_(printf("0x%02x ", array[i - 1]));
		if ((i % 8 == 0) || (i == len))
			VV_(printf("\n"));
	}
}

static inline int
sha3_available(void)
{
	sha3_224_context_t sha3_224_context;
	unsigned char output_hash[SHA3_224_HASH_LENGTH];
	unsigned char test_data[] = { 0x61,0x62,0x63 };
	int rc=0;

	rc = ica_sha3_224(SHA_MSG_PART_ONLY, sizeof(test_data), test_data,
			&sha3_224_context, output_hash);

	return (rc == EPERM ? 0 : 1);
}

#endif /* TESTCASE_H */
