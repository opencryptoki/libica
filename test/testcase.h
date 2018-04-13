/*
 * Testcase infrastructure.
 */
#ifndef TESTCASE_H
#define TESTCASE_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/ec.h>

#include "../include/ica_api.h"

/* automake test exist status */
#define TEST_SUCC	0
#define TEST_FAIL	1
#define TEST_SKIP	77
#define TEST_ERR	99

#define V_(print)	if (verbosity_ >= 1) print
#define VV_(print)	if (verbosity_ >= 2) print

static int verbosity_;	/* default verbosity level: 0 */

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

static inline void
dump_array_u64(uint64_t array[], size_t size)
{
	size_t i;

	for (i = 1; i <= size; i++) {
		VV_(printf("0x%016llx ", (unsigned long long)array[i - 1]));
		if ((i % 8 == 0) || (i == size))
			VV_(printf("\n"));
	}
}

static inline unsigned long long
delta_usec(const struct timeval *t1, const struct timeval *t2)
{
	return (t2->tv_sec * 1000000ULL + t2->tv_usec)
	       - (t1->tv_sec * 1000000ULL + t1->tv_usec);
}

static inline long double
ops_per_sec(unsigned long long ops, unsigned long long usec)
{
	return ops / ((long double)usec / 1000000ULL);
}

static inline int
sha3_available(void)
{
	sha3_224_context_t sha3_224_context;
	unsigned char output_hash[SHA3_224_HASH_LENGTH];
	unsigned char test_data[] = { 0x61,0x62,0x63 };
	int rc = 0;

	rc = ica_sha3_224(SHA_MSG_PART_ONLY, sizeof(test_data), test_data,
			&sha3_224_context, output_hash);

	return (rc == ENODEV ? 0 : 1);
}

static inline unsigned int
getenv_icapath()
{
	char* s = getenv("ICAPATH");
	int icapath=0; /* hw with sw fallback (default) */
	int env_icapath;

	if (s) {
		if (sscanf(s, "%d", &env_icapath) == 1) {
			switch (env_icapath) {
				case 1:	return 1; /* hw only */
				case 2: return 2; /* sw only */
				default:   break; /* default */
			}
		}
	}

	return icapath;
}

static inline int
is_supported_openssl_curve(int nid)
{
	EC_GROUP *ptr = EC_GROUP_new_by_curve_name(nid);
	if (ptr)
		EC_GROUP_free(ptr);
	return ptr ? 1 : 0;
}

static inline void
toggle_env_icapath()
{
	if (getenv_icapath() == 1)
		setenv("ICAPATH", "2", 1);
	else if (getenv_icapath() == 2)
		setenv("ICAPATH", "1", 1);
}

static inline void
unset_env_icapath()
{
	unsetenv("ICAPATH");
}

#endif /* TESTCASE_H */
