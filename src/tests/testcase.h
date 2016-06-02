/*
 * Testcase infrastructure.
 */
#ifndef TESTCASE_H
#define TESTCASE_H

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
		if (i % 8 == 0)
			VV_(printf("\n"));
	}
}

#endif /* TESTCASE_H */
