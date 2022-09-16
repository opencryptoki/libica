#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "ica_api.h"
#include "testcase.h"

#define FIPS_FLAG "/proc/sys/crypto/fips_enabled"

int
main(void)
{
	FILE *fd;
	int fips, rv;
	char fips_flag;

	printf("Kernel FIPS flag (%s) is ", FIPS_FLAG);
	if ((fd = fopen(FIPS_FLAG, "r")) != NULL) {
		if (fread(&fips_flag, sizeof(fips_flag), 1, fd) == 1) {
			fips_flag -= '0';
			printf("%d.", fips_flag);
		} else {
			printf("not readable.");
		}
		fclose(fd);
	}
	else {
		fips_flag = 0;
		printf("not present.");
	}
	printf("\nKernel %s in FIPS mode.\n", fips_flag ?
	    "runs" : "doesn't run");

	printf("Libica has ");
#ifdef ICA_FIPS
	fips = ica_fips_status();
#else
	fips = 0;
	printf("no ");
#endif /* ICA_FIPS */
	printf("built-in FIPS support.\nLibica %s in FIPS mode.\n",
	    fips & ICA_FIPS_MODE ? "runs" : "doesn't run");

	rv = EXIT_SUCCESS;
#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) != fips_flag) {
		/* Check if the fips_flag is turned on via env variable. In this case
		 * skip the test. */
		char *fips_override = getenv("LIBICA_FIPS_FLAG");
		if ((fips_override != NULL) && (atoi(fips_override) == 1)) {
			printf("Skip test: kernel is not in fips mode, but libica fips flag is set via env variable.\n");
			return TEST_SKIP;
		}
		printf("This shouldn't happen.\n");
		rv = EXIT_FAILURE;
	}
	if (fips & ICA_FIPS_CRYPTOALG) {
		printf("Libica FIPS powerup test failed.\n");
		rv = EXIT_FAILURE;
	}
	if (fips & ICA_FIPS_INTEGRITY) {
		printf("Libica FIPS integrity check failed.\n");
		rv = EXIT_FAILURE;
	}
#endif /* ICA_FIPS */

	printf("OpenSSL version is '%s'.\n", OPENSSL_VERSION_TEXT);
	printf("OpenSSL %s in FIPS mode.\n\n", fips ?
	    "runs" : "doesn't run");

	if (rv)
		return TEST_FAIL;

	return TEST_SUCC;
}
