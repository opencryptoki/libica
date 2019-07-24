/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * Copyright IBM Corp. 2018
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "ica_api.h"
#include "rng.h"
#include "s390_crypto.h"

static ica_drbg_t *rng_sh = ICA_DRBG_NEW_STATE_HANDLE;

/*
 * rng dev list. The first string (element 0) has the highest priority.
 */
static const char *const RNGDEV[] = {"/dev/prandom",
				     "/dev/hwrng",
				     "/dev/urandom",
				     NULL};

void rng_init(void)
{
	if (!sha512_switch && !sha512_drng_switch)
		return;

	/*
	 * Dont need to check return code here: rng_sh is NULL in
	 * case of failure.
	 */
	ica_drbg_instantiate(&rng_sh, 256, false, ICA_DRBG_SHA512,
			     (unsigned char *)"INTERNAL INSTANCE",
			     sizeof("INTERNAL INSTANCE"));
}

void rng_gen(unsigned char *buf, size_t buflen)
{
	const char *rngdev;
	FILE *rng_fh;
	int rc;

	if (rng_sh != NULL) {
	    rc = ica_drbg_generate(rng_sh, 256, false, NULL, 0, buf, buflen);
	    if (!rc)
		return;
	}

	for (rngdev = RNGDEV[0]; rngdev != NULL; rngdev++) {
		rng_fh = fopen(rngdev, "r");
		if (rng_fh) {
			rc = fread(buf, buflen, 1, rng_fh);
			fclose(rng_fh);
			if (rc == 1)
				return;
		}
	}

	syslog(LOG_ERR, "Libica internal RNG error..");
	fprintf(stderr, "Libica internal RNG error.");
	exit(1);
}

void rng_fini(void)
{
	if (rng_sh != NULL)
		ica_drbg_uninstantiate(&rng_sh);
}
