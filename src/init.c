/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	        Christian Maaser <cmaaser@de.ibm.com>
 * 	        Ingo Tuchscherer <ingo.tuchscherer.linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2001, 2009, 2011
 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>

#include "init.h"
#include "fips.h"
#include "icastats.h"
#include "s390_prng.h"
#include "s390_crypto.h"
#include "ica_api.h"

static sigjmp_buf sigill_jmp;

static void sigill_handler(int sig)
{
	siglongjmp(sigill_jmp, sig);
}

int begin_sigill_section(struct sigaction *oldact, sigset_t *oldset)
{
	struct sigaction newact;

	memset(&newact, 0, sizeof(newact));
	newact.sa_handler = sigill_handler;
	sigfillset(&newact.sa_mask);
	sigdelset(&newact.sa_mask, SIGILL);
	sigdelset(&newact.sa_mask, SIGTRAP);

	sigprocmask(SIG_SETMASK, &newact.sa_mask, oldset);
	sigaction(SIGILL, &newact, oldact);
	return sigsetjmp(sigill_jmp, 1);
}

void end_sigill_section(struct sigaction *oldact, sigset_t *oldset)
{
	sigaction(SIGILL, oldact, NULL);
	sigprocmask(SIG_SETMASK, oldset, NULL);
}

void __attribute__ ((constructor)) icainit(void)
{
	int value;
	const char *ptr;

	/* some init stuff but only when application is NOT icastats */
	if (!strcmp(program_invocation_name, "icastats"))
		return;

	if(stats_mmap(-1) == -1){
		syslog(LOG_INFO,
		  "Failed to access shared memory segment for libica statistics.");
	}

	/*
	 * Switches have to be done first. Otherwise we will not have
	 * hw support in initialization.
	 */
	s390_crypto_switches_init();

	/* check for fallback mode environment variable */
	ptr = getenv(ICA_FALLBACK_ENV);
	if (ptr && sscanf(ptr, "%i", &value) == 1)
		ica_set_fallback_mode(value);

	/* check for offload mode environment variable */
	ptr = getenv(ICA_OFFLOAD_ENV);
	if (ptr && sscanf(ptr, "%i", &value) == 1)
		ica_set_offload_mode(value);

	/* check for stats mode environment variable */
	ptr = getenv(ICA_STATS_ENV);
	if (ptr && sscanf(ptr, "%i", &value) == 1)
		ica_set_stats_mode(value);

#ifdef ICA_FIPS
	fips_init();
	fips_powerup_tests();
#else
	/* The fips_powerup_tests() include the ica_drbg_health_test(). */
	ica_drbg_health_test(ica_drbg_generate, 256, true,
				     ICA_DRBG_SHA512);
#endif /* ICA_FIPS */

	s390_prng_init();

	s390_initialize_functionlist();
}

void __attribute__ ((destructor)) icaexit(void)
{
	stats_munmap(SHM_CLOSE);
}
