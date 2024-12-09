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
#include <pthread.h>

#include "init.h"
#include "fips.h"
#include "icastats.h"
#include "s390_prng.h"
#include "s390_crypto.h"
#include "ica_api.h"
#include "rng.h"

#if OPENSSL_VERSION_PREREQ(3, 0)
#include <openssl/crypto.h>
#include <openssl/provider.h>
OSSL_LIB_CTX *openssl_libctx;
OSSL_PROVIDER *openssl_provider;
int openssl3_initialized = 0;
#endif

pthread_rwlock_t fips_list_lock;

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


void ica_cleanup(void)
{
#if OPENSSL_VERSION_PREREQ(3, 0)
	if (openssl_provider != NULL)
		OSSL_PROVIDER_unload(openssl_provider);
	openssl_provider = NULL;
	if (openssl_libctx != NULL)
		OSSL_LIB_CTX_free(openssl_libctx);
	openssl_libctx = NULL;
#endif
}

void __attribute__ ((constructor)) icainit(void)
{
	int value;
	const char *ptr;

	/* some init stuff but only when application is NOT icastats */
	if (!strcmp(program_invocation_name, "icastats"))
		return;

	if (stats_mmap(-1) == -1) {
		syslog(LOG_WARNING,
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
	fips_get_indicator();
#endif

	rng_init();

	s390_prng_init();

	s390_initialize_functionlist();

#if OPENSSL_VERSION_PREREQ(3, 0)
	/*
	 * OpenSSL >= 3.0:
	 * Create a separate library context for libica's use of OpenSSL services
	 * and explicitly load the 'default' or 'fips' provider for this context.
	 *
	 * Ensure OpenSSL is initialized and the OpenSSL config is loaded
	 * BEFORE creating the library context. Otherwise the OpenSSL config
	 * is loaded later, which may cause that all configured providers
	 * are also loaded into the library context. We need to make sure that
	 * only the default or fips provider is loaded in the library context.
	 *
	 * Also make sure that OpenSSL initialization happens AFTER the
	 * mechanism list has been initialized and the fips indicator has been
	 * obtained. OPENSSL_init_crypto may load configured providers, and a
	 * provider might use libica in its initialization function. It must
	 * be ensured that libica has been initialized that far before OpenSSL
	 * is initialized, so that such libica calls from providers can be
	 * fulfilled and return correct information.
	 *
	 * The remaining FIPS initialization (fips provider load, power on self
	 * tests, etc) must still happen after OpenSSL initialization, because
	 * that relies on OpenSSL being initialized.
	 */
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

	openssl_libctx = OSSL_LIB_CTX_new();
	if (openssl_libctx == NULL) {
		syslog(LOG_ERR, "Libica: failed to create openssl lib context\n");
		return;
	}
#endif

#ifdef ICA_FIPS
	if (pthread_rwlock_init(&fips_list_lock, NULL) != 0) {
		syslog(LOG_ERR, "Initializing fips_list_lock failed.\n");
		return;
	}

	fips_init();
#endif

#if OPENSSL_VERSION_PREREQ(3, 0)
	openssl3_initialized = 1;
#endif


#ifdef ICA_FIPS
	if (fips & ICA_FIPS_MODE)
		fips_powerup_tests();
#else
#if OPENSSL_VERSION_PREREQ(3, 0)
	openssl_provider = OSSL_PROVIDER_load(openssl_libctx, "default");
	if (openssl_provider == NULL) {
		syslog(LOG_ERR, "Libica: failed to load default provider\n");
		return;
	}
#endif

	/* The fips_powerup_tests() include the ica_drbg_health_test(). */
	ica_drbg_health_test(ica_drbg_generate, 256, true,
				     ICA_DRBG_SHA512);
#endif /* ICA_FIPS */

	/* close the remaining open syslog file descriptor */
	closelog();
}

void __attribute__ ((destructor)) icaexit(void)
{
	rng_fini();

	s390_prng_fini();

	stats_munmap(-1, SHM_CLOSE);

	pthread_rwlock_destroy(&fips_list_lock);
}
