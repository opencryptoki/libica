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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <semaphore.h>
#include <pthread.h>
#include <syslog.h>

#include "init.h"
#include "fips.h"
#include "icastats.h"
#include "s390_rsa.h"
#include "s390_prng.h"
#include "s390_crypto.h"
#include "ica_api.h"

static pthread_key_t envq_key;
static pthread_once_t envq_key_once = PTHREAD_ONCE_INIT;

static void destroy_envq(void* envq)
{
	free(envq);
}

static void make_envq_key()
{
	pthread_key_create(&envq_key, destroy_envq);
}

static void sigill_handler(int sig)
{
	jmp_buf* envq = pthread_getspecific(envq_key);
	if (envq) {
		longjmp(*envq, EXCEPTION_RV);
	}
}

int begin_sigill_section(struct sigaction *oldact, sigset_t *oldset)
{
	struct sigaction newact;
	sigset_t newset;

	sigemptyset(&newset);
	sigaddset(&newset, SIGILL);
	sigprocmask(SIG_UNBLOCK, &newset, oldset);
	newact.sa_handler = (void *)sigill_handler;
	newact.sa_flags = 0;
	sigaction(SIGILL, &newact, oldact);

	jmp_buf* envq;
	pthread_once(&envq_key_once, make_envq_key);
	if ((envq = pthread_getspecific(envq_key)) == 0)
	{
		envq = malloc(sizeof(jmp_buf));
		pthread_setspecific(envq_key, envq);
	}
	if (setjmp(*envq) != 0) {
		end_sigill_section(oldact, oldset);
		return -1;
	}
	return 0;
}

void end_sigill_section(struct sigaction *oldact, sigset_t *oldset)
{
	sigaction(SIGILL, oldact, 0);
	sigprocmask(SIG_SETMASK, oldset, 0);
}

static pthread_mutex_t *openssl_locks;

static void openssl_lock_callback(int mode, int num, char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(openssl_locks[num]));
	}
	else {
		pthread_mutex_unlock(&(openssl_locks[num]));
	}
}

static unsigned long get_thread_id(void)
{
	return (unsigned long)pthread_self();
}

static void init_openssl_locks(void)
{
	int i, crypt_num_locks;

	crypt_num_locks = CRYPTO_num_locks();
	openssl_locks = (pthread_mutex_t *)
			OPENSSL_malloc(crypt_num_locks *
				       sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(openssl_locks[i]),NULL);
	}

	CRYPTO_set_id_callback((unsigned long (*)())get_thread_id);
	CRYPTO_set_locking_callback((void (*)
		(int, int, const char*, int))openssl_lock_callback);

	sem_init(&openssl_crypto_lock_mtx, 0, crypt_num_locks);
}

static void free_openssl_locks(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_destroy(&(openssl_locks[i]));

	OPENSSL_free(openssl_locks);
}

void openssl_init(void)
{
	/* initial seed the openssl random generator */
	unsigned char random_data[64];
	s390_prng(random_data, sizeof(random_data));
	RAND_seed(random_data, sizeof(random_data));
	init_openssl_locks();
}

/* Switches have to be done first. Otherwise we will not have hw support
 * in initialization */
void __attribute__ ((constructor)) icainit(void)
{
	/* some init stuff but only when application is NOT icastats */
	if (strcmp(program_invocation_name, "icastats")) {

		if(stats_mmap(-1) == -1){
			syslog(LOG_INFO,
			  "Failed to access shared memory segment for libica statistics.");
		}

		s390_crypto_switches_init();

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

		openssl_init();
	}
}

void __attribute__ ((destructor)) icaexit(void)
{
	stats_munmap(SHM_CLOSE);
	free_openssl_locks();
}
