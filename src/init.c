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
#include <syslog.h>

#include "init.h"
#include "icastats.h"
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


void openssl_init(void)
{
	static const int random_data_length = 64;
	unsigned char random_data[random_data_length];
	/* Counts PRNG statistic! */
	s390_prng(random_data, random_data_length);
	RAND_seed(random_data, random_data_length);
}

/* Switches have to be done first. Otherwise we will not have hw support
 * in initialization */
void __attribute__ ((constructor)) icainit(void)
{
	if(strcmp(program_invocation_name, "icastats")){
		if(stats_mmap(-1) == -1){
			syslog(LOG_INFO,
			  "Failed to access shared memory segment for libica statistics.");
		}

		s390_crypto_switches_init();

		ica_drbg_health_test(ica_drbg_generate, 256, true,
				     ICA_DRBG_SHA512);

		s390_prng_init();

		s390_initialize_functionlist();

		openssl_init();
	}
}

void __attribute__ ((destructor)) icaexit(void)
{
	stats_munmap(SHM_CLOSE);
}

