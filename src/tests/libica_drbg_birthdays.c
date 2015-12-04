/*
 * Multithreaded birthday paradox test for a sha512 instantiation of ica_drbg
 *
 * usage: ica_drbg_birthdays <rnd_ex1> <rnd_ex2> <rnd_ex3>
 *
 * rnd_ex# is the no. of random experiments to be done for test no.#
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ica_api.h"

/*
 * no. of people	no. of possible birthdays	probability of a pair
 *     = THREADS	   = 2 ^ ( 8 * GEN_BYTES)
 * --------------------------------------------------------------------------
 *	      19		256 = 2 ^ (8 * 1)			  0.5
 *	     301	      65536 = 2 ^ (8 * 2)			  0.5
 *	    4823	   16777216 = 2 ^ (8 * 3)			  0.5
 */
static const int THREADS[]   = {19, 301, 4823};
static const int GEN_BYTES[] = { 1,   2,    3};

static int test	       = 0;
static ica_drbg_t *sh  = NULL;

void *thread(void *buffer)
{
	int rc = ica_drbg_generate(sh, 0, false, NULL, 0, buffer,
				   GEN_BYTES[test]);
	if(rc){
		fprintf(stderr, "error: ica_drbg_generate: %s (%d)\n",
			strerror(rc), rc);
		exit(1);
	}

	return NULL;
}

int main(int argc, char **argv)
{
	if(2 > argc || 4 < argc){
		fprintf(stderr,
			"usage: ica_drbg_birthdays <rnd_ex1> <rnd_ex2>"
			"<rnd_ex3>\n");
		exit(1);
	}
	long rnd_ex[3] = {0};
	int i = 1;
	for(; i < argc; i++)
		rnd_ex[i - 1] = strtol(argv[i], NULL, 10);

	/* create instantiation */
	int rc = ica_drbg_instantiate(&sh, 0, false, ICA_DRBG_SHA512, NULL, 0);
	if(rc){
		fprintf(stderr, "error: ica_drbg_instantiate: %s (%d)\n",
			strerror(rc), rc);
		exit(1);
	}

	printf("Multithreaded birthday paradox test for a sha512 "
	       "instantiation of ica_drbg\n"
	       "(the test result is good, if p is close to 0.5 for a large"
	       " number of random experiments)\n");
	/* perform each of the 3 tests rnd_ex[test] times */
	for(; test < 3; test++){
		if(!rnd_ex[test])
			continue;

		printf("%ld random Experiment(s): %4d threads, "
		       "%1d bytes/thread generated...\n",
		       rnd_ex[test], THREADS[test], GEN_BYTES[test]);
		pthread_t threads[THREADS[test]];

		unsigned char buffer[THREADS[test]][GEN_BYTES[test]];

		int status[THREADS[test]];
		long pair_found = 0;
		long ex = 0;
		for(; ex < rnd_ex[test]; ex++){
			/* start threads */
			for(i = 0; i < THREADS[test]; i++){
				if((rc = pthread_create(&threads[i], NULL,
							thread, buffer[i]))){
					fprintf(stderr,
						"error: pthread_create: "
						"%s (%d)\n",
						strerror(rc), rc);
					exit(1);
				}
			}

			/* wait for threads */
			for(i = 0; i < THREADS[test]; i++){
				if((rc = pthread_join(threads[i],
				   (void**)&status[i]))){
					fprintf(stderr, "error: pthread_join "
						"%s (%d)\n",
						strerror(rc), rc);
					exit(1);
				}
			}

			/* search pairs */
			bool toggle = false;
			for(i = 0; i < THREADS[test]; i++){
				int j = 0;
				for(; j < THREADS[test]; j++){
					if(!memcmp(buffer[i], buffer[j],
						   GEN_BYTES[test]) && i != j){
						pair_found++;
						toggle = true;
						break;
					}
				}
				if(toggle)
					break;
			}
		}
		printf("... %ld times a pair was found (p = %1.2f).\n",
		       pair_found, (float)pair_found/ex);
	}

	return 0;
}
