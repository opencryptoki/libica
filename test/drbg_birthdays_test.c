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
#include "testcase.h"

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
	int rc;

	rc = ica_drbg_generate(sh, 0, false, NULL, 0, buffer, GEN_BYTES[test]);
	if(rc){
		fprintf(stderr, "error: ica_drbg_generate: %s (%d)\n",
			strerror(rc), rc);
		exit(1);
	}

	return NULL;
}

int main(int argc, char **argv)
{
	long rnd_ex[3] = {0}, ex, pair_found;
	int i, j, rc;
	bool toggle;

	if(2 > argc || 4 < argc){
		fprintf(stderr,
			"usage: ica_drbg_birthdays <rnd_ex1> <rnd_ex2>"
			" <rnd_ex3>\n");
		return TEST_ERR;
	}
	for(i = 1; i < argc; i++)
		rnd_ex[i - 1] = strtol(argv[i], NULL, 10);

	/* create instantiation */
	rc = ica_drbg_instantiate(&sh, 0, false, ICA_DRBG_SHA512, NULL, 0);
	if(rc){
		fprintf(stderr, "error: ica_drbg_instantiate: %s (%d)\n",
			strerror(rc), rc);
		return TEST_FAIL;
	}

	printf("Multithreaded birthday paradox test for a sha512 "
	       "instantiation of ica_drbg\n"
	       "(the test result is good, if p is close to 0.5 for a large"
	       " number of random experiments)\n");

	/* perform each of the 3 tests rnd_ex[test] times */
	for(test = 0; test < 3; test++){
		if(!rnd_ex[test])
			continue;

		int status[THREADS[test]];
		unsigned char buffer[THREADS[test]][GEN_BYTES[test]];

		pair_found = 0;

		printf("%ld random Experiment(s): %d threads, "
		       "%1d bytes/thread generated...\n",
		       rnd_ex[test], THREADS[test], GEN_BYTES[test]);
		pthread_t threads[THREADS[test]];

		for(ex = 0; ex < rnd_ex[test]; ex++){
			/* start threads */
			for(i = 0; i < THREADS[test]; i++){
				while((rc = pthread_create(&threads[i], NULL,
				      thread, buffer[i])) == EAGAIN)
					;
				if(rc){
					fprintf(stderr,
						"error: pthread_create: "
						"%s (%d)\n",
						strerror(rc), rc);
					return TEST_FAIL;
				}
			}

			/* wait for threads */
			for(i = 0; i < THREADS[test]; i++){
				if((rc = pthread_join(threads[i],
				   (void**)&status[i]))){
					fprintf(stderr, "error: pthread_join "
						"%s (%d)\n",
						strerror(rc), rc);
					return TEST_FAIL;
				}
			}

			/* search pairs */
			toggle = false;
			for(i = 0; i < THREADS[test]; i++){
				for(j = 0; j < THREADS[test]; j++){
					if(i != j && !memcmp(buffer[i],
					   buffer[j], GEN_BYTES[test])){
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

	/* destroy instantiation */
	rc = ica_drbg_uninstantiate(&sh);
	if(rc){
		fprintf(stderr, "error: ica_drbg_uninstantiate: %s (%d)\n",
			strerror(rc), rc);
		return TEST_FAIL;
	}
	return TEST_SUCC;
}
