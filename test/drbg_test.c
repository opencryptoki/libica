/*
 * This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * DRBG conforming to NIST SP800-90A
 *
 * Author(s): Patrick Steuer <patrick.steuer@de.ibm.com>
 *
 * Copyright IBM Corp. 2015
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ica_api.h"
#include "s390_drbg.h"
#include "testcase.h"

/*
 * Known answer test types
 */
typedef struct{
	/* Inputs */
	ica_drbg_t **sh;
	int sec;
	bool pr;
	ica_drbg_mech_t *const mech;
	const unsigned char *pers;
	size_t pers_len;
	/* Expected return code */
	int rc;
}instantiate_test_t;

typedef struct{
	/* Inputs */
	ica_drbg_t *sh;
	bool pr;
	const unsigned char *add;
	size_t add_len;
	/* Expected return code */
	int rc;
}reseed_test_t;

typedef struct{
	/* Inputs */
	ica_drbg_t *sh;
	int sec;
	bool pr;
	const unsigned char *add;
	size_t add_len;
	size_t prnd_len;
	/* Expected return code */
	int rc;
}generate_test_t;

typedef struct{
	/* Inputs */
	ica_drbg_t **sh;
	/* Expected return code */
	int rc;
}uninstantiate_test_t;

typedef struct{
	/* Inputs */
	void *func;
	int sec;
	bool pr;
	ica_drbg_mech_t *mech;
	/* Expected return code */
	int rc;
}health_test_test_t;

/*
 * Testcase
 */
int main(int argc,
	 char **argv)
{
	unsigned int i = 0;
	int failed = 0;
	int passed = 0;
	int status = -1;
	const unsigned char pers[]  = {0x7e,0xa1,0x0e,0x96,0xaf,0x90,0x0c,0x25,
				       0xd3,0xbe,0x3b,0x50,0xa0,0xcc,0x71,0xa7,
				       0x9f,0xe4,0x14,0xbd,0x4c,0x37,0x39,0x80,
				       0x3f,0x02,0xff,0xe5,0xb2,0x60,0xbf,0xbb,};
	const unsigned char add[] = {0xc0,0x66,0xfd,0x2e,0xb8,0xe4,0xae,0xa2,
				     0xe7,0x14,0x5e,0xda,0x0c,0xfc,0x8b,0xef,
				     0x5e,0xed,0xcc,0x36,0x7b,0x1c,0xb4,0xde,
				     0x7e,0xb2,0xc2,0x75,0x9f,0xa7,0x5b,0xf7,};
	size_t pers_len = sizeof(pers) / sizeof(pers[0]);
	size_t add_len = sizeof(add) / sizeof(add[0]);

	set_verbosity(argc, argv);

	/*
	 * drbg_sha512 tests
	 */

	/* Instantiate */
	ica_drbg_t *sh = NULL;
	ica_drbg_t *sh2 = &(ica_drbg_t){.lock = PTHREAD_MUTEX_INITIALIZER};
	drbg_recursive_mutex_init(&sh2->lock);

	const instantiate_test_t inst_test[] = {
	{
		.mech = ICA_DRBG_SHA512,
		.sh = &sh,
		.sec = DRBG_SEC_112,
		.pr = true,
		.pers = NULL,
		.pers_len = 0,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.sh = &sh,
		.sec = DRBG_SEC_192,
		.pr = true,
		.pers = pers,
		.pers_len = pers_len,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.sh = &sh,
		.sec = DRBG_SEC_256,
		.pr = false,
		.pers = pers,
		.pers_len = pers_len,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.sh = &sh,
		.sec = DRBG_SEC_128,
		.pr = false,
		.pers = NULL,
		.pers_len = 0,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.sh = &sh,
		.sec = DRBG_SEC_256 + 1,
		.pr = true,
		.pers = NULL,
		.pers_len = 0,
		.rc = ENOTSUP,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.sh = &sh,
		.sec = DRBG_SEC_112,
		.pr = false,
		.pers = pers,
		.pers_len = ICA_DRBG_SHA512->max_pers_len + 1,
		.rc = EINVAL,
	},
	{
		.mech = NULL,
		.sh = &sh,
		.sec = DRBG_SEC_128,
		.pr = true,
		.pers = NULL,
		.pers_len = 0,
		.rc = EINVAL,
	},
	{
		.mech = NULL,
		.sh = NULL,
		.sec = DRBG_SEC_192,
		.pr = false,
		.pers = NULL,
		.pers_len = 0,
		.rc = EINVAL,
	},
	{
		.mech = NULL,
		.sh = &sh2,
		.sec = DRBG_SEC_256,
		.pr = true,
		.pers = pers,
		.pers_len = pers_len,
		.rc = EINVAL,
	},
	};
	for(i = 0; i < sizeof(inst_test) / sizeof(inst_test[0]); i++){
		V_(printf("instantiate function: test no. %u", i));
		status = ica_drbg_instantiate(inst_test[i].sh,
					      inst_test[i].sec,
					      inst_test[i].pr,
					      inst_test[i].mech,
					      inst_test[i].pers,
					      inst_test[i].pers_len);
		if(inst_test[i].rc == status){
			V_(printf(" passed\n"));
			passed++;
		}
		else{
			V_(printf(" failed\n"));
			failed++;
		}
		ica_drbg_uninstantiate(inst_test[i].sh);
	}

	/* Reseed */
	ica_drbg_t *sh_pr_false = NULL;
	ica_drbg_t *sh_pr_true = NULL;
	ica_drbg_instantiate(&sh_pr_true, DRBG_SEC_112, true, ICA_DRBG_SHA512,
			     pers, pers_len);
	ica_drbg_instantiate(&sh_pr_false, DRBG_SEC_112, false,
			     ICA_DRBG_SHA512, pers, pers_len);
	const reseed_test_t res_test[] = {
	{
		.sh = sh_pr_true,
		.pr = true,
		.add = NULL,
		.add_len = 0,
		.rc = 0,
	},
	{
		.sh = sh_pr_false,
		.pr = false,
		.add = add,
		.add_len = add_len,
		.rc = 0,
	},
	{
		.sh = sh_pr_true,
		.pr = true,
		.add = add,
		.add_len = ICA_DRBG_SHA512->max_add_len + 1,
		.rc = EINVAL,
	},
	{
		.sh = NULL,
		.pr = true,
		.add = NULL,
		.add_len = 0,
		.rc = EINVAL,
	},
	{
		.sh = sh_pr_false,
		.pr = true,
		.add = add,
		.add_len = add_len,
		.rc = ENOTSUP,
	},
	};
	for(i = 0; i < sizeof(res_test) / sizeof(res_test[0]); i++){
		V_(printf("reseed function: test no. %u", i));
		status = ica_drbg_reseed(res_test[i].sh, res_test[i].pr,
					 res_test[i].add, res_test[i].add_len);
		if(res_test[i].rc == status){
			V_(printf(" passed\n"));
			passed++;
		}
		else{
			V_(printf(" failed\n"));
			failed++;
		}
	}
	ica_drbg_uninstantiate(&sh_pr_true);
	ica_drbg_uninstantiate(&sh_pr_false);

	/* Generate */
	sh_pr_false = NULL;
	sh_pr_true = NULL;
	ica_drbg_instantiate(&sh_pr_true, DRBG_SEC_192, true, ICA_DRBG_SHA512,
			     pers, pers_len);
	ica_drbg_instantiate(&sh_pr_false, DRBG_SEC_192, false,
			     ICA_DRBG_SHA512, pers, pers_len);

	const generate_test_t gen_test[] = {
	{
		.sh = sh_pr_true,
		.sec = DRBG_SEC_112,
		.pr = true,
		.add = add,
		.add_len = add_len,
		.prnd_len = 0,
		.rc = 0,
	},
	{
		.sh = sh_pr_true,
		.sec = DRBG_SEC_112,
		.pr = true,
		.add = NULL,
		.add_len = 0,
		.prnd_len = 256,
		.rc = 0,
	},
	{
		.sh = sh_pr_false,
		.sec = DRBG_SEC_192,
		.pr = false,
		.add = NULL,
		.add_len = 0,
		.prnd_len = ICA_DRBG_SHA512->max_no_of_bytes_per_req,
		.rc = 0,
	},
	{
		.sh = sh_pr_false,
		.sec = DRBG_SEC_192,
		.pr = false,
		.add = add,
		.add_len = add_len,
		.prnd_len = 512,
		.rc = 0,
	},
	{
		.sh = sh_pr_true,
		.sec = DRBG_SEC_128,
		.pr = true,
		.add = add,
		.add_len = add_len,
		.prnd_len = 1024,
		.rc = 0,
	},
	{
		.sh = sh_pr_false,
		.sec = DRBG_SEC_256,
		.pr = false,
		.add = NULL,
		.add_len = 0,
		.prnd_len = 2048,
		.rc = ENOTSUP,
	},
	{
		.sh = sh_pr_false,
		.sec = DRBG_SEC_112,
		.pr = true,
		.add = add,
		.add_len = add_len,
		.prnd_len = 3072,
		.rc = ENOTSUP,
	},
	{
		.sh =  NULL,
		.sec = DRBG_SEC_112,
		.pr = true,
		.add = add,
		.add_len = add_len,
		.prnd_len = 128,
		.rc = EINVAL,
	},
	{
		.sh = sh_pr_true,
		.sec = DRBG_SEC_128,
		.pr = false,
		.add = add,
		.add_len = ICA_DRBG_SHA512->max_add_len + 1,
		.prnd_len = 64,
		.rc = EINVAL,
	},
	};
	for(i = 0; i < sizeof(gen_test) / sizeof(gen_test[0]); i++){
		V_(printf("generate function: test no. %u", i));
		size_t prnd_len = gen_test[i].prnd_len;
		unsigned char prnd[prnd_len + 1];	/* +1 avoids 0-length VLA */
		status = ica_drbg_generate(gen_test[i].sh, gen_test[i].sec,
					   gen_test[i].pr, gen_test[i].add,
					   gen_test[i].add_len, prnd,
					   prnd_len);
		if(gen_test[i].rc == status){
			V_(printf(" passed\n"));
			passed++;
		}
		else{
			V_(printf(" failed\n"));
			failed++;
		}
	}
	ica_drbg_uninstantiate(&sh_pr_true);
	ica_drbg_uninstantiate(&sh_pr_false);

	/* Uninstantiate */
	sh = NULL;
	ica_drbg_instantiate(&sh, DRBG_SEC_256, true, ICA_DRBG_SHA512, pers,
			     pers_len);
	const uninstantiate_test_t uninst_test[] = {
	{
		.sh = &sh,
		.rc = 0,
	},
	{
		.sh = NULL,
		.rc = EINVAL,
	},
	};
	for(i = 0; i < sizeof(uninst_test) / sizeof(uninst_test[0]); i++){
		V_(printf("uninstantiate function: test no. %u", i));
		status = ica_drbg_uninstantiate(uninst_test[i].sh);
		if(uninst_test[i].rc == status){
			V_(printf(" passed\n"));
			passed++;
		}
		else{
			V_(printf(" failed\n"));
			failed++;
		}
	}
	ica_drbg_uninstantiate(&sh);

	/* Health test */
	const health_test_test_t ht_test[] = {
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_instantiate,
		.sec = DRBG_SEC_112,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_instantiate,
		.sec = DRBG_SEC_128,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_instantiate,
		.sec = DRBG_SEC_192,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_instantiate,
		.sec = DRBG_SEC_256,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_instantiate,
		.sec = DRBG_SEC_112,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_instantiate,
		.sec = DRBG_SEC_128,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_instantiate,
		.sec = DRBG_SEC_192,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_instantiate,
		.sec = DRBG_SEC_256,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_reseed,
		.sec = DRBG_SEC_112,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_reseed,
		.sec = DRBG_SEC_128,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_reseed,
		.sec = DRBG_SEC_192,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_reseed,
		.sec = DRBG_SEC_256,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_reseed,
		.sec = DRBG_SEC_112,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_reseed,
		.sec = DRBG_SEC_128,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_reseed,
		.sec = DRBG_SEC_192,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_reseed,
		.sec = DRBG_SEC_256,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_generate,
		.sec = DRBG_SEC_112,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_generate,
		.sec = DRBG_SEC_128,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_generate,
		.sec = DRBG_SEC_192,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_generate,
		.sec = DRBG_SEC_256,
		.pr = true,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_generate,
		.sec = DRBG_SEC_112,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_generate,
		.sec = DRBG_SEC_128,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_generate,
		.sec = DRBG_SEC_192,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_generate,
		.sec = DRBG_SEC_256,
		.pr = false,
		.rc = 0,
	},
	{
		.mech = NULL,
		.func = ica_drbg_generate,
		.sec = DRBG_SEC_256,
		.pr = false,
		.rc = EINVAL,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = NULL,
		.sec = DRBG_SEC_256,
		.pr = true,
		.rc = EINVAL,
	},
	{
		.mech = ICA_DRBG_SHA512,
		.func = ica_drbg_instantiate,
		.sec = DRBG_SEC_256 + 1,
		.pr = false,
		.rc = ENOTSUP,
	},
	};
	for(i = 0; i < sizeof(ht_test) / sizeof(ht_test[0]); i++){
		V_(printf("health test function: test no. %u", i));
		status = ica_drbg_health_test(ht_test[i].func, ht_test[i].sec,
					      ht_test[i].pr, ht_test[i].mech);
		if(ht_test[i].rc == status){
			V_(printf(" passed\n"));
			passed++;
		}
		else{
			V_(printf(" failed\n"));
			failed++;
		}
	}

	if(failed) {
		printf("DRBG tests: %d passed, %d failed, %d total\n", passed, failed,
		       passed + failed);
		return TEST_FAIL;
	}

	printf("All DRBG tests passed.\n");
	return TEST_SUCC;
}
