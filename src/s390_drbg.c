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

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "s390_crypto.h"
#include "s390_drbg.h"
#include "s390_sha.h"

//#define NDEBUG	/* turns off assertions *///DEBUG

/*
 * Test DRBG mechanisms
 */
static ica_drbg_mech_t DRBG_TESTMECH1 = {.error_state = DRBG_HEALTH_TEST_FAIL};
static ica_drbg_mech_t DRBG_TESTMECH2 = {.error_state = 0};

/*
 * Auxiliary functions
 */
static int test_uninstantiate(ica_drbg_mech_t *mech);

static int test_instantiate_error_handling(ica_drbg_mech_t *mech);

static int test_reseed_error_handling(ica_drbg_mech_t *mech);

static int test_generate_error_handling(ica_drbg_mech_t *mech);

/*
 * DRBG mechanism list. Add new DRBG mechanism here:
 */
ica_drbg_mech_t *const DRBG_MECH_LIST[] = {&DRBG_SHA512,
					   &DRBG_TESTMECH1,
					   &DRBG_TESTMECH2};
const size_t DRBG_MECH_LIST_LEN = sizeof(DRBG_MECH_LIST)
				  / sizeof(DRBG_MECH_LIST[0]);

/*
 * DRBG mechanism functions
 */
int drbg_instantiate(ica_drbg_t **sh,
		     int sec,
		     bool pr,
		     ica_drbg_mech_t *mech,
		     const unsigned char *pers,
		     size_t pers_len,
		     bool test_mode,
		     const unsigned char *test_nonce,
		     size_t test_nonce_len,
		     const unsigned char *test_entropy,
		     size_t test_entropy_len)
{
	/* 9.1 Instantiate Process */

	if(!sh || *sh)
		return DRBG_SH_INV;
	int status = drbg_mech_valid(mech);
	if(status)
		return status;

	/* step 1 */
	if(sec > mech->highest_supp_sec)
		return DRBG_SEC_NOTSUPP;

	/* step 2: pr is supported. */

	/* step 3 */
	if(!pers)
		pers_len = 0;
	else if(pers_len <= 0)
		pers = NULL;
	if(pers_len > mech->max_pers_len)
		return DRBG_PERS_INV;

	/* step 4 */
	if(sec <= DRBG_SEC_112)
		sec = DRBG_SEC_112;
	else
	if(sec <= DRBG_SEC_128)
		sec = DRBG_SEC_128;
	else
	if(sec <= DRBG_SEC_192)
		sec = DRBG_SEC_192;
	else
		sec = DRBG_SEC_256;

	/* step 5: Null step. */

	const size_t entropy_len = !test_mode ?
				   (sec + 7) / 8 + DRBG_ADD_ENTROPY_LEN :
				   test_entropy_len;
	const size_t nonce_len = !test_mode ? DRBG_NONCE_LEN : test_nonce_len;
	unsigned char entropy[entropy_len];
	unsigned char nonce[nonce_len];

	/* step 6 */
	if(!test_mode)			/* use entropy from SEI */
		status = drbg_get_entropy_input(pr, sec, mech->max_len,
						entropy, entropy_len);
	else{
		if(test_entropy){	/* use test entropy */
			memcpy(entropy, test_entropy, entropy_len);
			status = 0;
		}
		else{			/* test for entropy source failure */
			status = drbg_get_entropy_input(pr, sec, mech->max_len,
							entropy, entropy_len);
		}
	}

	/* step 7 */
	if(status){
		status = DRBG_ENTROPY_SOURCE_FAIL;
		goto _exit_;
	}

	/* step 8 */
	if(!test_mode){		/* use thread id + timestamp + counter */
		status = drbg_get_nonce(nonce, nonce_len);
	}
	else{			/* use test nonce */
		memcpy(nonce, test_nonce, nonce_len);
	}
	if(status){
		status = DRBG_NONCE_INV;
		goto _exit_;
	}

	/* step 9 */
	void *init_ws;
	status = mech->instantiate(&init_ws, sec, pers, pers_len, entropy,
				   entropy_len, nonce, nonce_len);
	if(status){
		if(0 > status)
			mech->error_state = status;
		goto _exit_;
	}

	/* step 10 */
	*sh = malloc(sizeof(ica_drbg_t));
	if(!*sh){
		status = DRBG_NOMEM;
		goto _exit_;
	}

	/* step 11 */
	drbg_recursive_mutex_init(&(*sh)->lock);
	(*sh)->mech = mech;
	(*sh)->ws = init_ws;
	(*sh)->sec = sec;
	(*sh)->pr = pr;

	/* step 12 */
_exit_:
	drbg_zmem(entropy, entropy_len);
	drbg_zmem(nonce, nonce_len);
	return status;
}

int drbg_reseed(ica_drbg_t *sh,
		bool pr,
		const unsigned char *add,
		size_t add_len,
		bool test_mode,
		const unsigned char *test_entropy,
		size_t test_entropy_len)
{
	/* 9.2 Reseed Process */

	/* step 1 */
	if(!sh || !sh->ws)
		return DRBG_SH_INV;
	int status = drbg_mech_valid(sh->mech);
	if(status)
		return status;

	/* step 2 */
	if(pr && !sh->pr)
		return DRBG_PR_NOTSUPP;

	/* step 3 */
	if(!add)
		add_len = 0;
	else if(add_len <= 0)
		add = NULL;
	if(add_len > sh->mech->max_add_len)
		return DRBG_ADD_INV;

	const size_t entropy_len = !test_mode ?
				   (sh->sec + 7) / 8 + DRBG_ADD_ENTROPY_LEN :
				   test_entropy_len;
	unsigned char entropy[entropy_len];

	/* step 4 */
	if(!test_mode)			/* use entropy from SEI */
		status = drbg_get_entropy_input(pr, sh->sec, sh->mech->max_len,
						entropy, entropy_len);
	else{
		if(test_entropy){	/* use test entropy */
			memcpy(entropy, test_entropy, entropy_len);
			status = 0;
		}
		else{			/* test for entropy source failure */
			status = drbg_get_entropy_input(pr, sh->sec,
							sh->mech->max_len,
							entropy, entropy_len);
		}
	}

	/* step 5 */
	if(status){
		status = DRBG_ENTROPY_SOURCE_FAIL;
		goto _exit_;
	}

	/* steps 6 and 7 */
	assert(!pthread_mutex_lock(&sh->lock));
	status = sh->mech->reseed(sh->ws, add, add_len, entropy, entropy_len);
	assert(!pthread_mutex_unlock(&sh->lock));
	if(0 > status)
		sh->mech->error_state = status;

	/* step 8 */
_exit_:
	drbg_zmem(entropy, entropy_len);
	return status; /* return reseed status */
}

int drbg_generate(ica_drbg_t *sh,
		  int sec,
		  bool pr,
		  const unsigned char *add,
		  size_t add_len,
		  bool test_mode,
		  const unsigned char *test_entropy,
		  size_t test_entropy_len,
		  unsigned char *prnd,
		  size_t prnd_len)
{
	/* 9.3 Generate Process */

	/* step 1 */
	if(!sh || !sh->ws)
		return DRBG_SH_INV;
	int status = drbg_mech_valid(sh->mech);
	if(status)
		return status;

	/* step 2 */
	if(prnd_len > sh->mech->max_no_of_bytes_per_req)
		return DRBG_REQUEST_INV;

	/* step 3 */
	if(sec > sh->sec)
		return DRBG_SEC_NOTSUPP;

	/* step 4 */
	if(!add)
		add_len = 0;
	else if(add_len <= 0)
		add = NULL;
	if(add_len > sh->mech->max_add_len)
		return DRBG_ADD_INV;

	/* step 5 */
	if(pr && !sh->pr)
		return DRBG_PR_NOTSUPP;

	/* step 6 */
	bool reseed_required = false;

	/* step 7 */
_reseed_req_:
	assert(!pthread_mutex_lock(&sh->lock));
	if(pr || reseed_required){
		/* steps 7.1 and 7.3 */
		status = drbg_reseed(sh, pr, add, add_len, test_mode,
				     test_entropy, test_entropy_len);
		/* step 7.2 */
		if(status){
			assert(!pthread_mutex_unlock(&sh->lock));
			return status;	/* return reseed status */
		}
		/* step 7.4 */
		add = NULL;
		add_len = 0;
		/* step 7.5 */
		reseed_required = false;
	}

	/* steps 8 and 10 */
	status = sh->mech->generate(sh->ws, add, add_len, prnd, prnd_len);
	assert(!pthread_mutex_unlock(&sh->lock));

	/* step 9 */
	if(DRBG_RESEED_REQUIRED == status){
		/* step 9.1 */
		reseed_required = true;
		/* step 9.2 */
		if(sh->pr)
			pr = true;
		/* step 9.3 */
		goto _reseed_req_;
	}
	else if(0 > status)
		sh->mech->error_state = status;

	/* step 11 */
	return status;
}

int drbg_uninstantiate(ica_drbg_t **sh,
		       bool test_mode)
{
	/* 9.4 Uninstantiate Process */

	/* step 1 */
	if(!sh || !(*sh) || !(*sh)->ws)
		return DRBG_SH_INV;
	int status = drbg_mech_valid((*sh)->mech);
	if(status > 0)		/* uninst. is possible in error state (< 0) */
		return status;

	/* step 2 */
	assert(!pthread_mutex_lock(&(*sh)->lock));
	status = (*sh)->mech->uninstantiate(&(*sh)->ws, test_mode);
	if(status){
		if(0 > status)
			(*sh)->mech->error_state = status;
		return status;	/* return uninstantiate status */
	}
	assert(!pthread_mutex_unlock(&(*sh)->lock));
	assert(!pthread_mutex_destroy(&(*sh)->lock));
	drbg_zmem(*sh, sizeof(ica_drbg_t));
	if(test_mode)
		status = drbg_check_zmem(*sh, sizeof(ica_drbg_t));
	free(*sh);
	*sh = NULL;

	/* step 3 */
	return status;
}

int drbg_health_test(const void *func,
		     int sec,
		     bool pr,
		     ica_drbg_mech_t *mech)
{
	const int SEC[] = {DRBG_SEC_112, DRBG_SEC_128, DRBG_SEC_192,
			   DRBG_SEC_256};

	int status = drbg_mech_valid(mech);
	if(status)
		return status;

	if(drbg_instantiate == func){
		/* Test vectors. */
		status = mech->health_test(drbg_instantiate, sec, pr);
		if(status){
			if(0 > status)
				mech->error_state = status;
			return status;
		}

		/* Error handling test. */
		status = test_instantiate_error_handling(mech);
		if(status)
			return mech->error_state = DRBG_HEALTH_TEST_FAIL;

		/* Uninstantiate test. */
		status = test_uninstantiate(mech);
		if(status)
			return mech->error_state = DRBG_HEALTH_TEST_FAIL;

		return 0;
	}
	else if(drbg_reseed == func){
		/* Test vectors. */
		status = mech->health_test(drbg_reseed, sec, pr);
		if(status){
			if(0 > status)
				mech->error_state = status;
			return status;
		}

		/* Error handling test. */
		status = test_reseed_error_handling(mech);
		if(status)
			return mech->error_state = DRBG_HEALTH_TEST_FAIL;

		/* Uninstantiate test. */
		status = test_uninstantiate(mech);
		if(status)
			return mech->error_state = DRBG_HEALTH_TEST_FAIL;

		return 0;
	}
	else if(drbg_generate == func){
		/* Test vectors: test all combinations sec, pr supp, pr req */
		int i = 0;
		for(; i < sizeof(SEC) / sizeof(SEC[0]); i++){
			if(SEC[i] > mech->highest_supp_sec)
				break;

			status = mech->health_test(drbg_generate, SEC[i],
						   false);
			if(status){
				if(0 > status)
					mech->error_state = status;
				return status;
			}

			status = mech->health_test(drbg_generate, SEC[i],
						   true);
			if(status){
				if(0 > status)
					mech->error_state = status;
				return status;
			}
		}

		/* Error handling test. */
		status = test_generate_error_handling(mech);
		if(status)
			return mech->error_state = DRBG_HEALTH_TEST_FAIL;

		/* Uninstantiate test.*/
		status = test_uninstantiate(mech);
		if(status)
			return mech->error_state = DRBG_HEALTH_TEST_FAIL;

		return 0;
	}
	else
		return DRBG_REQUEST_INV;
}

/*
 * Auxiliary functions
 */
int drbg_get_entropy_input(bool pr,
			   int min_entropy,
			   size_t max_len,
			   unsigned char *entropy,
			   size_t entropy_len)
{
	/* NIST SP800-90C Get_entropy_input */

	if(!entropy)
		return DRBG_REQUEST_INV;
	if(0 > min_entropy)
		min_entropy = 0;

	size_t min_len = ((min_entropy + 7) / 8);

	if(min_len > max_len)
		return DRBG_REQUEST_INV;

	if(entropy_len < min_len || entropy_len > max_len)
		return DRBG_REQUEST_INV;

	/* SEI (source of entropy input) priority. */
	FILE *fd = fopen("/dev/hwrng", "r");
	if(!fd)
		fd = fopen("/dev/prandom", "r");
	if(!fd)
		return DRBG_ENTROPY_SOURCE_FAIL;

	if(1 != fread(entropy, entropy_len, 1, fd)){
		fclose(fd);
		return DRBG_ENTROPY_SOURCE_FAIL;
	}

	if(fclose(fd))
		return DRBG_ENTROPY_SOURCE_FAIL;

	return 0;
}

int drbg_get_nonce(unsigned char *nonce,
		   size_t nonce_len)
{
	static uint16_t ctr;

	/* The buffer for nonce must hold a 16 byte timestamp. */
	if(DRBG_NONCE_LEN != nonce_len)
		return DRBG_NONCE_INV;

	/* Get timestamp from TOD clock. */
	s390_stcke_hw(nonce);
	/* The value in the bits 72 - 111 is non-zero when the clock is
	 * running. */
	const unsigned char zero_buff[(111 - 72 + 1) / 8] = {0};
	int status = !memcmp(nonce + (72 / 8), &zero_buff,
			     (111 - 72 + 1) / 8);
	if(status)
		return DRBG_NONCE_INV;

	/* Get thread id. */
	pthread_t thread_id = pthread_self();

	/* Store bytewise XOR of the thread id in first byte. */
	int i = 0;
	for(; i < sizeof(thread_id); i++)
		*nonce ^= *((unsigned char *)&thread_id + i);

	/* Store counter in the last two bytes. Since TOD clock is thread-save,
	 * this counter is chosen not to be thread-safe. */
	*((uint16_t *)(nonce + DRBG_NONCE_LEN - 2)) = ctr;
	ctr++;

	return 0;
}

int drbg_hash_df(const unsigned char *input,
		 size_t input_len,
		 unsigned char *req_bytes,
		 size_t req_bytes_len)
{
	/* 10.4.1 Hash_df Process */

#define MAX_NO_OF_BYTES	(255 * DRBG_OUT_LEN)
	if(!req_bytes_len)
		return 0;	/* no bytes requested: do nothing */
	if(!req_bytes || !input)
		return DRBG_REQUEST_INV;
	if (MAX_NO_OF_BYTES < req_bytes_len)
		return DRBG_REQUEST_INV;

	const uint32_t no_of_bits_to_return = req_bytes_len * 8;

	/* steps 1 and 2 */
	const size_t len = (req_bytes_len + DRBG_OUT_LEN - 1) / DRBG_OUT_LEN;
	unsigned char temp[len * DRBG_OUT_LEN];

	/* step 3 */
	unsigned counter = 0x01;

	/* step 4 */
	const size_t _tmp_len = 1 + sizeof(no_of_bits_to_return) + input_len;
	unsigned char _tmp[_tmp_len];
	memcpy(_tmp + 1, &no_of_bits_to_return, sizeof(no_of_bits_to_return));
	memcpy(_tmp + 1 + sizeof(no_of_bits_to_return), input, input_len);
	int status;
	uint64_t shabuff[2];
	size_t i = 1;
	for(; i <= len; i++){
		/* step 4.1 */
		_tmp[0] = counter;
		status = s390_sha_hw(SHA_512_DEFAULT_IV, _tmp, _tmp_len,
				     temp + (i - 1) * DRBG_OUT_LEN,
				     SHA_MSG_PART_ONLY, &shabuff[0],
				     &shabuff[1], SHA_512);
		if(status){
			status = DRBG_HEALTH_TEST_FAIL;
			goto _exit_;
		}
		/* step 4.2 */
		counter++;
	}

	/* step 5 */
	memcpy(req_bytes, temp, req_bytes_len);

	/* step 6 */
_exit_:
	drbg_zmem(_tmp, _tmp_len);
	drbg_zmem(temp, len * DRBG_OUT_LEN);
	return status;
}

void drbg_zmem(void *ptr,
	       size_t len)
{
	if(ptr)
		memset(ptr, 0, len);
}

int drbg_check_zmem(void *ptr,
		    size_t len)
{
	if(!ptr)
		return DRBG_HEALTH_TEST_FAIL;

	int i = 0;
	for(; i < len; i++){
		if(((unsigned char *)ptr)[i])
			return DRBG_HEALTH_TEST_FAIL;
	}

	return 0;
}

int drbg_mech_valid(const ica_drbg_mech_t *mech)
{
	if(!mech)
		return DRBG_MECH_INV;

	/* Check if @mech is supported. */
	int i = DRBG_MECH_LIST_LEN - 1;
	for(; i >= 0; i--){
		if(DRBG_MECH_LIST[i] == mech)
			break;
	}
	if(i < 0)
		return DRBG_MECH_INV;

	/* Check if @mech is in error state. */
	if(mech->error_state)
		return mech->error_state;

	return 0;
}

static int test_uninstantiate(ica_drbg_mech_t *mech)
{
	/* Error handling test. */
	int status = drbg_uninstantiate(NULL, false);
	if(DRBG_SH_INV != status)
		return DRBG_HEALTH_TEST_FAIL;

	/* Test if internal state is zeroised. */
	ica_drbg_t *sh = NULL;
	status = drbg_instantiate(&sh, mech->highest_supp_sec, true, mech,
				  NULL, 0, false, NULL, 0, NULL, 0);
	if(0 > status)
		mech->error_state = status;
	if(status)
		return status;

	status = drbg_uninstantiate(&sh, true);
	if(status)
		return status;

	return 0;
}

static int test_instantiate_error_handling(ica_drbg_mech_t *mech)
{
	/* Pointer to state handle is NULL. */
	int test_no = 1;
	int status = drbg_instantiate(NULL, 0, true, mech, NULL, 0, false,
				      NULL, 0, NULL, 0);
	if(DRBG_SH_INV != status)
		return test_no;

	/* State handle is already in use. */
	test_no++;
	ica_drbg_t *sh = NULL;
	ica_drbg_t test_sh = {.lock = PTHREAD_MUTEX_INITIALIZER};
	drbg_recursive_mutex_init(&test_sh.lock);
	sh = &test_sh;
	test_sh.mech = mech;
	test_sh.ws = (void *)"ws";
	status = drbg_instantiate(&sh, 0, true, mech, NULL, 0, false, NULL, 0,
				  NULL, 0);
	if(DRBG_SH_INV != status)
		return test_no;
	test_sh.mech = NULL;
	sh = NULL;

	/* Mechanism is not supported. */
	test_no++;
	ica_drbg_mech_t test_mech = {.lock = PTHREAD_RWLOCK_INITIALIZER};
	status = drbg_instantiate(&sh, 0, true, &test_mech, NULL, 0, false,
				  NULL, 0, NULL, 0);
	if(DRBG_MECH_INV != status)
		return test_no;

	/* Mechanism in error state. */
	test_no++;
	status = drbg_instantiate(&sh, 0, true, &DRBG_TESTMECH1, NULL, 0,
				  false, NULL, 0, NULL, 0);
	if(0 <= status)
		return test_no;

	/* Security strength is not supported. */
	test_no++;
	status = drbg_instantiate(&sh, mech->highest_supp_sec + 1, true, mech,
				  NULL, 0, true, NULL, 0, NULL, 0);
	if(DRBG_SEC_NOTSUPP != status)
		return test_no;

	/* Personalization string is too long. */
	test_no++;
	status = drbg_instantiate(&sh, 0, true, mech, (unsigned char *)"pers",
				  mech->max_pers_len + 1, false, NULL, 0, NULL,
				  0);
	if(DRBG_PERS_INV != status)
		return test_no;

	/* Entropy source failed. */
	test_no++;
	status = drbg_instantiate(&sh, 0, true, mech, NULL, 0, true, NULL, 0,
				  NULL, 0);
	if(DRBG_ENTROPY_SOURCE_FAIL != status)
		return test_no;

	return 0;
}

static int test_reseed_error_handling(ica_drbg_mech_t *mech)
{
	/* Invalid state handle. */
	int test_no = 1;
	int status = drbg_reseed(NULL, true, NULL, 0, false, NULL, 0);
	if(DRBG_SH_INV != status)
		return test_no;

	/* Mechanism is not supported. */
	test_no++;
	ica_drbg_mech_t test_mech = {.lock = PTHREAD_RWLOCK_INITIALIZER};
	ica_drbg_t test_sh = {.lock = PTHREAD_MUTEX_INITIALIZER};
	drbg_recursive_mutex_init(&test_sh.lock);
	test_sh.mech = &test_mech;
	test_sh.ws = (void *)"ws";
	status = drbg_reseed(&test_sh, true, NULL, 0, false, NULL, 0);
	if(DRBG_MECH_INV != status)
		return test_no;
	test_sh.mech = NULL;

	/* Mechanism is in error state */
	test_no++;
	test_sh.mech = &DRBG_TESTMECH1;
	status = drbg_reseed(&test_sh, true, NULL, 0, false, NULL, 0);
	if(0 <= status)
		return test_no;
	test_sh.mech = NULL;

	/* Prediction resistance is requested but not supported. */
	test_no++;
	test_sh.mech = &DRBG_TESTMECH2;
	status = drbg_reseed(&test_sh, true, NULL, 0, false, NULL, 0);
	if(DRBG_PR_NOTSUPP != status)
		return test_no;
	test_sh.mech = NULL;

	/* Additional input is too long. */
	test_no++;
	test_sh.mech = mech;
	status = drbg_reseed(&test_sh, false, (unsigned char *)"add",
			     mech->max_add_len + 1, false, NULL, 0);
	if(DRBG_ADD_INV != status)
		return test_no;
	test_sh.mech = NULL;

	/* Entropy source failed. */
	test_no++;
	test_sh.mech = mech;
	status = drbg_reseed(&test_sh, false, NULL, 0, true, NULL, 0);
	if(DRBG_ENTROPY_SOURCE_FAIL != status)
		return test_no;
	test_sh.mech = NULL;

	return 0;
}

static int test_generate_error_handling(ica_drbg_mech_t *mech)
{
	const int SEC[] = {DRBG_SEC_112, DRBG_SEC_128, DRBG_SEC_192,
			   DRBG_SEC_256};

	/* Invalid state handle. */
	int test_no = 1;
	unsigned char prnd;
	int status = drbg_generate(NULL, mech->highest_supp_sec, false, NULL,
				   0, false, NULL, 0, &prnd, sizeof(prnd));
	if(DRBG_SH_INV != status)
		return test_no;

	/* Mechanism is not supported. */
	test_no++;
	ica_drbg_mech_t test_mech = {.lock = PTHREAD_RWLOCK_INITIALIZER};
	ica_drbg_t test_sh = {.lock = PTHREAD_MUTEX_INITIALIZER};
	drbg_recursive_mutex_init(&test_sh.lock);
	test_sh.mech = &test_mech;
	test_sh.ws = (void *)"ws";
	status = drbg_generate(&test_sh, mech->highest_supp_sec, false, NULL, 0,
			       false, NULL, 0, &prnd, sizeof(prnd));
	if(DRBG_MECH_INV != status)
		return test_no;
	test_sh.mech = NULL;

	/* Mechanism is in error state. */
	test_no++;
	test_sh.mech = &DRBG_TESTMECH1;
	status = drbg_generate(&test_sh, mech->highest_supp_sec, false, NULL, 0,
			       false, NULL, 0, &prnd, sizeof(prnd));
	if(0 <= status)
		return test_no;
	test_sh.mech = NULL;

	/* Too many pseudorandom bytes requested. */
	test_no++;
	test_sh.mech = mech;

	status = drbg_generate(&test_sh, mech->highest_supp_sec, false, NULL,
			       0, false, NULL, 0, &prnd,
			       mech->max_no_of_bytes_per_req + 1);
	if(DRBG_REQUEST_INV != status)
		return test_no;
	test_sh.mech = NULL;

	/* Requested security strength is too high. */
	test_no++;
	test_sh.mech = mech;
	test_sh.sec = DRBG_SEC_112;

	status = drbg_generate(&test_sh, DRBG_SEC_112 + 1, false, NULL, 0,
			       true, NULL, 0, &prnd, sizeof(prnd));
	if(DRBG_SEC_NOTSUPP != status)
		return test_no;
	test_sh.mech = NULL;
	test_sh.sec = 0;

	/* Additional input is too long. */
	test_no++;
	test_sh.mech = mech;
	test_sh.sec = mech->highest_supp_sec;

	status = drbg_generate(&test_sh, mech->highest_supp_sec, false,
			       (unsigned char *)"add", mech->max_add_len + 1,
			       false, NULL, 0, &prnd, sizeof(prnd));
	if(DRBG_ADD_INV != status)
		return test_no;
	test_sh.mech = NULL;
	test_sh.sec = 0;

	/* Prediction resistance is requested but not supported. */
	test_no++;
	test_sh.mech = mech;
	test_sh.sec = mech->highest_supp_sec;
	int i = 0;
	for(; i < sizeof(SEC); i++){
		if(SEC[i] > mech->highest_supp_sec)
			break;
		status = drbg_generate(&test_sh, SEC[i], true, NULL, 0, true,
				       NULL, 0, &prnd, sizeof(prnd));
		if(DRBG_PR_NOTSUPP != status)
			return test_no;
	}
	test_sh.mech = NULL;
	test_sh.sec = 0;

	/* Entropy source failed. */
	test_no++;
	test_sh.mech = mech;
	test_sh.sec = mech->highest_supp_sec;
	test_sh.pr = true;

	status = drbg_generate(&test_sh, mech->highest_supp_sec, true, NULL, 0,
			       true, NULL, 0, &prnd, sizeof(prnd));
	if(DRBG_ENTROPY_SOURCE_FAIL != status)
		return test_no;
	test_sh.mech = NULL;
	test_sh.sec = 0;
	test_sh.pr = false;

	return 0;
}

void drbg_recursive_mutex_init(pthread_mutex_t *lock)
{
	pthread_mutexattr_t attr;

	assert(!pthread_mutexattr_init(&attr));
	assert(!pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE));
	assert(!pthread_mutex_init(lock, &attr));
}
